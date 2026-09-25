package io.github.hannescoetzee.wazuhagent.collectors

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.os.Build
import android.provider.Settings
import androidx.core.content.edit
import io.github.hannescoetzee.wazuhagent.queue.EventQueue
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject
import java.io.File
import java.time.LocalDate
import java.time.temporal.ChronoUnit
import java.util.concurrent.TimeUnit

/**
 * Device security posture. When any tracked value changes, and at least every
 * [HEARTBEAT_MS], this sends one `posture` report, one `posture_finding` per failing check
 * and one `posture_change` per changed sensitive list. The manager raises a single alert per
 * event, so each problem needs its own event to be seen.
 */
class PostureCollector(private val context: Context) {
    private val prefs = context.getSharedPreferences("posture_state", Context.MODE_PRIVATE)

    suspend fun collectAndReport(queue: EventQueue, force: Boolean = false) = lock.withLock {
        val snapshot = snapshot()
        val previous = prefs.getString(KEY_LAST, null)?.let { runCatching { JSONObject(it) }.getOrNull() }
        val changed = changedFields(previous, snapshot)
        val lastSent = prefs.getLong(KEY_LAST_SENT, 0)
        val due = System.currentTimeMillis() - lastSent > HEARTBEAT_MS

        if (!force && !due && changed.isEmpty() && previous != null) return@withLock

        queue.enqueue(
            Events.build("posture") {
                snapshot.keys().forEach { put(it, snapshot.get(it)) }
                put("changed", Events.array(changed))
                put("first_report", previous == null)
            },
        )
        findings(snapshot).forEach { (check, detail) ->
            queue.enqueue(
                Events.build("posture_finding") {
                    put("check", check)
                    put("detail", detail)
                    put("new", changed.any { it in CHECK_FIELDS.getValue(check) })
                },
            )
        }
        if (previous != null) {
            changed.filter { it in WATCHED_LISTS }.forEach { field ->
                val before = jsonList(previous.optJSONArray(field))
                val after = jsonList(snapshot.optJSONArray(field))
                queue.enqueue(
                    Events.build("posture_change") {
                        put("field", field)
                        put("added", Events.array(after - before.toSet()))
                        put("removed", Events.array(before - after.toSet()))
                        put("current", Events.array(after))
                    },
                )
            }
        }
        prefs.edit {
            putString(KEY_LAST, snapshot.toString())
            putLong(KEY_LAST_SENT, System.currentTimeMillis())
        }
    }

    /** Failing checks as check id to human-readable detail. */
    private fun findings(s: JSONObject): List<Pair<String, String>> = buildList {
        if (!s.optBoolean("device_secure", true)) add("screen_lock" to "No PIN, pattern or password is set")
        s.optString("encryption").takeIf { it == "inactive" || it == "unsupported" }
            ?.let { add("encryption" to "Storage encryption is $it") }
        if (s.optBoolean("rooted")) add("root" to "Root indicators: ${jsonList(s.optJSONArray("root_indicators")).joinToString()}")
        if (s.optBoolean("adb_wifi_enabled")) add("adb_wifi" to "Wireless debugging is enabled")
        if (s.optBoolean("adb_enabled")) add("adb" to "USB debugging is enabled")
        if (s.optBoolean("developer_options")) add("developer_options" to "Developer options are enabled")
        s.optLong("security_patch_age_days", -1).takeIf { it > PATCH_MAX_AGE_DAYS }
            ?.let { add("security_patch" to "Security patch ${s.optString("security_patch")} is $it days old") }
        s.optString("verified_boot_state").takeIf { it == "orange" || it == "yellow" || it == "red" }
            ?.let { add("verified_boot" to "Verified boot state is $it") }
        if (s.optBoolean("emulator")) add("emulator" to "Running on an emulator")
    }

    private fun jsonList(array: org.json.JSONArray?): List<String> =
        if (array == null) emptyList() else (0 until array.length()).map { array.optString(it) }

    fun snapshot(): JSONObject {
        val keyguard = context.getSystemService(KeyguardManager::class.java)
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
        val resolver = context.contentResolver
        val patch = Build.VERSION.SECURITY_PATCH
        val patchAge = runCatching { ChronoUnit.DAYS.between(LocalDate.parse(patch), LocalDate.now()) }.getOrNull()

        return JSONObject().apply {
            put("device_secure", keyguard.isDeviceSecure)
            put("biometrics_enrolled", biometricsEnrolled())
            put("encryption", encryptionStatus(dpm.storageEncryptionStatus))
            put("security_patch", patch)
            put("security_patch_age_days", patchAge ?: -1)
            put("android_release", Build.VERSION.RELEASE)
            put("sdk_int", Build.VERSION.SDK_INT)
            put("build_fingerprint", Build.FINGERPRINT)
            put("manufacturer", Build.MANUFACTURER)
            put("model", Build.MODEL)
            put("developer_options", Settings.Global.getInt(resolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1)
            put("adb_enabled", Settings.Global.getInt(resolver, Settings.Global.ADB_ENABLED, 0) == 1)
            put("adb_wifi_enabled", Settings.Global.getInt(resolver, "adb_wifi_enabled", 0) == 1)
            put("sideload_capable_apps", Events.array(sideloadCapableApps()))
            put("device_admins", Events.array(dpm.activeAdmins.orEmpty().map { it.packageName }.distinct().sorted()))
            put("accessibility_services", Events.array(secureList(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)))
            put("notification_listeners", Events.array(secureList("enabled_notification_listeners")))
            put("verified_boot_state", prop("ro.boot.verifiedbootstate"))
            put("bootloader_locked", prop("ro.boot.flash.locked").let { if (it.isEmpty()) JSONObject.NULL else it == "1" })
            put("build_tags", Build.TAGS ?: "")
            val indicators = rootIndicators()
            put("root_indicators", Events.array(indicators))
            put("rooted", indicators.isNotEmpty())
            put("emulator", isEmulator())
        }
    }

    private fun changedFields(previous: JSONObject?, current: JSONObject): List<String> {
        if (previous == null) return emptyList()
        return current.keys().asSequence()
            .filter { it !in VOLATILE_FIELDS }
            .filter { previous.opt(it)?.toString() != current.opt(it)?.toString() }
            .toList()
    }

    private fun biometricsEnrolled(): Any = runCatching {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return JSONObject.NULL
        val bm = context.getSystemService(BiometricManager::class.java) ?: return JSONObject.NULL
        val result = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            bm.canAuthenticate()
        }
        result == BiometricManager.BIOMETRIC_SUCCESS
    }.getOrDefault(JSONObject.NULL)

    private fun encryptionStatus(status: Int) = when (status) {
        DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE -> "active"
        DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER -> "active_per_user"
        DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY -> "active_default_key"
        DevicePolicyManager.ENCRYPTION_STATUS_ACTIVATING -> "activating"
        DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE -> "inactive"
        DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED -> "unsupported"
        else -> "unknown"
    }

    /**
     * Apps that can ask to install other apps. Their per-app "install unknown apps" toggle is
     * not readable without system privileges, so this is the closest non-root signal.
     */
    private fun sideloadCapableApps(): List<String> {
        val pm = context.packageManager
        return runCatching {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
                .filter { pkg ->
                    val system = (pkg.applicationInfo?.flags ?: 0) and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0
                    !system && pkg.requestedPermissions?.contains(android.Manifest.permission.REQUEST_INSTALL_PACKAGES) == true
                }
                .map { it.packageName }
                .sorted()
        }.getOrDefault(emptyList())
    }

    private fun secureList(key: String): List<String> = runCatching {
        Settings.Secure.getString(context.contentResolver, key).orEmpty()
            .split(':').map { it.trim() }.filter { it.isNotEmpty() }.sorted()
    }.getOrDefault(emptyList())

    private fun rootIndicators(): List<String> {
        val found = mutableListOf<String>()
        SU_PATHS.filter { File(it).exists() }.forEach { found += "su:$it" }
        if (Build.TAGS?.contains("test-keys") == true) found += "build:test-keys"
        if (prop("ro.debuggable") == "1") found += "prop:ro.debuggable"
        if (prop("ro.secure") == "0") found += "prop:ro.secure=0"
        val pm = context.packageManager
        ROOT_PACKAGES.filter { pkg ->
            runCatching { pm.getPackageInfo(pkg, 0); true }.getOrDefault(false)
        }.forEach { found += "package:$it" }
        return found
    }

    private fun isEmulator(): Boolean =
        Build.FINGERPRINT.startsWith("generic") || Build.FINGERPRINT.contains("emulator") ||
            Build.HARDWARE.contains("goldfish") || Build.HARDWARE.contains("ranchu") ||
            Build.PRODUCT.contains("sdk") || Build.MODEL.contains("Emulator")

    private fun prop(name: String): String = runCatching {
        val process = ProcessBuilder("getprop", name).redirectErrorStream(true).start()
        val value = process.inputStream.bufferedReader().use { it.readText().trim() }
        if (!process.waitFor(2, TimeUnit.SECONDS)) process.destroyForcibly()
        value
    }.getOrDefault("")

    companion object {
        private const val KEY_LAST = "last_snapshot"
        private const val KEY_LAST_SENT = "last_sent"
        const val HEARTBEAT_MS = 6 * 60 * 60 * 1000L
        private const val PATCH_MAX_AGE_DAYS = 90L
        private val VOLATILE_FIELDS = setOf("security_patch_age_days")
        private val WATCHED_LISTS = setOf("accessibility_services", "device_admins", "notification_listeners", "sideload_capable_apps")
        private val CHECK_FIELDS = mapOf(
            "screen_lock" to setOf("device_secure"),
            "encryption" to setOf("encryption"),
            "root" to setOf("rooted", "root_indicators"),
            "adb_wifi" to setOf("adb_wifi_enabled"),
            "adb" to setOf("adb_enabled"),
            "developer_options" to setOf("developer_options"),
            "security_patch" to setOf("security_patch"),
            "verified_boot" to setOf("verified_boot_state"),
            "emulator" to setOf("emulator"),
        )

        /** The service, the settings observer and the periodic worker may all trigger a run. */
        private val lock = Mutex()

        private val SU_PATHS = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su", "/su/bin/su",
            "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su", "/system/sbin/su", "/vendor/bin/su",
            "/data/adb/magisk", "/data/adb/ksu",
        )
        private val ROOT_PACKAGES = listOf(
            "com.topjohnwu.magisk", "io.github.huskydg.magisk", "io.github.vvb2060.magisk",
            "me.weishu.kernelsu", "com.rifsxd.ksunext", "eu.chainfire.supersu",
            "com.koushikdutta.superuser", "com.noshufou.android.su", "com.kingroot.kinguser",
        )
    }
}
