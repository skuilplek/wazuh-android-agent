package io.github.hannescoetzee.wazuhagent.collectors

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.os.Build
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import io.github.hannescoetzee.wazuhagent.queue.EventQueue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject

/**
 * App installs, updates and removals. Live changes come from package broadcasts; a snapshot
 * diff on start and on every periodic run catches anything that happened while the agent
 * was not running. The first run sends a full `package_inventory`.
 */
class PackageCollector(private val context: Context, private val queue: EventQueue) {
    private val pm = context.packageManager
    private val prefs = context.getSharedPreferences("package_state", Context.MODE_PRIVATE)
    private var receiver: BroadcastReceiver? = null

    fun register(scope: CoroutineScope) {
        val r = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                val pkg = intent.data?.schemeSpecificPart ?: return
                val replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
                val pending = goAsync()
                scope.launch {
                    try {
                        when (intent.action) {
                            Intent.ACTION_PACKAGE_ADDED -> if (!replacing) onChanged(pkg, "installed")
                            Intent.ACTION_PACKAGE_REPLACED -> onChanged(pkg, "updated")
                            Intent.ACTION_PACKAGE_FULLY_REMOVED -> onChanged(pkg, "removed")
                        }
                    } catch (e: Exception) {
                        AgentLog.error("Package event handling failed for $pkg", e)
                    } finally {
                        pending.finish()
                    }
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addAction(Intent.ACTION_PACKAGE_FULLY_REMOVED)
            addDataScheme("package")
        }
        ContextCompat.registerReceiver(context, r, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
        receiver = r
    }

    fun unregister() {
        receiver?.let { runCatching { context.unregisterReceiver(it) } }
        receiver = null
    }

    /** Diffs installed packages against the saved snapshot and reports the differences. */
    suspend fun reconcile() = lock.withLock {
        val installed = installedPackages().associateBy { it.packageName }
        val snapshot = loadSnapshot()

        if (snapshot == null) {
            installed.values.sortedBy { it.packageName }.forEach { info ->
                queue.enqueue(Events.build("package_inventory") { putAll(describe(info)) })
            }
            queue.enqueue(summary(installed.values))
        } else {
            installed.values.forEach { info ->
                val known = snapshot[info.packageName]
                when {
                    known == null -> queue.enqueue(packageEvent("installed", describe(info), missedWhileOffline = true))
                    known.versionCode != versionCode(info) || known.lastUpdate != info.lastUpdateTime ->
                        queue.enqueue(packageEvent("updated", describe(info), missedWhileOffline = true, previous = known))
                }
            }
            (snapshot.keys - installed.keys).forEach { name ->
                queue.enqueue(packageEvent("removed", removedDescription(name, snapshot.getValue(name)), missedWhileOffline = true))
            }
            val lastSummary = prefs.getLong(KEY_LAST_SUMMARY, 0)
            if (System.currentTimeMillis() - lastSummary > SUMMARY_INTERVAL_MS) queue.enqueue(summary(installed.values))
        }
        saveSnapshot(installed.values)
    }

    private suspend fun onChanged(packageName: String, action: String) = lock.withLock {
        val snapshot = loadSnapshot().orEmpty().toMutableMap()
        if (action == "removed") {
            val known = snapshot.remove(packageName)
            queue.enqueue(packageEvent("removed", known?.let { removedDescription(packageName, it) } ?: JSONObject().put("package", packageName)))
        } else {
            val info = packageInfo(packageName) ?: return@withLock
            queue.enqueue(packageEvent(action, describe(info), previous = snapshot[packageName]))
            snapshot[packageName] = Known(versionCode(info), info.lastUpdateTime, label(info), info.versionName.orEmpty(), installerOf(packageName).orEmpty())
        }
        writeSnapshot(snapshot)
    }

    private fun packageEvent(action: String, details: JSONObject, missedWhileOffline: Boolean = false, previous: Known? = null) =
        Events.build("package") {
            put("action", action)
            putAll(details)
            put("detected_by", if (missedWhileOffline) "reconcile" else "broadcast")
            previous?.let {
                put("previous_version", it.versionName)
                put("previous_version_code", it.versionCode)
            }
        }

    private fun summary(packages: Collection<PackageInfo>) = Events.build("package_summary") {
        val user = packages.filter { !isSystem(it) }
        val sideloaded = user.filter { InstallerType.of(installerOf(it.packageName)).sideloaded }
        put("total", packages.size)
        put("system", packages.size - user.size)
        put("user", user.size)
        put("sideloaded_count", sideloaded.size)
        put("sideloaded", Events.array(sideloaded.map { it.packageName }.sorted()))
    }.also { prefs.edit { putLong(KEY_LAST_SUMMARY, System.currentTimeMillis()) } }

    private fun describe(info: PackageInfo): JSONObject {
        val app = info.applicationInfo
        val installer = installerOf(info.packageName)
        val installerType = InstallerType.of(installer)
        val dangerous = grantedDangerousPermissions(info)
        return JSONObject().apply {
            put("package", info.packageName)
            put("label", label(info))
            put("version", info.versionName.orEmpty())
            put("version_code", versionCode(info))
            put("installer", installer ?: "")
            put("installer_type", if (isSystem(info) && installer == null) "system" else installerType.id)
            put("sideloaded", !isSystem(info) && installerType.sideloaded)
            put("system_app", isSystem(info))
            put("debuggable", app != null && app.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
            put("target_sdk", app?.targetSdkVersion ?: 0)
            put("first_install_time", info.firstInstallTime)
            put("last_update_time", info.lastUpdateTime)
            put("dangerous_permissions", Events.array(dangerous))
            put("can_install_packages", info.requestedPermissions?.contains(android.Manifest.permission.REQUEST_INSTALL_PACKAGES) == true)
        }
    }

    private fun removedDescription(name: String, known: Known) = JSONObject().apply {
        put("package", name)
        put("label", known.label)
        put("version", known.versionName)
        put("version_code", known.versionCode)
        put("installer", known.installer)
        put("installer_type", InstallerType.of(known.installer.ifEmpty { null }).id)
    }

    private fun grantedDangerousPermissions(info: PackageInfo): List<String> {
        val requested = info.requestedPermissions ?: return emptyList()
        val flags = info.requestedPermissionsFlags ?: return emptyList()
        return requested.indices
            .filter { flags[it] and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0 }
            .map { requested[it] }
            .filter { isDangerous(it) }
            .sorted()
    }

    private val dangerousCache = HashMap<String, Boolean>()

    private fun isDangerous(permission: String): Boolean = dangerousCache.getOrPut(permission) {
        runCatching {
            val p = pm.getPermissionInfo(permission, 0)
            val protection = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) p.protection
            else @Suppress("DEPRECATION") (p.protectionLevel and PermissionInfo.PROTECTION_MASK_BASE)
            protection == PermissionInfo.PROTECTION_DANGEROUS
        }.getOrDefault(false)
    }

    private fun installedPackages(): List<PackageInfo> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
    } else {
        @Suppress("DEPRECATION") pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
    }

    private fun packageInfo(name: String): PackageInfo? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageInfo(name, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            @Suppress("DEPRECATION") pm.getPackageInfo(name, PackageManager.GET_PERMISSIONS)
        }
    }.getOrNull()

    private fun installerOf(name: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(name).installingPackageName
        } else {
            @Suppress("DEPRECATION") pm.getInstallerPackageName(name)
        }
    }.getOrNull()

    private fun label(info: PackageInfo): String =
        info.applicationInfo?.let { runCatching { pm.getApplicationLabel(it).toString() }.getOrNull() } ?: info.packageName

    private fun isSystem(info: PackageInfo) = (info.applicationInfo?.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM != 0

    private fun versionCode(info: PackageInfo): Long =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) info.longVersionCode else @Suppress("DEPRECATION") info.versionCode.toLong()

    private data class Known(val versionCode: Long, val lastUpdate: Long, val label: String, val versionName: String, val installer: String)

    private fun loadSnapshot(): Map<String, Known>? {
        val raw = prefs.getString(KEY_SNAPSHOT, null) ?: return null
        return runCatching {
            val json = JSONObject(raw)
            json.keys().asSequence().associateWith { name ->
                val o = json.getJSONObject(name)
                Known(o.getLong("vc"), o.getLong("lu"), o.optString("l"), o.optString("v"), o.optString("i"))
            }
        }.getOrNull()
    }

    private fun saveSnapshot(packages: Collection<PackageInfo>) = writeSnapshot(
        packages.associate {
            it.packageName to Known(versionCode(it), it.lastUpdateTime, label(it), it.versionName.orEmpty(), installerOf(it.packageName).orEmpty())
        },
    )

    private fun writeSnapshot(snapshot: Map<String, Known>) {
        val json = JSONObject()
        snapshot.forEach { (name, k) ->
            json.put(name, JSONObject().put("vc", k.versionCode).put("lu", k.lastUpdate).put("l", k.label).put("v", k.versionName).put("i", k.installer))
        }
        prefs.edit { putString(KEY_SNAPSHOT, json.toString()) }
    }

    private fun JSONObject.putAll(other: JSONObject) {
        other.keys().forEach { put(it, other.get(it)) }
    }

    private companion object {
        const val KEY_SNAPSHOT = "snapshot"
        const val KEY_LAST_SUMMARY = "last_summary"
        const val SUMMARY_INTERVAL_MS = 24 * 60 * 60 * 1000L
        /** Shared by the service's receiver and the periodic worker, which run in the same process. */
        val lock = Mutex()
    }
}

enum class InstallerType(val id: String, val sideloaded: Boolean) {
    PLAY_STORE("play_store", false),
    OEM_STORE("oem_store", false),
    FDROID("fdroid", false),
    PACKAGE_INSTALLER("package_installer", true),
    ADB("adb", true),
    UNKNOWN("unknown", true),
    OTHER("other", true);

    companion object {
        private val OEM_STORES = setOf(
            "com.sec.android.app.samsungapps", "com.amazon.venezia", "com.huawei.appmarket",
            "com.xiaomi.market", "com.xiaomi.mipicks", "com.oppo.market", "com.heytap.market",
            "com.bbk.appstore", "com.oneplus.appstore",
        )

        fun of(installer: String?): InstallerType = when (installer) {
            null, "" -> UNKNOWN
            "com.android.vending", "com.google.android.feedback" -> PLAY_STORE
            in OEM_STORES -> OEM_STORE
            "org.fdroid.fdroid", "org.fdroid.basic", "com.looker.droidify", "com.machiav3lli.fdroid" -> FDROID
            "com.android.shell" -> ADB
            "com.google.android.packageinstaller", "com.android.packageinstaller", "com.samsung.android.packageinstaller" -> PACKAGE_INSTALLER
            else -> OTHER
        }
    }
}
