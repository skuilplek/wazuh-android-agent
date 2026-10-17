package io.github.hannescoetzee.wazuhagent.collectors

import android.app.admin.DevicePolicyManager
import android.app.admin.SecurityLog
import android.content.Context
import android.provider.Settings
import androidx.core.content.edit
import io.github.hannescoetzee.wazuhagent.admin.AgentDeviceAdminReceiver
import io.github.hannescoetzee.wazuhagent.admin.DeviceOwner
import io.github.hannescoetzee.wazuhagent.admin.SecurityLogMapper
import io.github.hannescoetzee.wazuhagent.queue.EventQueue
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/**
 * Device Owner only. Android hands out new security log entries only after it has called
 * `onSecurityLogsAvailable`, so [collect] runs from that callback. [collectPreReboot] picks up
 * what was logged between the last batch and a reboot, once per boot.
 */
class SecurityLogCollector(private val context: Context) {
    private val dpm = context.getSystemService(DevicePolicyManager::class.java)
    private val admin = AgentDeviceAdminReceiver.component(context)
    private val prefs = context.getSharedPreferences("security_log_state", Context.MODE_PRIVATE)

    suspend fun collect(queue: EventQueue) = lock.withLock {
        if (!DeviceOwner.isDeviceOwner(context)) return@withLock
        val logs = runCatching { dpm.retrieveSecurityLogs(admin) }
            .onFailure { AgentLog.warn("Security log retrieval failed: ${it.message}") }
            .getOrNull() ?: return@withLock
        report(queue, logs, "batch")
    }

    suspend fun collectPreReboot(queue: EventQueue) = lock.withLock {
        if (!DeviceOwner.isDeviceOwner(context)) return@withLock
        val boot = Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT, -1)
        if (boot == prefs.getInt(KEY_BOOT, Int.MIN_VALUE)) return@withLock
        prefs.edit { putInt(KEY_BOOT, boot) }
        // Null or an exception when the phone does not keep logs across reboots.
        val logs = runCatching { dpm.retrievePreRebootSecurityLogs(admin) }.getOrNull() ?: return@withLock
        report(queue, logs, "pre_reboot")
    }

    /** Entry ids restart at every boot, so the timestamp is what marks entries as already sent. */
    private suspend fun report(queue: EventQueue, logs: List<SecurityLog.SecurityEvent>, source: String) {
        val watermark = prefs.getLong(KEY_LAST_NANOS, 0)
        val fresh = logs.filter { it.timeNanos > watermark }.sortedBy { it.timeNanos }
        val hashes = loadHashes()
        var hashesChanged = false
        fresh.forEach { entry ->
            val mapped = SecurityLogMapper.map(entry.tag, entry.data) ?: return@forEach
            if (mapped.tag == "app_apk_hash") {
                val process = mapped.fields["process"] as? String ?: return@forEach
                val hash = mapped.fields["apk_sha256"] as? String ?: return@forEach
                if (!rememberApkHash(hashes, process, hash)) return@forEach
                hashesChanged = true
            }
            queue.enqueue(
                Events.build("security_log") {
                    put("tag", mapped.tag)
                    put("logged_at", iso(entry.timeNanos))
                    put("source", source)
                    mapped.fields.forEach { (k, v) -> put(k, v) }
                },
            )
        }
        fresh.lastOrNull()?.let { last ->
            prefs.edit {
                putLong(KEY_LAST_NANOS, last.timeNanos)
                if (hashesChanged) putString(KEY_APK_HASHES, JSONObject(hashes as Map<String, String>).toString())
            }
        }
    }

    private fun loadHashes(): MutableMap<String, String> {
        val raw = prefs.getString(KEY_APK_HASHES, null) ?: return mutableMapOf()
        return runCatching {
            val json = JSONObject(raw)
            json.keys().asSequence().associateWith { json.getString(it) }.toMutableMap()
        }.getOrDefault(mutableMapOf())
    }

    private fun iso(nanos: Long): String =
        OffsetDateTime.ofInstant(Instant.ofEpochMilli(nanos / 1_000_000), ZoneId.systemDefault())
            .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)

    private companion object {
        const val KEY_LAST_NANOS = "last_time_nanos"
        const val KEY_BOOT = "pre_reboot_boot_count"
        const val KEY_APK_HASHES = "apk_hashes"
        /** The admin callback and the service start may both run a collection. */
        val lock = Mutex()
    }
}

/** True when [hash] is new for [process]. Same hash on the next launch is not reported again. */
internal fun rememberApkHash(known: MutableMap<String, String>, process: String, hash: String): Boolean {
    if (process.isEmpty() || hash.length != 64) return false
    if (known[process] == hash) return false
    known[process] = hash
    return true
}
