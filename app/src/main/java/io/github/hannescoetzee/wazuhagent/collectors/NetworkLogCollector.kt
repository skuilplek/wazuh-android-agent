package io.github.hannescoetzee.wazuhagent.collectors

import android.app.admin.ConnectEvent
import android.app.admin.DevicePolicyManager
import android.app.admin.DnsEvent
import android.content.Context
import io.github.hannescoetzee.wazuhagent.admin.AgentDeviceAdminReceiver
import io.github.hannescoetzee.wazuhagent.admin.DeviceOwner
import io.github.hannescoetzee.wazuhagent.admin.NetworkLogEntry
import io.github.hannescoetzee.wazuhagent.admin.NetworkLogGrouper
import io.github.hannescoetzee.wazuhagent.queue.EventQueue
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/**
 * Device Owner only. DNS lookups and TCP connects per app, from the batch Android announces
 * in `onNetworkLogsAvailable`. The batch token is only valid inside that callback.
 */
class NetworkLogCollector(private val context: Context) {
    suspend fun collect(queue: EventQueue, batchToken: Long) {
        if (!DeviceOwner.isDeviceOwner(context)) return
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
        val events = runCatching { dpm.retrieveNetworkLogs(AgentDeviceAdminReceiver.component(context), batchToken) }
            .onFailure { AgentLog.warn("Network log retrieval failed: ${it.message}") }
            .getOrNull() ?: return

        val entries = events.mapNotNull { e ->
            when (e) {
                is DnsEvent -> NetworkLogEntry(
                    "dns", e.packageName.orEmpty(), e.hostname.orEmpty(), null,
                    e.inetAddresses.mapNotNull { it.hostAddress }, e.timestamp,
                )
                is ConnectEvent -> NetworkLogEntry(
                    "connect", e.packageName.orEmpty(), e.inetAddress.hostAddress.orEmpty(), e.port,
                    emptyList(), e.timestamp,
                )
                else -> null
            }
        }
        NetworkLogGrouper.group(entries).forEach { g ->
            queue.enqueue(
                Events.build("network_log") {
                    put("kind", g.kind)
                    put("package", g.packageName)
                    if (g.kind == "dns") {
                        put("hostname", g.host)
                        put("addresses", Events.array(g.addresses))
                    } else {
                        put("ip", g.host)
                        put("port", g.port)
                    }
                    put("count", g.count)
                    put("first_seen", iso(g.firstMillis))
                    put("last_seen", iso(g.lastMillis))
                },
            )
        }
    }

    private fun iso(millis: Long): String =
        OffsetDateTime.ofInstant(Instant.ofEpochMilli(millis), ZoneId.systemDefault()).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
}
