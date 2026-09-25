package io.github.hannescoetzee.wazuhagent.admin

/** One DNS lookup ([port] is null) or TCP connect ([host] is the IP address) from a network log batch. */
data class NetworkLogEntry(
    val kind: String,
    val packageName: String,
    val host: String,
    val port: Int?,
    val addresses: List<String>,
    val timeMillis: Long,
)

data class NetworkLogGroup(
    val kind: String,
    val packageName: String,
    val host: String,
    val port: Int?,
    val addresses: List<String>,
    val count: Int,
    val firstMillis: Long,
    val lastMillis: Long,
)

/**
 * A batch holds up to 1200 entries, mostly repeats of the same lookups. Sending one event per
 * package and destination keeps the queue and the manager's event rate manageable.
 */
object NetworkLogGrouper {
    const val MAX_ADDRESSES = 10

    fun group(entries: List<NetworkLogEntry>): List<NetworkLogGroup> =
        entries.groupBy { listOf(it.kind, it.packageName, it.host, it.port) }
            .values
            .map { same ->
                val first = same.first()
                NetworkLogGroup(
                    kind = first.kind,
                    packageName = first.packageName,
                    host = first.host,
                    port = first.port,
                    addresses = same.flatMap { it.addresses }.distinct().sorted().take(MAX_ADDRESSES),
                    count = same.size,
                    firstMillis = same.minOf { it.timeMillis },
                    lastMillis = same.maxOf { it.timeMillis },
                )
            }
            .sortedBy { it.firstMillis }
}
