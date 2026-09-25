package io.github.hannescoetzee.wazuhagent.admin

import org.junit.Assert.assertEquals
import org.junit.Test

class NetworkLogGrouperTest {
    private fun dns(pkg: String, host: String, time: Long, vararg ips: String) =
        NetworkLogEntry("dns", pkg, host, null, ips.toList(), time)

    private fun connect(pkg: String, ip: String, port: Int, time: Long) =
        NetworkLogEntry("connect", pkg, ip, port, emptyList(), time)

    @Test
    fun repeatedLookupsCollapseIntoOneGroupWithCountAndTimeRange() {
        val groups = NetworkLogGrouper.group(
            listOf(
                dns("com.app", "api.example.com", 300, "10.0.0.2"),
                dns("com.app", "api.example.com", 100, "10.0.0.1"),
                dns("com.app", "api.example.com", 200, "10.0.0.1"),
            ),
        )
        assertEquals(1, groups.size)
        val g = groups.single()
        assertEquals(3, g.count)
        assertEquals(100L, g.firstMillis)
        assertEquals(300L, g.lastMillis)
        assertEquals(listOf("10.0.0.1", "10.0.0.2"), g.addresses)
    }

    @Test
    fun packageKindHostAndPortAllSeparateGroups() {
        val groups = NetworkLogGrouper.group(
            listOf(
                dns("com.a", "example.com", 1),
                dns("com.b", "example.com", 2),
                connect("com.a", "93.184.216.34", 443, 3),
                connect("com.a", "93.184.216.34", 80, 4),
                connect("com.a", "93.184.216.34", 443, 5),
            ),
        )
        assertEquals(4, groups.size)
        assertEquals(listOf(1L, 2L, 3L, 4L), groups.map { it.firstMillis })
        assertEquals(2, groups.single { it.port == 443 }.count)
    }

    @Test
    fun addressListIsCapped() {
        val ips = (1..25).map { "10.0.0.$it" }.toTypedArray()
        val g = NetworkLogGrouper.group(listOf(dns("com.cdn", "cdn.example.com", 1, *ips))).single()
        assertEquals(NetworkLogGrouper.MAX_ADDRESSES, g.addresses.size)
    }
}
