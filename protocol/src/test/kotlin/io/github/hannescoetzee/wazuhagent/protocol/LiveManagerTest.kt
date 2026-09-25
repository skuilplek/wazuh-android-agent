package io.github.hannescoetzee.wazuhagent.protocol

import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * End-to-end check against a real manager. Skipped unless `WAZUH_MANAGER` is set:
 *
 *     WAZUH_MANAGER=192.168.1.10 WAZUH_PASSWORD=secret ./gradlew :protocol:test --tests '*LiveManagerTest*'
 */
class LiveManagerTest {
    @Test
    fun enrollsConnectsAndSendsEvents() {
        val host = System.getenv("WAZUH_MANAGER").orEmpty()
        assumeTrue("WAZUH_MANAGER not set", host.isNotEmpty())
        val name = System.getenv("WAZUH_AGENT_NAME")?.takeIf { it.isNotEmpty() } ?: "protocol-test-${System.currentTimeMillis() % 100000}"
        val enrollPort = System.getenv("WAZUH_ENROLL_PORT")?.toIntOrNull() ?: 1515
        val port = System.getenv("WAZUH_PORT")?.toIntOrNull() ?: 1514
        val candidates = System.getenv("WAZUH_AGENT_VERSION")?.takeIf { it.isNotEmpty() }?.let { listOf(it) }
            ?: Enrollment.VERSION_CANDIDATES

        val result = Enrollment.enrollNegotiatingVersion(
            EnrollmentRequest(
                host = host,
                port = enrollPort,
                agentName = name,
                password = System.getenv("WAZUH_PASSWORD")?.takeIf { it.isNotEmpty() },
                groups = System.getenv("WAZUH_GROUP")?.takeIf { it.isNotEmpty() },
            ),
            candidates,
        )
        val version = result.agentVersion ?: AgentIdentity.DEFAULT_AGENT_VERSION
        println("Enrolled ${result.key} cert=${result.serverCertSha256}")
        Thread.sleep(2_000)

        val acks = CountDownLatch(2)
        val identity = AgentIdentity("protocol-test", "6.1.0", "test", "aarch64", "14", agentVersion = version)
        val conn = AgentConnection(
            host, port, result.key, SenderCounter(InMemoryCounterStore()), identity,
            listener = object : AgentConnection.Listener {
                override fun onAck() = acks.countDown()
                override fun onUnhandled(text: String) = println("manager: $text")
            },
        )
        conn.connect()
        conn.sendKeepalive(mapOf("device.model" to "JVM test"), "x")
        conn.sendEvent(
            "android",
            "{\"android\":{\"type\":\"posture\",\"device_secure\":false,\"adb_enabled\":true,\"source\":\"protocol-test\"}}",
        )
        assertTrue("expected ack for startup and keepalive", acks.await(30, TimeUnit.SECONDS))
        Thread.sleep(2_000)
        conn.shutdown()
    }
}
