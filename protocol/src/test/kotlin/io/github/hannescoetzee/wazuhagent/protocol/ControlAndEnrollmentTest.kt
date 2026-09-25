package io.github.hannescoetzee.wazuhagent.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ControlAndEnrollmentTest {
    private val identity = AgentIdentity(
        hostname = "Pixel-8",
        kernelRelease = "5.15.137-android14",
        buildVersion = "AP2A.240905.003",
        machine = "aarch64",
        osVersion = "14",
    )

    @Test
    fun enrollmentRequestMatchesAuthdFormat() {
        val req = EnrollmentRequest(
            host = "h", agentName = "Pixel-8", password = "s3cret", groups = "android", agentVersion = "v4.9.2",
        )
        assertEquals("OSSEC PASS: s3cret OSSEC A:'Pixel-8' V:'v4.9.2' G:'android'\n", Enrollment.buildRequest(req))
        assertEquals("OSSEC A:'Pixel-8'\n", Enrollment.buildRequest(EnrollmentRequest(host = "h", agentName = "Pixel-8")))
    }

    @Test
    fun parsesKeyAndErrors() {
        val key = Enrollment.parseResponse("OSSEC K:'012 Pixel-8 any 4f2a9c'\n\n")
        assertEquals("012", key.id)
        assertEquals("Pixel-8", key.name)
        assertEquals("any", key.ip)
        assertEquals("4f2a9c", key.key)

        val err = assertThrows(EnrollmentException::class.java) {
            Enrollment.parseResponse("ERROR: Invalid password\n")
        }
        assertEquals("Invalid password", err.message)

        val versionErr = assertThrows(EnrollmentException::class.java) {
            Enrollment.parseResponse("ERROR: Agent version must be lower or equal to manager version\n")
        }
        assertTrue(Enrollment.isVersionRejection(versionErr))
        assertTrue(!Enrollment.isVersionRejection(err))
    }

    @Test
    fun unameUsesWazuhLayout() {
        assertEquals(
            "Linux |Pixel-8 |5.15.137-android14 |AP2A.240905.003 |aarch64 [Android|android: 14] - Wazuh v4.9.2",
            identity.uname(),
        )
    }

    @Test
    fun keepaliveMatchesRunNotify() {
        val msg = Control.keepalive(identity, mapOf("device.model" to "Pixel 8"), "x", "192.168.1.50")
        assertEquals(
            "#!-${identity.uname()}\n\"device.model\":Pixel 8\nx merged.mg\n#\"_agent_ip\":192.168.1.50\n",
            msg,
        )
    }

    @Test
    fun startupAndEventFormats() {
        assertEquals("#!-agent startup {\"version\":\"v4.9.2\"}", Control.startup("v4.9.2"))
        assertEquals("1:android:{}", Control.event("android", "{}"))
        assertTrue(runCatching { Control.event("bad:loc", "x") }.isFailure)
    }

    @Test
    fun sanitizesAgentNames() {
        assertEquals("Pixel-8-Pro", AgentNames.sanitize("Pixel 8 Pro"))
        assertEquals("Galaxy-S23-5G", AgentNames.sanitize("Galaxy S23 (5G)"))
        assertTrue(AgentNames.isValid(AgentNames.sanitize("é")))
    }
}
