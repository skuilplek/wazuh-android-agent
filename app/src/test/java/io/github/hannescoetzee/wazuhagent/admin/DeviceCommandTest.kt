package io.github.hannescoetzee.wazuhagent.admin

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceCommandTest {
    @Test
    fun timeoutSuffixIsRemovedOnlyForKnownCommands() {
        assertEquals("android-lock", canonicalCommand("android-lock0"))
        assertEquals("android-suspend", canonicalCommand("android-suspend10"))
        assertEquals("restart-wazuh0", canonicalCommand("restart-wazuh0"))
    }

    @Test
    fun parseReadsCommandArgumentsAndAlertPackage() {
        val payload = """
            {"command":"android-suspend0","parameters":{"extra_args":[],"alert":{"data":{"android":{"package":"com.example.tool"}}}}}
        """.trim()
        val request = parseExec(payload)
        assertEquals("android-suspend", request?.command)
        assertEquals("com.example.tool", packageNameFrom(request!!.extraArgs, request.alert))
    }

    @Test
    fun extraArgPackageWinsOverTheAlert() {
        val alert = JSONObject("""{"data":{"android":{"package":"com.from.alert"}}}""")
        assertEquals("com.from.args", packageNameFrom(listOf("com.from.args"), alert))
    }

    @Test
    fun wipeTokenIsNotAPackageName() {
        assertFalse(isPackageName(WIPE_CONFIRM))
        assertNull(packageNameFrom(listOf(WIPE_CONFIRM), null))
    }

    @Test
    fun lockMessageUsesArgumentsOrADefault() {
        assertEquals("Call the desk", lockMessage(listOf("Call the desk")))
        assertEquals(DEFAULT_LOCK_MESSAGE, lockMessage(emptyList()))
        assertEquals(DEFAULT_LOCK_MESSAGE, lockMessage(listOf(WIPE_CONFIRM)))
    }

    @Test
    fun malformedPayloadIsIgnored() {
        assertNull(parseExec("not-json"))
        assertNull(parseExec("""{"parameters":{}}"""))
    }

    @Test
    fun orgPolicyAcceptsTheQrValues() {
        assertTrue(orgPolicyRequested("true"))
        assertTrue(orgPolicyRequested("YES"))
        assertTrue(orgPolicyRequested("1"))
        assertFalse(orgPolicyRequested("false"))
        assertFalse(orgPolicyRequested(""))
    }
}
