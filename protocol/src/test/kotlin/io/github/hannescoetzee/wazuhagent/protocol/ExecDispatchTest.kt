package io.github.hannescoetzee.wazuhagent.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ExecDispatchTest {
    @Test
    fun execdPayloadReachesTheListenerWithoutTheHeader() {
        var payload: String? = null
        val connection = connection(object : AgentConnection.Listener {
            override fun onExec(value: String) {
                payload = value
            }
        })
        connection.handleMessage("#!-execd {\"command\":\"android-lock0\"}")
        assertEquals("{\"command\":\"android-lock0\"}", payload)
    }

    @Test
    fun otherControlMessagesAreNotTreatedAsCommands() {
        var payload: String? = null
        var unhandled: String? = null
        val connection = connection(object : AgentConnection.Listener {
            override fun onExec(value: String) {
                payload = value
            }

            override fun onUnhandled(text: String) {
                unhandled = text
            }
        })
        connection.handleMessage("#!-restart-wazuh")
        assertNull(payload)
        assertEquals("#!-restart-wazuh", unhandled)
    }

    private fun connection(listener: AgentConnection.Listener) = AgentConnection(
        host = "127.0.0.1",
        port = 1514,
        key = AgentKey("001", "pixel", "any", "00112233445566778899aabbccddeeff"),
        counter = SenderCounter(InMemoryCounterStore()),
        identity = AgentIdentity("pixel", "5.15", "AP2A", "aarch64", "14"),
        listener = listener,
    )
}
