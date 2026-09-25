package io.github.hannescoetzee.wazuhagent.service

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

enum class ConnectionState { STOPPED, CONNECTING, CONNECTED, WAITING_RETRY }

data class AgentStatus(
    val state: ConnectionState = ConnectionState.STOPPED,
    val detail: String = "",
    val lastAckAt: Long = 0,
    val eventsSent: Long = 0,
)

/** Process-wide status shared between the service and the UI. */
object AgentState {
    private val _status = MutableStateFlow(AgentStatus())
    val status: StateFlow<AgentStatus> = _status

    fun set(state: ConnectionState, detail: String = "") = _status.update { it.copy(state = state, detail = detail) }

    fun acked(at: Long) = _status.update { it.copy(lastAckAt = at) }

    fun sent(count: Int) = _status.update { it.copy(eventsSent = it.eventsSent + count) }
}
