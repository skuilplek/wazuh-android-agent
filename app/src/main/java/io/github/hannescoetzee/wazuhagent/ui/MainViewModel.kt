package io.github.hannescoetzee.wazuhagent.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.hannescoetzee.wazuhagent.DeviceInfo
import io.github.hannescoetzee.wazuhagent.app
import io.github.hannescoetzee.wazuhagent.collectors.AgentLog
import io.github.hannescoetzee.wazuhagent.collectors.CollectorManager
import io.github.hannescoetzee.wazuhagent.collectors.PostureWorker
import io.github.hannescoetzee.wazuhagent.protocol.AgentNames
import io.github.hannescoetzee.wazuhagent.protocol.Enrollment
import io.github.hannescoetzee.wazuhagent.protocol.EnrollmentRequest
import io.github.hannescoetzee.wazuhagent.service.AgentForegroundService
import io.github.hannescoetzee.wazuhagent.service.AgentState
import io.github.hannescoetzee.wazuhagent.storage.ManagerConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class SetupForm(
    val host: String = "",
    val enrollPort: String = "1515",
    val port: String = "1514",
    val password: String = "",
    val agentName: String = DeviceInfo.defaultAgentName(),
    val groups: String = "",
    val keepaliveSeconds: String = "60",
)

data class EnrollmentInfo(
    val agentId: String,
    val agentName: String,
    val agentVersion: String?,
    val certSha256: String?,
)

data class UiState(
    val form: SetupForm = SetupForm(),
    val enrollment: EnrollmentInfo? = null,
    val busy: Boolean = false,
    val message: String? = null,
    val isError: Boolean = false,
    val agentEnabled: Boolean = false,
)

class MainViewModel(application: Application) : AndroidViewModel(application) {
    private val store = application.app.store
    private val queue = application.app.queue

    private val _ui = MutableStateFlow(UiState())
    val ui: StateFlow<UiState> = _ui.asStateFlow()

    val status = AgentState.status
    val queueSize: StateFlow<Int> = queue.size.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), 0)

    init {
        viewModelScope.launch {
            val loaded = withContext(Dispatchers.IO) { Triple(store.config, enrollmentInfo(), store.agentEnabled) }
            _ui.update { state ->
                state.copy(
                    form = loaded.first?.toForm() ?: state.form,
                    enrollment = loaded.second,
                    agentEnabled = loaded.third,
                )
            }
        }
    }

    fun updateForm(transform: (SetupForm) -> SetupForm) = _ui.update { it.copy(form = transform(it.form), message = null) }

    fun enroll() {
        val config = validatedConfig() ?: return
        _ui.update { it.copy(busy = true, message = "Enrolling with ${config.host}:${config.enrollPort}…", isError = false) }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val previousHost = store.config?.host
                    val pin = store.pinnedCertSha256.takeIf { previousHost == config.host && store.agentKey != null }
                    val request = EnrollmentRequest(
                        host = config.host,
                        port = config.enrollPort,
                        agentName = config.agentName,
                        password = config.password.ifEmpty { null },
                        groups = config.groups.ifBlank { null },
                        pinnedCertSha256 = pin,
                    )
                    val enrolled = Enrollment.enrollNegotiatingVersion(request)
                    AgentForegroundService.stop(getApplication())
                    store.config = config
                    store.saveEnrollment(enrolled.key, enrolled.agentVersion, enrolled.serverCertSha256)
                    CollectorManager.resetState(getApplication())
                    store.agentEnabled = true
                    enrolled
                }
            }
            result.onSuccess { enrolled ->
                AgentLog.info("Enrolled as agent ${enrolled.key.id} (${enrolled.key.name}) with ${config.host}")
                AgentForegroundService.start(getApplication())
                _ui.update {
                    it.copy(
                        busy = false,
                        enrollment = enrollmentInfo(),
                        agentEnabled = true,
                        message = "Enrolled as agent ${enrolled.key.id}. Agent started.",
                        isError = false,
                    )
                }
            }.onFailure { e ->
                _ui.update { it.copy(busy = false, message = e.message ?: e.javaClass.simpleName, isError = true) }
            }
        }
    }

    fun saveSettings() {
        val config = validatedConfig() ?: return
        viewModelScope.launch(Dispatchers.IO) {
            store.config = config
            _ui.update { it.copy(message = "Settings saved. Restart the agent to apply.", isError = false) }
        }
    }

    fun startAgent() {
        store.agentEnabled = true
        AgentForegroundService.start(getApplication())
        _ui.update { it.copy(agentEnabled = true, message = null) }
    }

    fun stopAgent() {
        AgentForegroundService.stop(getApplication())
        _ui.update { it.copy(agentEnabled = false, message = null) }
    }

    /** Drops the local key; the agent must also be removed on the manager to free the name. */
    fun forgetEnrollment() {
        AgentForegroundService.stop(getApplication())
        viewModelScope.launch(Dispatchers.IO) {
            store.clearEnrollment()
            queue.clear()
            PostureWorker.cancel(getApplication())
            CollectorManager.resetState(getApplication())
            _ui.update {
                it.copy(enrollment = null, agentEnabled = false, message = "Enrollment removed from this phone.", isError = false)
            }
        }
    }

    private fun showError(message: String) = _ui.update { it.copy(message = message, isError = true) }

    /** Shows the first problem and returns null, or writes the cleaned-up values back into the form. */
    private fun validatedConfig(): ManagerConfig? {
        val config = try {
            _ui.value.form.toConfig()
        } catch (e: IllegalArgumentException) {
            showError(e.message ?: "Invalid settings")
            return null
        }
        _ui.update { it.copy(form = config.toForm()) }
        return config
    }

    private fun enrollmentInfo(): EnrollmentInfo? = store.agentKey?.let {
        EnrollmentInfo(it.id, it.name, store.agentVersion, store.pinnedCertSha256)
    }

    private fun ManagerConfig.toForm() = SetupForm(
        host = host,
        enrollPort = enrollPort.toString(),
        port = port.toString(),
        password = password,
        agentName = agentName,
        groups = groups,
        keepaliveSeconds = keepaliveSeconds.toString(),
    )

    private fun SetupForm.toConfig(): ManagerConfig {
        val host = host.trim()
        require(host.isNotEmpty()) { "Enter the manager address" }
        require(host.none { it.isWhitespace() }) { "Manager address must not contain spaces" }
        val enrollPort = parsePort(enrollPort, "Enroll port")
        val port = parsePort(port, "Agent port")
        val keepalive = keepaliveSeconds.trim().toIntOrNull()?.takeIf { it in 10..600 }
            ?: throw IllegalArgumentException("Keepalive must be between 10 and 600 seconds")
        require(password.none { it == '\n' || it == '\r' }) { "Password must not contain line breaks" }
        val name = AgentNames.sanitize(agentName)
        require(AgentNames.isValid(name)) { "Agent name must be 2-128 letters, digits, '.', '_' or '-'" }
        val groupList = groups.split(',').map { it.trim() }.filter { it.isNotEmpty() }
        require(groupList.all { GROUP_NAME.matches(it) }) {
            "Group names may only use letters, digits, '.', '_' or '-' (separate groups with commas)"
        }
        return ManagerConfig(
            host = host,
            enrollPort = enrollPort,
            port = port,
            password = password,
            agentName = name,
            groups = groupList.joinToString(","),
            keepaliveSeconds = keepalive,
        )
    }

    private fun parsePort(value: String, label: String): Int =
        value.trim().toIntOrNull()?.takeIf { it in 1..65535 }
            ?: throw IllegalArgumentException("$label must be a number from 1 to 65535")

    private companion object {
        val GROUP_NAME = Regex("^[A-Za-z0-9._-]{1,255}$")
    }
}
