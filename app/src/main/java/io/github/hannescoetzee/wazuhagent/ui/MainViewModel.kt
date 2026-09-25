package io.github.hannescoetzee.wazuhagent.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.hannescoetzee.wazuhagent.DeviceInfo
import io.github.hannescoetzee.wazuhagent.app
import io.github.hannescoetzee.wazuhagent.collectors.CollectorManager
import io.github.hannescoetzee.wazuhagent.collectors.PostureWorker
import io.github.hannescoetzee.wazuhagent.service.AgentForegroundService
import io.github.hannescoetzee.wazuhagent.service.AgentState
import io.github.hannescoetzee.wazuhagent.service.Enroller
import io.github.hannescoetzee.wazuhagent.storage.ManagerConfig
import io.github.hannescoetzee.wazuhagent.storage.validatedManagerConfig
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
            if (loaded.second != null && loaded.third) AgentForegroundService.start(getApplication())
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
                runCatching { Enroller.enroll(getApplication(), config) }
            }
            result.onSuccess { enrolled ->
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

    private fun SetupForm.toConfig(): ManagerConfig =
        validatedManagerConfig(host, enrollPort, port, password, agentName, groups, keepaliveSeconds)
}
