package io.github.hannescoetzee.wazuhagent.service

import android.content.Context
import io.github.hannescoetzee.wazuhagent.app
import io.github.hannescoetzee.wazuhagent.collectors.AgentLog
import io.github.hannescoetzee.wazuhagent.collectors.CollectorManager
import io.github.hannescoetzee.wazuhagent.protocol.Enrollment
import io.github.hannescoetzee.wazuhagent.protocol.EnrollmentRequest
import io.github.hannescoetzee.wazuhagent.protocol.EnrollmentResult
import io.github.hannescoetzee.wazuhagent.storage.ManagerConfig

/** Enrollment shared by the setup screen and QR provisioning. */
object Enroller {
    /**
     * Blocking network call; run it off the main thread. Saves the key and starts the agent.
     * Without [pinnedCertSha256], a re-enrollment to the same host must present the
     * certificate pinned the first time.
     */
    fun enroll(context: Context, config: ManagerConfig, pinnedCertSha256: String? = null): EnrollmentResult {
        val store = context.app.store
        val previousHost = store.config?.host
        val pin = pinnedCertSha256?.takeIf { it.isNotBlank() }
            ?: store.pinnedCertSha256.takeIf { previousHost == config.host && store.agentKey != null }
        val request = EnrollmentRequest(
            host = config.host,
            port = config.enrollPort,
            agentName = config.agentName,
            password = config.password.ifEmpty { null },
            groups = config.groups.ifBlank { null },
            pinnedCertSha256 = pin,
        )
        val enrolled = Enrollment.enrollNegotiatingVersion(request)
        AgentForegroundService.stop(context)
        store.config = config
        store.saveEnrollment(enrolled.key, enrolled.agentVersion, enrolled.serverCertSha256)
        CollectorManager.resetState(context)
        store.agentEnabled = true
        AgentLog.info("Enrolled as agent ${enrolled.key.id} (${enrolled.key.name}) with ${config.host}")
        // Android can refuse a background start; the agent then starts on the next boot or when the app is opened.
        runCatching { AgentForegroundService.start(context) }
            .onFailure { AgentLog.warn("Agent service could not start after enrollment: ${it.message}") }
        return enrolled
    }
}
