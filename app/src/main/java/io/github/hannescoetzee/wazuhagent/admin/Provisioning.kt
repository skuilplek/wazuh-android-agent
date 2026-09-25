package io.github.hannescoetzee.wazuhagent.admin

import android.content.Context
import android.os.PersistableBundle
import io.github.hannescoetzee.wazuhagent.DeviceInfo
import io.github.hannescoetzee.wazuhagent.app
import io.github.hannescoetzee.wazuhagent.collectors.AgentLog
import io.github.hannescoetzee.wazuhagent.service.Enroller
import io.github.hannescoetzee.wazuhagent.storage.validatedManagerConfig
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Manager settings from the QR code's `PROVISIONING_ADMIN_EXTRAS_BUNDLE`. See
 * `provisioning/qr_payload.example.json` for the keys.
 */
object Provisioning {
    /** Android 12+ delivers the extras to both the compliance activity and the receiver. */
    private val started = AtomicBoolean(false)

    /** Blocking; run it off the main thread. Saves the settings and enrolls. */
    fun apply(context: Context, extras: PersistableBundle?) {
        if (extras == null || extras.isEmpty) return
        val store = context.app.store
        if (store.agentKey != null || !started.compareAndSet(false, true)) return

        val config = try {
            validatedManagerConfig(
                host = extras.text("manager_host"),
                enrollPort = extras.text("enroll_port", "1515"),
                port = extras.text("agent_port", "1514"),
                password = extras.text("enrollment_password"),
                agentName = extras.text("agent_name").ifBlank { DeviceInfo.defaultAgentName() },
                groups = extras.text("groups"),
                keepaliveSeconds = extras.text("keepalive_seconds", "60"),
            )
        } catch (e: IllegalArgumentException) {
            AgentLog.error("Provisioning extras rejected: ${e.message}")
            return
        }
        store.config = config
        runCatching { Enroller.enroll(context, config, extras.text("manager_cert_sha256").ifBlank { null }) }
            .onFailure { AgentLog.error("Enrollment from provisioning extras failed; enroll from the app instead", it) }
    }

    /** QR payloads may carry ports as numbers or strings. */
    @Suppress("DEPRECATION")
    private fun PersistableBundle.text(key: String, default: String = ""): String = get(key)?.toString() ?: default
}
