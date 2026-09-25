package io.github.hannescoetzee.wazuhagent

import android.os.Build
import io.github.hannescoetzee.wazuhagent.protocol.AgentIdentity
import io.github.hannescoetzee.wazuhagent.protocol.AgentNames

object DeviceInfo {
    /** App build, separate from the Wazuh protocol version negotiated with the manager. */
    val appVersion: String = "${BuildConfig.VERSION_NAME}+${BuildConfig.VERSION_CODE}"

    fun defaultAgentName(): String = AgentNames.sanitize("${Build.MANUFACTURER}-${Build.MODEL}")

    fun identity(agentVersion: String): AgentIdentity = AgentIdentity(
        hostname = AgentNames.sanitize(Build.MODEL),
        kernelRelease = System.getProperty("os.version").orEmpty().ifEmpty { "unknown" },
        buildVersion = Build.DISPLAY,
        machine = System.getProperty("os.arch").orEmpty().ifEmpty { Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown" },
        osVersion = Build.VERSION.RELEASE,
        agentVersion = agentVersion,
    )

    /** Sent with every keepalive; shown as agent labels in the dashboard. */
    fun labels(): Map<String, String> = mapOf(
        "device.manufacturer" to Build.MANUFACTURER,
        "device.model" to Build.MODEL,
        "android.release" to Build.VERSION.RELEASE,
        "android.sdk" to Build.VERSION.SDK_INT.toString(),
        "android.security_patch" to Build.VERSION.SECURITY_PATCH,
        "agent.type" to "android",
        "agent.app_version" to appVersion,
    )
}
