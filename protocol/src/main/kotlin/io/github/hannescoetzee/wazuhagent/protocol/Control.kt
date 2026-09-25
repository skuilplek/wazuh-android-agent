package io.github.hannescoetzee.wazuhagent.protocol

/**
 * Values reported in the keepalive's uname line, which the manager uses for the
 * agent's OS columns in the dashboard.
 */
data class AgentIdentity(
    val hostname: String,
    val kernelRelease: String,
    val buildVersion: String,
    val machine: String,
    val osVersion: String,
    val agentVersion: String = DEFAULT_AGENT_VERSION,
    val sysname: String = "Linux",
    val osName: String = "Android",
    val osPlatform: String = "android",
) {
    /** Same layout as `getuname()` in `src/shared/file_op.c`. */
    fun uname(): String =
        "$sysname |${clean(hostname)} |${clean(kernelRelease)} |${clean(buildVersion)} |${clean(machine)} " +
            "[${clean(osName)}|${clean(osPlatform)}: ${clean(osVersion)}] - Wazuh $agentVersion"

    private fun clean(value: String) = value.replace('|', '-').replace('\n', ' ').replace('[', '(').replace(']', ')')

    companion object {
        const val DEFAULT_AGENT_VERSION = "v4.9.2"
    }
}

object Control {
    const val HEADER = "#!-"
    const val STARTUP = "agent startup "
    const val SHUTDOWN = "agent shutdown "
    const val ACK = "agent ack "
    const val FILE_UPDATE = "up file "
    const val FILE_CLOSE = "close file "
    const val FORCE_RECONNECT = "force_reconnect"
    const val ERROR = "err "
    const val REQUEST = "req "
    const val EXECD = "execd "

    /** Queue id for log messages (`LOCALFILE_MQ`). */
    const val LOCALFILE_MQ = '1'

    fun startup(agentVersion: String) = "$HEADER$STARTUP{\"version\":\"$agentVersion\"}"

    fun shutdown() = "$HEADER$SHUTDOWN"

    fun agentStarted(key: AgentKey) =
        "$LOCALFILE_MQ:wazuh-agent:ossec: Agent started: '${key.name}->${key.ip}'."

    fun event(location: String, message: String): String {
        require(location.isNotEmpty() && !location.contains(':')) { "Location must be non-empty and contain no ':'" }
        return "$LOCALFILE_MQ:$location:$message"
    }

    /**
     * Keepalive as built by `run_notify()`: uname, labels, shared file sums and the agent IP label.
     */
    fun keepalive(
        identity: AgentIdentity,
        labels: Map<String, String> = emptyMap(),
        mergedSum: String = "x",
        agentIp: String? = null,
    ): String = buildString {
        append(HEADER).append(identity.uname()).append('\n')
        labels.forEach { (k, v) ->
            append('"').append(k.replace("\"", "")).append("\":").append(v.replace('\n', ' ')).append('\n')
        }
        append(mergedSum).append(" merged.mg\n")
        if (!agentIp.isNullOrEmpty()) append("#\"_agent_ip\":").append(agentIp).append('\n')
    }

    fun requestReply(counter: String, payload: String) = "$HEADER$REQUEST$counter $payload"

    fun isControl(text: String) = text.startsWith(HEADER)
}
