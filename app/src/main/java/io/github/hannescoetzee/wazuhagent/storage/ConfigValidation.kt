package io.github.hannescoetzee.wazuhagent.storage

import io.github.hannescoetzee.wazuhagent.protocol.AgentNames

private val GROUP_NAME = Regex("^[A-Za-z0-9._-]{1,255}$")

/**
 * Cleans up manager settings typed in the app or passed in QR provisioning extras. Throws
 * [IllegalArgumentException] with a message for the user on the first invalid value.
 */
fun validatedManagerConfig(
    host: String,
    enrollPort: String,
    port: String,
    password: String,
    agentName: String,
    groups: String,
    keepaliveSeconds: String,
): ManagerConfig {
    val cleanHost = host.trim()
    require(cleanHost.isNotEmpty()) { "Enter the manager address" }
    require(cleanHost.none { it.isWhitespace() }) { "Manager address must not contain spaces" }
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
        host = cleanHost,
        enrollPort = parsePort(enrollPort, "Enroll port"),
        port = parsePort(port, "Agent port"),
        password = password,
        agentName = name,
        groups = groupList.joinToString(","),
        keepaliveSeconds = keepalive,
    )
}

private fun parsePort(value: String, label: String): Int =
    value.trim().toIntOrNull()?.takeIf { it in 1..65535 }
        ?: throw IllegalArgumentException("$label must be a number from 1 to 65535")
