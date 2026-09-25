package io.github.hannescoetzee.wazuhagent.protocol

/**
 * One `client.keys` entry: `<id> <name> <ip> <key>`.
 */
class AgentKey(
    val id: String,
    val name: String,
    val ip: String,
    val key: String,
) {
    init {
        require(id.isNotEmpty() && id.all { it.isDigit() }) { "Invalid agent id" }
        require(AgentNames.isValid(name)) { "Invalid agent name" }
        require(ip.isNotEmpty()) { "Invalid agent ip" }
        require(key.isNotEmpty() && key.none { it.isWhitespace() }) { "Invalid agent key" }
    }

    /**
     * Mirrors `isSingleHost()` in wazuh: agents registered with a network or `any`
     * must prefix every message with `!<id>!` so the manager can find the key.
     */
    val isDynamicIp: Boolean
        get() {
            if (ip.equals("any", ignoreCase = true)) return true
            val slash = ip.indexOf('/')
            if (slash < 0) return false
            val bits = ip.substring(slash + 1).toIntOrNull() ?: return true
            val isV6 = ip.contains(':')
            return bits < (if (isV6) 128 else 32)
        }

    fun toKeysLine(): String = "$id $name $ip $key"

    override fun toString(): String = "AgentKey(id=$id, name=$name, ip=$ip, key=***)"

    override fun equals(other: Any?): Boolean =
        other is AgentKey && other.id == id && other.name == name && other.ip == ip && other.key == key

    override fun hashCode(): Int = toKeysLine().hashCode()

    companion object {
        fun parse(line: String): AgentKey {
            val parts = line.trim().split(' ', limit = 4)
            require(parts.size == 4) { "Invalid key entry" }
            return AgentKey(parts[0], parts[1], parts[2], parts[3])
        }
    }
}

object AgentNames {
    private val VALID = Regex("^[A-Za-z0-9._-]{2,128}$")

    fun isValid(name: String): Boolean = VALID.matches(name)

    /** Turns arbitrary device names ("Pixel 8 Pro") into a name authd accepts ("Pixel-8-Pro"). */
    fun sanitize(raw: String): String {
        val cleaned = raw.trim()
            .replace(Regex("\\s+"), "-")
            .replace(Regex("[^A-Za-z0-9._-]"), "")
            .take(128)
        return if (cleaned.length >= 2) cleaned else "android-$cleaned".take(128)
    }
}
