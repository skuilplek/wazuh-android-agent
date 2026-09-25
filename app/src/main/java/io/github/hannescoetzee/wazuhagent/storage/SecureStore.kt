@file:Suppress("DEPRECATION") // androidx.security-crypto is deprecated but still the simplest Keystore-backed prefs.

package io.github.hannescoetzee.wazuhagent.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import io.github.hannescoetzee.wazuhagent.protocol.AgentKey
import io.github.hannescoetzee.wazuhagent.protocol.CounterStore
import io.github.hannescoetzee.wazuhagent.protocol.CounterValue

data class ManagerConfig(
    val host: String,
    val enrollPort: Int = 1515,
    val port: Int = 1514,
    val password: String = "",
    val agentName: String,
    val groups: String = "",
    val keepaliveSeconds: Int = 60,
)

/**
 * Agent key, manager settings and message counters, encrypted with a key held in the
 * Android Keystore.
 */
class SecureStore(context: Context) {
    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        context,
        "wazuh_agent_secure",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    var config: ManagerConfig?
        get() {
            val host = prefs.getString(K_HOST, null) ?: return null
            return ManagerConfig(
                host = host,
                enrollPort = prefs.getInt(K_ENROLL_PORT, 1515),
                port = prefs.getInt(K_PORT, 1514),
                password = prefs.getString(K_PASSWORD, "").orEmpty(),
                agentName = prefs.getString(K_NAME, "").orEmpty(),
                groups = prefs.getString(K_GROUPS, "").orEmpty(),
                keepaliveSeconds = prefs.getInt(K_KEEPALIVE, 60),
            )
        }
        set(value) = prefs.edit {
            if (value == null) {
                listOf(K_HOST, K_ENROLL_PORT, K_PORT, K_PASSWORD, K_NAME, K_GROUPS, K_KEEPALIVE)
                    .forEach { remove(it) }
            } else {
                putString(K_HOST, value.host)
                putInt(K_ENROLL_PORT, value.enrollPort)
                putInt(K_PORT, value.port)
                putString(K_PASSWORD, value.password)
                putString(K_NAME, value.agentName)
                putString(K_GROUPS, value.groups)
                putInt(K_KEEPALIVE, value.keepaliveSeconds)
            }
        }

    var agentKey: AgentKey?
        get() = prefs.getString(K_AGENT_KEY, null)?.let { runCatching { AgentKey.parse(it) }.getOrNull() }
        set(value) = prefs.edit { if (value == null) remove(K_AGENT_KEY) else putString(K_AGENT_KEY, value.toKeysLine()) }

    /** Version accepted by the manager at enrollment; reused for the startup handshake. */
    var agentVersion: String?
        get() = prefs.getString(K_AGENT_VERSION, null)
        set(value) = prefs.edit { putString(K_AGENT_VERSION, value) }

    /** SHA-256 of the authd certificate seen at first enrollment. */
    var pinnedCertSha256: String?
        get() = prefs.getString(K_CERT_PIN, null)
        set(value) = prefs.edit { putString(K_CERT_PIN, value) }

    var mergedSum: String
        get() = prefs.getString(K_MERGED_SUM, "x") ?: "x"
        set(value) = prefs.edit { putString(K_MERGED_SUM, value) }

    /** Whether the user wants the agent running; checked after reboot. */
    var agentEnabled: Boolean
        get() = prefs.getBoolean(K_ENABLED, false)
        set(value) = prefs.edit { putBoolean(K_ENABLED, value) }

    val counterStore: CounterStore = object : CounterStore {
        override fun load(): CounterValue? {
            if (!prefs.contains(K_COUNTER_GLOBAL)) return null
            return CounterValue(prefs.getLong(K_COUNTER_GLOBAL, 0), prefs.getInt(K_COUNTER_LOCAL, 0))
        }

        override fun save(value: CounterValue) = prefs.edit {
            putLong(K_COUNTER_GLOBAL, value.global)
            putInt(K_COUNTER_LOCAL, value.local)
        }
    }

    /** A new key means the manager starts counting from zero again. */
    fun saveEnrollment(key: AgentKey, agentVersion: String?, certSha256: String) = prefs.edit(commit = true) {
        putString(K_AGENT_KEY, key.toKeysLine())
        putString(K_AGENT_VERSION, agentVersion)
        if (certSha256.isNotEmpty()) putString(K_CERT_PIN, certSha256)
        putString(K_MERGED_SUM, "x")
        remove(K_COUNTER_GLOBAL)
        remove(K_COUNTER_LOCAL)
    }

    fun clearEnrollment() = prefs.edit(commit = true) {
        listOf(K_AGENT_KEY, K_AGENT_VERSION, K_CERT_PIN, K_MERGED_SUM, K_COUNTER_GLOBAL, K_COUNTER_LOCAL, K_ENABLED)
            .forEach { remove(it) }
    }

    private companion object {
        const val K_HOST = "host"
        const val K_ENROLL_PORT = "enroll_port"
        const val K_PORT = "port"
        const val K_PASSWORD = "password"
        const val K_NAME = "agent_name"
        const val K_GROUPS = "groups"
        const val K_KEEPALIVE = "keepalive_seconds"
        const val K_AGENT_KEY = "agent_key"
        const val K_AGENT_VERSION = "agent_version"
        const val K_CERT_PIN = "cert_sha256"
        const val K_MERGED_SUM = "merged_sum"
        const val K_ENABLED = "agent_enabled"
        const val K_COUNTER_GLOBAL = "counter_global"
        const val K_COUNTER_LOCAL = "counter_local"
    }
}
