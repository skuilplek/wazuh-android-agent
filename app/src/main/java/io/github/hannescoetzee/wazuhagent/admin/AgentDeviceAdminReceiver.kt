package io.github.hannescoetzee.wazuhagent.admin

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.PersistableBundle
import android.os.UserHandle
import androidx.core.content.IntentCompat
import androidx.core.content.edit
import io.github.hannescoetzee.wazuhagent.app
import io.github.hannescoetzee.wazuhagent.collectors.AgentLog
import io.github.hannescoetzee.wazuhagent.collectors.Events
import io.github.hannescoetzee.wazuhagent.collectors.NetworkLogCollector
import io.github.hannescoetzee.wazuhagent.collectors.SecurityLogCollector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * Device admin with only the watch-login policy, for failed-unlock reports. When the app is
 * also Device Owner, the same receiver gets the security and network log callbacks.
 */
class AgentDeviceAdminReceiver : DeviceAdminReceiver() {

    override fun onEnabled(context: Context, intent: Intent) {
        DeviceOwner.enableLogging(context)
        enqueue(context, "agent_admin") {
            put("action", "enabled")
            put("device_owner", DeviceOwner.isDeviceOwner(context))
        }
    }

    /** Older releases deliver the QR admin extras only here; newer ones also send them to [ProvisioningActivity]. */
    override fun onProfileProvisioningComplete(context: Context, intent: Intent) {
        DeviceOwner.enableLogging(context)
        val extras = IntentCompat.getParcelableExtra(
            intent, DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE, PersistableBundle::class.java,
        )
        val pending = goAsync()
        context.app.appScope.launch(Dispatchers.IO) {
            try {
                Provisioning.apply(context, extras)
            } finally {
                pending.finish()
            }
        }
    }

    override fun onSecurityLogsAvailable(context: Context, intent: Intent) {
        runAsync(context) { SecurityLogCollector(context).collect(context.app.queue) }
    }

    override fun onNetworkLogsAvailable(context: Context, intent: Intent, batchToken: Long, networkLogsCount: Int) {
        runAsync(context) { NetworkLogCollector(context).collect(context.app.queue, batchToken) }
    }

    override fun onDisableRequested(context: Context, intent: Intent): CharSequence =
        "Failed unlock attempts will no longer be reported, and the manager will be told that the agent's device admin was turned off."

    override fun onDisabled(context: Context, intent: Intent) {
        enqueue(context, "agent_admin") { put("action", "disabled") }
    }

    override fun onPasswordFailed(context: Context, intent: Intent, user: UserHandle) {
        val attempts = runCatching {
            context.getSystemService(DevicePolicyManager::class.java).currentFailedPasswordAttempts
        }.getOrDefault(-1)
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val sinceSuccess = prefs.getInt(KEY_FAILURES, 0) + 1
        prefs.edit { putInt(KEY_FAILURES, sinceSuccess) }
        enqueue(context, "unlock") {
            put("result", "failed")
            put("failed_attempts", if (attempts >= 0) attempts else sinceSuccess)
        }
    }

    override fun onPasswordSucceeded(context: Context, intent: Intent, user: UserHandle) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val failures = prefs.getInt(KEY_FAILURES, 0)
        if (failures == 0) return
        prefs.edit { putInt(KEY_FAILURES, 0) }
        enqueue(context, "unlock") {
            put("result", "success")
            put("failures_before", failures)
        }
    }

    private fun enqueue(context: Context, type: String, fill: JSONObject.() -> Unit) {
        val event = Events.build(type, fill)
        runAsync(context) { context.app.queue.enqueue(event) }
    }

    /** Only runs once the phone is enrolled; otherwise there is nobody to send events to. */
    private fun runAsync(context: Context, block: suspend () -> Unit) {
        val app = context.app
        if (app.store.agentKey == null) return
        val pending = goAsync()
        app.appScope.launch(Dispatchers.IO) {
            try {
                block()
            } catch (e: Exception) {
                AgentLog.error("Device admin event handling failed", e)
            } finally {
                pending.finish()
            }
        }
    }

    companion object {
        private const val PREFS = "unlock_state"
        private const val KEY_FAILURES = "failures_since_success"

        fun component(context: Context) = ComponentName(context, AgentDeviceAdminReceiver::class.java)

        fun isActive(context: Context): Boolean =
            context.getSystemService(DevicePolicyManager::class.java).isAdminActive(component(context))
    }
}
