package io.github.hannescoetzee.wazuhagent.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import io.github.hannescoetzee.wazuhagent.app

/** Restarts the agent after a reboot or app update if the user left it running. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED -> {
                val store = runCatching { context.app.store }.getOrNull() ?: return
                if (store.agentEnabled && store.agentKey != null) AgentForegroundService.start(context)
            }
        }
    }
}
