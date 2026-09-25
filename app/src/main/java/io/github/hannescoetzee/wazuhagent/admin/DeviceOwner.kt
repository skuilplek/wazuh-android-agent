package io.github.hannescoetzee.wazuhagent.admin

import android.app.admin.DevicePolicyManager
import android.content.Context
import io.github.hannescoetzee.wazuhagent.collectors.AgentLog

/** Device Owner is only possible on a factory-reset phone; everything here is a no-op otherwise. */
object DeviceOwner {
    fun isDeviceOwner(context: Context): Boolean =
        context.getSystemService(DevicePolicyManager::class.java).isDeviceOwnerApp(context.packageName)

    /** Turns on the security and network logs. No other policy is set. */
    fun enableLogging(context: Context) {
        if (!isDeviceOwner(context)) return
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
        val admin = AgentDeviceAdminReceiver.component(context)
        runCatching {
            if (!dpm.isSecurityLoggingEnabled(admin)) dpm.setSecurityLoggingEnabled(admin, true)
            if (!dpm.isNetworkLoggingEnabled(admin)) dpm.setNetworkLoggingEnabled(admin, true)
        }.onFailure { AgentLog.error("Could not enable Device Owner logging", it) }
    }
}
