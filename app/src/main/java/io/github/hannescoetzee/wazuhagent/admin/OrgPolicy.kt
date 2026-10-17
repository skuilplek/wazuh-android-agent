package io.github.hannescoetzee.wazuhagent.admin

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Build
import android.os.UserManager
import io.github.hannescoetzee.wazuhagent.collectors.AgentLog

/**
 * Optional Device Owner restrictions. Off unless a QR extra or the Settings switch turns
 * them on. Logging stays available either way.
 */
object OrgPolicy {
    private const val PREFS = "org_policy"
    private const val KEY_ENABLED = "enabled"

    fun isEnabled(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY_ENABLED, false)

    fun setEnabled(context: Context, enabled: Boolean) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (!DeviceOwner.isDeviceOwner(context)) {
            if (enabled) throw IllegalStateException("Organization policy needs Device Owner")
            prefs.edit().putBoolean(KEY_ENABLED, false).commit()
            return
        }
        apply(context, enabled)
        prefs.edit().putBoolean(KEY_ENABLED, enabled).commit()
    }

    /** Re-applies a saved choice after reboot. A phone without the choice is left alone. */
    fun applyIfEnabled(context: Context) {
        if (!isEnabled(context) || !DeviceOwner.isDeviceOwner(context)) return
        runCatching { apply(context, true) }
            .onFailure { AgentLog.error("Could not apply organization policy", it) }
    }

    private fun apply(context: Context, enabled: Boolean) {
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
        val admin = AgentDeviceAdminReceiver.component(context)
        if (enabled) {
            dpm.addUserRestriction(admin, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES)
            dpm.setSystemUpdatePolicy(admin, android.app.admin.SystemUpdatePolicy.createAutomaticInstallPolicy())
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                dpm.setRequiredPasswordComplexity(DevicePolicyManager.PASSWORD_COMPLEXITY_MEDIUM)
            }
        } else {
            dpm.clearUserRestriction(admin, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES)
            dpm.setSystemUpdatePolicy(admin, null)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                dpm.setRequiredPasswordComplexity(DevicePolicyManager.PASSWORD_COMPLEXITY_NONE)
            }
        }
    }
}
