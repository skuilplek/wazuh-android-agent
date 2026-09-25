package io.github.hannescoetzee.wazuhagent.collectors

import android.Manifest
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.PowerManager
import androidx.core.content.ContextCompat
import io.github.hannescoetzee.wazuhagent.admin.AgentDeviceAdminReceiver
import io.github.hannescoetzee.wazuhagent.admin.DeviceOwner
import org.json.JSONObject

/** What the agent can see on this phone. [reason] says what is missing when [available] is false. */
data class Capability(val name: String, val label: String, val available: Boolean, val reason: String)

object Capabilities {
    const val DEVICE_ADMIN = "device_admin"
    const val DEVICE_OWNER = "device_owner"
    const val SECURITY_LOGGING = "security_logging"
    const val NETWORK_LOGGING = "network_logging"
    const val LOCATION = "location"
    const val BATTERY_UNRESTRICTED = "battery_unrestricted"
    const val NOTIFICATIONS = "notifications"

    fun check(context: Context): List<Capability> {
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
        val admin = AgentDeviceAdminReceiver.component(context)
        val owner = DeviceOwner.isDeviceOwner(context)
        return listOf(
            Capability(
                DEVICE_ADMIN, "Device admin (failed unlock reports)",
                AgentDeviceAdminReceiver.isActive(context),
                "Not enabled, so failed unlock attempts are not reported",
            ),
            Capability(
                DEVICE_OWNER, "Device Owner",
                owner,
                "Not provisioned as Device Owner (needs a factory-reset phone), so security and network logs are unavailable",
            ),
            Capability(
                SECURITY_LOGGING, "Security log",
                owner && runCatching { dpm.isSecurityLoggingEnabled(admin) }.getOrDefault(false),
                if (owner) "Security logging is turned off" else "Requires Device Owner",
            ),
            Capability(
                NETWORK_LOGGING, "Network log (DNS and connections)",
                owner && runCatching { dpm.isNetworkLoggingEnabled(admin) }.getOrDefault(false),
                if (owner) "Network logging is turned off" else "Requires Device Owner",
            ),
            Capability(
                LOCATION, "Location (Wi-Fi name in network events)",
                granted(context, Manifest.permission.ACCESS_FINE_LOCATION),
                "Wi-Fi name and BSSID are not reported",
            ),
            Capability(
                BATTERY_UNRESTRICTED, "Run unrestricted in background",
                context.getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(context.packageName),
                "Android may stop the agent in the background",
            ),
            Capability(
                NOTIFICATIONS, "Status notification",
                Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU || granted(context, Manifest.permission.POST_NOTIFICATIONS),
                "The agent status notification is hidden",
            ),
        )
    }

    /** `{"device_admin": {"available": false, "reason": "..."}, ...}`; the reason is empty when available. */
    fun toJson(capabilities: List<Capability>): JSONObject = JSONObject().apply {
        capabilities.forEach { c ->
            put(c.name, JSONObject().put("available", c.available).put("reason", if (c.available) "" else c.reason))
        }
    }

    private fun granted(context: Context, permission: String) =
        ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
}
