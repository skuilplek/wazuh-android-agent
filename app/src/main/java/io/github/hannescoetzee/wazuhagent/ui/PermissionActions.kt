package io.github.hannescoetzee.wazuhagent.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.LocationOn
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.ui.graphics.vector.ImageVector
import io.github.hannescoetzee.wazuhagent.collectors.Capabilities
import io.github.hannescoetzee.wazuhagent.collectors.Capability
import io.github.hannescoetzee.wazuhagent.ui.theme.AppIcons

/** System prompts for the capabilities the user can grant from inside the app. */
class PermissionActions(
    val notifications: () -> Unit,
    val battery: () -> Unit,
    val exactAlarm: () -> Unit,
    val location: () -> Unit,
    val usageAccess: () -> Unit,
    val deviceAdmin: () -> Unit,
) {
    fun forCapability(name: String): (() -> Unit)? = when (name) {
        Capabilities.NOTIFICATIONS -> notifications
        Capabilities.BATTERY_UNRESTRICTED -> battery
        Capabilities.EXACT_ALARM -> exactAlarm
        Capabilities.LOCATION -> location
        Capabilities.USAGE_ACCESS -> usageAccess
        Capabilities.DEVICE_ADMIN -> deviceAdmin
        else -> null
    }

    companion object {
        val GRANTABLE = listOf(
            Capabilities.NOTIFICATIONS,
            Capabilities.BATTERY_UNRESTRICTED,
            Capabilities.EXACT_ALARM,
            Capabilities.LOCATION,
            Capabilities.USAGE_ACCESS,
            Capabilities.DEVICE_ADMIN,
        )

        fun icon(name: String): ImageVector = when (name) {
            Capabilities.NOTIFICATIONS -> Icons.Filled.Notifications
            Capabilities.BATTERY_UNRESTRICTED -> AppIcons.Battery
            Capabilities.EXACT_ALARM -> AppIcons.Alarm
            Capabilities.LOCATION -> Icons.Filled.LocationOn
            Capabilities.USAGE_ACCESS -> AppIcons.Memory
            Capabilities.DEVICE_ADMIN -> Icons.Filled.Lock
            Capabilities.NETWORK_LOGGING -> AppIcons.Dns
            else -> AppIcons.Shield
        }
    }
}

/**
 * Grantable capabilities that are missing, in display order. With [suPresent] the process
 * list comes from root, so Usage Access is not nagged for. It stays in Settings, where
 * granting it is the fallback while root is denied.
 */
fun List<Capability>.missingGrantable(suPresent: Boolean): List<Capability> {
    val byName = associateBy { it.name }
    return PermissionActions.GRANTABLE.mapNotNull { byName[it] }.filter { capability ->
        if (suPresent && capability.name == Capabilities.USAGE_ACCESS) false else !capability.available
    }
}
