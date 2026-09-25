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
    val location: () -> Unit,
    val deviceAdmin: () -> Unit,
) {
    fun forCapability(name: String): (() -> Unit)? = when (name) {
        Capabilities.NOTIFICATIONS -> notifications
        Capabilities.BATTERY_UNRESTRICTED -> battery
        Capabilities.LOCATION -> location
        Capabilities.DEVICE_ADMIN -> deviceAdmin
        else -> null
    }

    companion object {
        val GRANTABLE = listOf(
            Capabilities.NOTIFICATIONS,
            Capabilities.BATTERY_UNRESTRICTED,
            Capabilities.LOCATION,
            Capabilities.DEVICE_ADMIN,
        )

        fun icon(name: String): ImageVector = when (name) {
            Capabilities.NOTIFICATIONS -> Icons.Filled.Notifications
            Capabilities.BATTERY_UNRESTRICTED -> AppIcons.Battery
            Capabilities.LOCATION -> Icons.Filled.LocationOn
            Capabilities.DEVICE_ADMIN -> Icons.Filled.Lock
            Capabilities.NETWORK_LOGGING -> AppIcons.Dns
            else -> AppIcons.Shield
        }
    }
}

/** Grantable capabilities that are missing, in display order. */
fun List<Capability>.missingGrantable(): List<Capability> {
    val byName = associateBy { it.name }
    return PermissionActions.GRANTABLE.mapNotNull { byName[it] }.filter { !it.available }
}
