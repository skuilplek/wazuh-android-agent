package io.github.hannescoetzee.wazuhagent.ui

import android.Manifest
import android.annotation.SuppressLint
import android.app.admin.DevicePolicyManager
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import io.github.hannescoetzee.wazuhagent.admin.AgentDeviceAdminReceiver
import io.github.hannescoetzee.wazuhagent.collectors.Capabilities
import io.github.hannescoetzee.wazuhagent.collectors.Capability
import io.github.hannescoetzee.wazuhagent.ui.theme.WazuhTheme

class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()
    private val capabilities = mutableStateOf(emptyList<Capability>())

    private val requestPermission = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        refreshCapabilities()
    }

    private val permissions = PermissionActions(
        notifications = ::requestNotifications,
        battery = ::requestBatteryExemption,
        location = {
            requestPermission.launch(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION))
        },
        deviceAdmin = ::requestDeviceAdmin,
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            WazuhTheme {
                val caps by capabilities
                AppScaffold(viewModel = viewModel, capabilities = caps, permissions = permissions)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        refreshCapabilities()
    }

    private fun refreshCapabilities() {
        capabilities.value = Capabilities.check(this)
    }

    private fun requestDeviceAdmin() {
        val intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN)
            .putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, AgentDeviceAdminReceiver.component(this))
            .putExtra(
                DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                "Lets the agent report failed screen unlock attempts to your Wazuh manager. It cannot lock, wipe or change the phone.",
            )
        startActivity(intent)
    }

    private fun requestNotifications() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestPermission.launch(arrayOf(Manifest.permission.POST_NOTIFICATIONS))
        }
    }

    // Sideloaded security agent: a persistent connection is the point of the app.
    @SuppressLint("BatteryLife")
    private fun requestBatteryExemption() {
        val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName"))
        runCatching { startActivity(intent) }
            .onFailure { startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) }
    }
}
