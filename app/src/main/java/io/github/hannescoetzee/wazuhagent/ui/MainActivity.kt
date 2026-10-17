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
import io.github.hannescoetzee.wazuhagent.collectors.RootCheck
import io.github.hannescoetzee.wazuhagent.ui.theme.WazuhTheme

class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()
    private val capabilities = mutableStateOf(emptyList<Capability>())
    private val suPresent = mutableStateOf(false)

    private val requestPermission = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        refreshCapabilities()
    }

    private val permissions = PermissionActions(
        notifications = ::requestNotifications,
        battery = ::requestBatteryExemption,
        exactAlarm = ::requestExactAlarm,
        location = {
            requestPermission.launch(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION))
        },
        usageAccess = ::requestUsageAccess,
        deviceAdmin = ::requestDeviceAdmin,
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            WazuhTheme {
                val caps by capabilities
                val su by suPresent
                AppScaffold(viewModel = viewModel, capabilities = caps, suPresent = su, permissions = permissions)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        refreshCapabilities()
    }

    private fun refreshCapabilities() {
        capabilities.value = Capabilities.check(this)
        suPresent.value = RootCheck.suBinary() != null
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
            .onFailure { runCatching { startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) } }
    }

    private fun requestUsageAccess() {
        val direct = Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS, Uri.parse("package:$packageName"))
        runCatching { startActivity(direct) }
            .onFailure { runCatching { startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)) } }
    }

    private fun requestExactAlarm() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return
        val intent = Intent(Settings.ACTION_REQUEST_SCHEDULE_EXACT_ALARM, Uri.parse("package:$packageName"))
        runCatching { startActivity(intent) }
            .onFailure { runCatching { startActivity(Intent(Settings.ACTION_REQUEST_SCHEDULE_EXACT_ALARM)) } }
    }
}
