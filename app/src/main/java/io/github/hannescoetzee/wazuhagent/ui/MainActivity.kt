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
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.hannescoetzee.wazuhagent.admin.AgentDeviceAdminReceiver
import io.github.hannescoetzee.wazuhagent.collectors.Capabilities
import io.github.hannescoetzee.wazuhagent.collectors.Capability

class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()
    private val capabilities = mutableStateOf(emptyList<Capability>())

    private val requestPermission = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        refreshCapabilities()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val context = LocalContext.current
            val dark = isSystemInDarkTheme()
            val colors = when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
                    if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
                dark -> darkColorScheme()
                else -> lightColorScheme()
            }
            MaterialTheme(colorScheme = colors) {
                Surface(Modifier.fillMaxSize().safeDrawingPadding()) {
                    val ui by viewModel.ui.collectAsStateWithLifecycle()
                    val status by viewModel.status.collectAsStateWithLifecycle()
                    val queueSize by viewModel.queueSize.collectAsStateWithLifecycle()
                    val caps by capabilities
                    SetupScreen(
                        ui = ui,
                        status = status,
                        queueSize = queueSize,
                        capabilities = caps,
                        onFormChange = viewModel::updateForm,
                        onEnroll = viewModel::enroll,
                        onSave = viewModel::saveSettings,
                        onStart = viewModel::startAgent,
                        onStop = viewModel::stopAgent,
                        onForget = viewModel::forgetEnrollment,
                        onRequestNotifications = ::requestNotifications,
                        onRequestBattery = ::requestBatteryExemption,
                        onRequestLocation = {
                            requestPermission.launch(
                                arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION),
                            )
                        },
                        onRequestDeviceAdmin = ::requestDeviceAdmin,
                    )
                }
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
