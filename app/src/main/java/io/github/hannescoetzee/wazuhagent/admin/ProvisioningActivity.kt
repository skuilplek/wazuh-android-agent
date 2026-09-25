package io.github.hannescoetzee.wazuhagent.admin

import android.app.Activity
import android.app.admin.DevicePolicyManager
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import androidx.core.content.IntentCompat
import io.github.hannescoetzee.wazuhagent.app
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Setup wizard steps that Android 10+ asks a Device Owner app to handle during QR
 * provisioning: pick fully managed mode, then finish setup. No UI is shown.
 */
class ProvisioningActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            setResult(RESULT_CANCELED)
            finish()
            return
        }
        when (intent.action) {
            DevicePolicyManager.ACTION_GET_PROVISIONING_MODE -> setResult(
                RESULT_OK,
                Intent().putExtra(DevicePolicyManager.EXTRA_PROVISIONING_MODE, DevicePolicyManager.PROVISIONING_MODE_FULLY_MANAGED_DEVICE),
            )
            DevicePolicyManager.ACTION_ADMIN_POLICY_COMPLIANCE -> {
                DeviceOwner.enableLogging(this)
                val extras = IntentCompat.getParcelableExtra(
                    intent, DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE, PersistableBundle::class.java,
                )
                val context = applicationContext
                app.appScope.launch(Dispatchers.IO) { Provisioning.apply(context, extras) }
                setResult(RESULT_OK)
            }
            else -> setResult(RESULT_CANCELED)
        }
        finish()
    }
}
