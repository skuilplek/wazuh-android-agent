package io.github.hannescoetzee.wazuhagent.collectors

import android.content.Context
import android.database.ContentObserver
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import io.github.hannescoetzee.wazuhagent.admin.DeviceCommands
import io.github.hannescoetzee.wazuhagent.admin.DeviceOwner
import io.github.hannescoetzee.wazuhagent.admin.OrgPolicy
import io.github.hannescoetzee.wazuhagent.queue.EventQueue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.coroutines.cancellation.CancellationException

/** Starts and stops all collectors together with the agent service. */
class CollectorManager(
    private val context: Context,
    private val queue: EventQueue,
    onNetworkAvailable: () -> Unit,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val packages = PackageCollector(context, queue)
    private val network = NetworkCollector(context, queue, onNetworkAvailable)
    private val posture = PostureCollector(context)
    private var postureJob: Job? = null

    /** Reports debugging and accessibility changes right away instead of on the next periodic run. */
    private val settingsObserver = object : ContentObserver(Handler(Looper.getMainLooper())) {
        override fun onChange(selfChange: Boolean, uri: Uri?) = schedulePosture()
    }

    fun start() {
        packages.register(scope)
        network.register(scope)
        WATCHED_SETTINGS.forEach { uri ->
            runCatching { context.contentResolver.registerContentObserver(uri, false, settingsObserver) }
        }
        PostureWorker.schedule(context)
        DeviceOwner.enableLogging(context)
        DeviceCommands.restoreInterruptedLocate(context)
        OrgPolicy.applyIfEnabled(context)
        scope.launch {
            runCatching { posture.collectAndReport(queue) }.logUnlessCancelled("Posture collection failed")
            runCatching { packages.reconcile() }.logUnlessCancelled("Package reconcile failed")
            runCatching { ProcessCollector(context).collectAndReport(queue) }.logUnlessCancelled("Process collection failed")
            runCatching { SecurityLogCollector(context).collectPreReboot(queue) }
                .logUnlessCancelled("Pre-reboot security log collection failed")
        }
    }

    fun stop() {
        packages.unregister()
        network.unregister()
        context.contentResolver.unregisterContentObserver(settingsObserver)
        scope.cancel()
    }

    private fun schedulePosture() {
        postureJob?.cancel()
        postureJob = scope.launch {
            delay(SETTINGS_SETTLE_MS)
            runCatching { posture.collectAndReport(queue) }.logUnlessCancelled("Posture collection failed")
        }
    }

    private fun <T> Result<T>.logUnlessCancelled(message: String) {
        val error = exceptionOrNull() ?: return
        if (error is CancellationException) throw error
        AgentLog.error(message, error)
    }

    companion object {
        private const val SETTINGS_SETTLE_MS = 2_000L

        private val WATCHED_SETTINGS = listOf(
            Settings.Global.getUriFor(Settings.Global.ADB_ENABLED),
            Settings.Global.getUriFor(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED),
            Settings.Global.getUriFor("adb_wifi_enabled"),
            Settings.Secure.getUriFor(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES),
            Settings.Secure.getUriFor("enabled_notification_listeners"),
        )

        /** A new agent id on the manager should get a fresh inventory and first posture report. */
        fun resetState(context: Context) {
            listOf("posture_state", "package_state", "network_state", "process_state").forEach {
                context.getSharedPreferences(it, Context.MODE_PRIVATE).edit().clear().commit()
            }
        }
    }
}
