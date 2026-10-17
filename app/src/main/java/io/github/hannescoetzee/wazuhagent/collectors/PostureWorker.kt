package io.github.hannescoetzee.wazuhagent.collectors

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import io.github.hannescoetzee.wazuhagent.app
import io.github.hannescoetzee.wazuhagent.service.AgentForegroundService
import java.util.concurrent.TimeUnit
import kotlin.coroutines.cancellation.CancellationException

/** Periodic posture, package and process checks; runs even when Android has paused the service. */
class PostureWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val app = applicationContext.app
        if (app.store.agentKey == null || !app.store.agentEnabled) return Result.success()
        // A worker cannot start a foreground service on Android 12+. The exact alarm can.
        // Skip it while the service is already up; task removal arms its own alarm.
        // A force-stop from system settings still will not come back until the next open or reboot.
        // Without exact alarms this stays quiet: posture already reports the exact_alarm
        // capability, and a warning every run would raise rule 100271 every 15 minutes.
        if (!AgentForegroundService.isRunning && AgentForegroundService.canScheduleRestart(applicationContext)) {
            AgentForegroundService.scheduleRestart(applicationContext)
        }
        return runCatching {
            PostureCollector(applicationContext).collectAndReport(app.queue)
            PackageCollector(applicationContext, app.queue).reconcile()
            ProcessCollector(applicationContext).collectAndReport(app.queue)
            Result.success()
        }.getOrElse { error ->
            if (error is CancellationException) throw error
            AgentLog.error("Periodic collection failed", error)
            Result.retry()
        }
    }

    companion object {
        private const val NAME = "posture-check"

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<PostureWorker>(15, TimeUnit.MINUTES).build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(NAME, ExistingPeriodicWorkPolicy.KEEP, request)
        }

        fun cancel(context: Context) = WorkManager.getInstance(context).cancelUniqueWork(NAME)
    }
}
