package io.github.hannescoetzee.wazuhagent.collectors

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import io.github.hannescoetzee.wazuhagent.app
import java.util.concurrent.TimeUnit

/** Periodic posture and package checks; runs even when Android has paused the service. */
class PostureWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val app = applicationContext.app
        if (app.store.agentKey == null || !app.store.agentEnabled) return Result.success()
        return runCatching {
            PostureCollector(applicationContext).collectAndReport(app.queue)
            PackageCollector(applicationContext, app.queue).reconcile()
            Result.success()
        }.getOrElse {
            AgentLog.error("Periodic collection failed", it)
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
