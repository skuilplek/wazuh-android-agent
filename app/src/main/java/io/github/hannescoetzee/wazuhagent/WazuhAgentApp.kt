package io.github.hannescoetzee.wazuhagent

import android.app.Application
import android.content.Context
import io.github.hannescoetzee.wazuhagent.collectors.AgentLog
import io.github.hannescoetzee.wazuhagent.queue.EventDatabase
import io.github.hannescoetzee.wazuhagent.queue.EventQueue
import io.github.hannescoetzee.wazuhagent.service.Notifications
import io.github.hannescoetzee.wazuhagent.storage.SecureStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob

class WazuhAgentApp : Application() {
    val store: SecureStore by lazy { SecureStore(this) }
    val queue: EventQueue by lazy { EventQueue(EventDatabase.create(this).events()) }
    val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onCreate() {
        super.onCreate()
        Notifications.createChannels(this)
        AgentLog.init(queue, appScope)
        installCrashReporter()
    }

    private fun installCrashReporter() {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            runCatching { AgentLog.crash(thread.name, error) }
            previous?.uncaughtException(thread, error)
        }
    }
}

val Context.app: WazuhAgentApp
    get() = applicationContext as WazuhAgentApp
