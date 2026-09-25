package io.github.hannescoetzee.wazuhagent.collectors

import android.util.Log
import io.github.hannescoetzee.wazuhagent.queue.EventQueue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

/**
 * The app's own lifecycle and error log, forwarded to the manager as `agent_log` events.
 * Identical messages are suppressed for [DEDUPE_WINDOW_MS] so an offline phone does not
 * fill the queue with repeated connection errors.
 */
object AgentLog {
    private const val TAG = "WazuhAgent"
    private const val DEDUPE_WINDOW_MS = 10 * 60 * 1000L

    private var queue: EventQueue? = null
    private var scope: CoroutineScope? = null
    private val lastSeen = ConcurrentHashMap<String, Long>()

    fun init(queue: EventQueue, scope: CoroutineScope) {
        this.queue = queue
        this.scope = scope
    }

    fun info(message: String) = log("info", message, null)

    fun warn(message: String) = log("warning", message, null)

    fun error(message: String, error: Throwable? = null) = log("error", message, error)

    /** Called from the uncaught-exception handler, where the process is about to die. */
    fun crash(thread: String, error: Throwable) {
        Log.e(TAG, "Crash in $thread", error)
        queue?.enqueueBlocking(event("crash", "Uncaught exception in thread $thread", error))
    }

    private fun log(level: String, message: String, error: Throwable?) {
        when (level) {
            "error" -> Log.e(TAG, message, error)
            "warning" -> Log.w(TAG, message, error)
            else -> Log.i(TAG, message)
        }
        val now = System.currentTimeMillis()
        val previous = lastSeen.put("$level:$message", now)
        if (previous != null && now - previous < DEDUPE_WINDOW_MS) return
        val q = queue ?: return
        scope?.launch { runCatching { q.enqueue(event(level, message, error)) } }
    }

    private fun event(level: String, message: String, error: Throwable?) = Events.build("agent_log") {
        put("level", level)
        put("message", message)
        if (error != null) {
            put("exception", error.javaClass.name)
            put("exception_message", error.message ?: "")
            put("stacktrace", error.stackTraceToString().take(4000))
        }
    }
}
