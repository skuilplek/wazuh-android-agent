package io.github.hannescoetzee.wazuhagent.queue

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicInteger

/**
 * Durable FIFO of events waiting to be sent, so nothing is lost while the phone is offline.
 */
class EventQueue(private val dao: EventDao) {
    private val wakeups = Channel<Unit>(Channel.CONFLATED)

    val size: Flow<Int> = dao.observeCount()

    suspend fun enqueue(event: JSONObject, location: String = LOCATION) {
        dao.insert(QueuedEvent(location = location, message = truncate(event.toString()), createdAt = System.currentTimeMillis()))
        if (insertsSinceTrim.incrementAndGet() % TRIM_EVERY == 0) dao.trimTo(MAX_EVENTS)
        wakeups.trySend(Unit)
    }

    /** For callers that cannot suspend, such as the uncaught-exception handler. */
    fun enqueueBlocking(event: JSONObject, location: String = LOCATION) {
        dao.insertBlocking(QueuedEvent(location = location, message = truncate(event.toString()), createdAt = System.currentTimeMillis()))
        wakeups.trySend(Unit)
    }

    suspend fun oldest(limit: Int): List<QueuedEvent> = dao.oldest(limit)

    suspend fun remove(events: List<QueuedEvent>) {
        if (events.isNotEmpty()) dao.delete(events.map { it.id })
    }

    suspend fun clear() = dao.clear()

    /** Suspends until something is enqueued or [timeoutMs] passes. */
    suspend fun awaitNew(timeoutMs: Long) {
        withTimeoutOrNull(timeoutMs) { wakeups.receive() }
    }

    private val insertsSinceTrim = AtomicInteger()

    private fun truncate(message: String): String {
        if (message.length <= MAX_MESSAGE_CHARS) return message
        val type = runCatching { JSONObject(message).getJSONObject("android").optString("type") }.getOrDefault("")
        return JSONObject().put(
            "android",
            JSONObject().put("type", type).put("truncated", true).put("original_size", message.length),
        ).toString()
    }

    companion object {
        const val LOCATION = "android"
        const val MAX_EVENTS = 20_000
        private const val TRIM_EVERY = 500
        /** Leaves room under the manager's 65k limit for multi-byte characters and the queue header. */
        private const val MAX_MESSAGE_CHARS = 20_000
    }
}
