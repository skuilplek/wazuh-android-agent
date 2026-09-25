package io.github.hannescoetzee.wazuhagent.queue

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

data class RecentEvent(
    val id: Long,
    val type: String,
    val createdAt: Long,
    val message: String,
    val sent: Boolean = false,
)

/**
 * The last [CAPACITY] events enqueued in this process, newest first, for the in-app
 * events screen. Sent events stay here after the queue deletes them.
 */
object RecentEvents {
    const val CAPACITY = 500

    private val _events = MutableStateFlow(emptyList<RecentEvent>())
    val events: StateFlow<List<RecentEvent>> = _events

    fun record(event: RecentEvent) = _events.update { (listOf(event) + it).take(CAPACITY) }

    fun markSent(ids: Collection<Long>) {
        if (ids.isEmpty()) return
        val sent = ids.toHashSet()
        _events.update { list -> list.map { if (!it.sent && it.id in sent) it.copy(sent = true) else it } }
    }

    fun clear() = _events.update { emptyList() }
}
