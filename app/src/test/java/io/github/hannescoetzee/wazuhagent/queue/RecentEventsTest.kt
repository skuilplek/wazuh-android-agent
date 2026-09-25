package io.github.hannescoetzee.wazuhagent.queue

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class RecentEventsTest {
    private fun event(id: Long) = RecentEvent(id, "posture", id, "{}")

    @Before
    fun reset() = RecentEvents.clear()

    @Test
    fun keepsNewestFirstAndDropsOldestPastCapacity() {
        (1L..RecentEvents.CAPACITY + 10L).forEach { RecentEvents.record(event(it)) }
        val ids = RecentEvents.events.value.map { it.id }
        assertEquals(RecentEvents.CAPACITY, ids.size)
        assertEquals(RecentEvents.CAPACITY + 10L, ids.first())
        assertEquals(11L, ids.last())
    }

    @Test
    fun markSentFlipsOnlyMatchingIds() {
        (1L..3L).forEach { RecentEvents.record(event(it)) }
        RecentEvents.markSent(listOf(1L, 3L, 99L))
        val sent = RecentEvents.events.value.associate { it.id to it.sent }
        assertEquals(mapOf(3L to true, 2L to false, 1L to true), sent)
    }

    @Test
    fun clearEmptiesTheBuffer() {
        RecentEvents.record(event(1))
        RecentEvents.clear()
        assertTrue(RecentEvents.events.value.isEmpty())
    }
}
