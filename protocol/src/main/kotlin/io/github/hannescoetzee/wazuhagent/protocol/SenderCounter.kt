package io.github.hannescoetzee.wazuhagent.protocol

data class CounterValue(val global: Long, val local: Int)

/**
 * The manager rejects any message whose counter is not strictly greater than the last one
 * it saw for this agent, so the counter must survive process restarts.
 */
interface CounterStore {
    fun load(): CounterValue?
    fun save(value: CounterValue)
}

class InMemoryCounterStore(private var value: CounterValue? = null) : CounterStore {
    override fun load(): CounterValue? = value
    override fun save(value: CounterValue) {
        this.value = value
    }
}

/**
 * Starting a counter skips to the next global block, so messages stay strictly increasing
 * even if the last saves before a crash never reached disk.
 */
class SenderCounter(private val store: CounterStore) {
    private var global: Long
    private var local: Int

    init {
        val saved = store.load()
        global = if (saved == null) 0 else (saved.global + 1) and 0xFFFF_FFFFL
        local = 0
    }

    /** Same rollover as `CreateSecMSG()`: local wraps after 9997 and bumps global. */
    @Synchronized
    fun next(): CounterValue {
        if (local >= 9997) {
            local = 0
            global = (global + 1) and 0xFFFF_FFFFL
        }
        local++
        val value = CounterValue(global, local)
        store.save(value)
        return value
    }
}
