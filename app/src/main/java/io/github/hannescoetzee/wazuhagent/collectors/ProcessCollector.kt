package io.github.hannescoetzee.wazuhagent.collectors

import android.app.ActivityManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.util.Log
import androidx.core.content.edit
import io.github.hannescoetzee.wazuhagent.queue.EventQueue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlin.coroutines.cancellation.CancellationException

/**
 * RAM, swap and a process list, sent as one `process_snapshot` about every 15 minutes.
 * Rooted phones get the top processes by RSS from `su ps`. Otherwise, with Usage Access,
 * the event lists recent foreground apps and foreground services. Per-app RAM is not
 * available without root.
 */
class ProcessCollector(private val context: Context) {
    private val prefs = context.getSharedPreferences("process_state", Context.MODE_PRIVATE)

    suspend fun collectAndReport(queue: EventQueue) = lock.withLock {
        val event = withContext(Dispatchers.IO) { snapshot() }
        queue.enqueue(event)
    }

    private suspend fun snapshot(): JSONObject {
        val memory = memory()
        val now = System.currentTimeMillis()
        val rooted = tryRoot()
        val usage = if (rooted == null && Capabilities.usageAccessGranted(context)) readUsage(now) else null
        val source = when {
            rooted != null -> "root"
            usage != null -> "usage_stats"
            else -> "memory_only"
        }
        val top = rooted?.let { topByRss(it).map { (name, rssKb) -> formatRss(name, rssKb) } }.orEmpty()
        return Events.build("process_snapshot") {
            put("source", source)
            put("mem_total_mb", memory.totalMb)
            put("mem_available_mb", memory.availableMb)
            put("mem_used_percent", memory.usedPercent)
            put("low_memory", memory.lowMemory)
            put("low_memory_threshold_mb", memory.thresholdMb)
            put("swap_total_mb", memory.swapTotalMb ?: JSONObject.NULL)
            put("swap_free_mb", memory.swapFreeMb ?: JSONObject.NULL)
            put("agent_pss_mb", memory.agentPssMb)
            put("process_count", rooted?.processCount ?: 0)
            put("top_processes", Events.array(top))
            put("window_minutes", WINDOW_MINUTES)
            put("foreground_app", usage?.foregroundApp.orEmpty())
            put("recent_apps", Events.array(usage?.recentApps.orEmpty()))
            put("foreground_services", Events.array(usage?.services.orEmpty()))
        }
    }

    private fun memory(): Memory {
        val am = context.getSystemService(ActivityManager::class.java)
        val info = ActivityManager.MemoryInfo()
        am.getMemoryInfo(info)
        val usedBytes = (info.totalMem - info.availMem).coerceAtLeast(0)
        val usedPercent = if (info.totalMem <= 0) 0 else ((usedBytes * 100) / info.totalMem).toInt().coerceIn(0, 100)
        val (swapTotal, swapFree) = runCatching { parseSwapMb(File("/proc/meminfo").readText()) }.getOrDefault(null to null)
        val pssKb = am.getProcessMemoryInfo(intArrayOf(android.os.Process.myPid())).firstOrNull()?.totalPss ?: 0
        return Memory(
            totalMb = bytesToMb(info.totalMem),
            availableMb = bytesToMb(info.availMem),
            usedPercent = usedPercent,
            lowMemory = info.lowMemory,
            thresholdMb = bytesToMb(info.threshold),
            swapTotalMb = swapTotal,
            swapFreeMb = swapFree,
            agentPssMb = (pssKb / 1024).coerceAtLeast(0),
        )
    }

    /**
     * Runs `ps` only when a root indicator and an `su` binary are present, and not during
     * the backoff after a failure. See [rootBackoffMs] for how long each failure waits.
     */
    private suspend fun tryRoot(): PsSnapshot? {
        if (RootCheck.indicators(context).isEmpty() || rootBackoffActive()) return null
        val su = RootCheck.suBinary() ?: return null
        val result = runProcess(listOf(su, "-c", "ps -A -o RSS,NAME"), SU_TIMEOUT_MS)
        val parsed = result.output?.let { parsePs(it) }?.takeIf { it.processCount > 0 }
        if (parsed != null) {
            clearRootFailure()
            return parsed
        }
        if (currentCoroutineContext().isActive) recordRootFailure(rootBackoffMs(result.exitCode, result.elapsedMs))
        return null
    }

    private fun rootBackoffActive(): Boolean {
        val failedAt = prefs.getLong(KEY_ROOT_FAILED_AT, 0L)
        if (failedAt == 0L) return false
        val backoff = prefs.getLong(KEY_ROOT_BACKOFF_MS, ROOT_DENIAL_BACKOFF_MS)
        return System.currentTimeMillis() - failedAt < backoff
    }

    private fun recordRootFailure(backoffMs: Long) {
        prefs.edit {
            putLong(KEY_ROOT_FAILED_AT, System.currentTimeMillis())
            putLong(KEY_ROOT_BACKOFF_MS, backoffMs)
        }
    }

    private fun clearRootFailure() {
        prefs.edit {
            remove(KEY_ROOT_FAILED_AT)
            remove(KEY_ROOT_BACKOFF_MS)
        }
    }

    /**
     * Events are read further back than the reported window so an app or foreground service
     * that was already running at the start of the window is still counted. A foreground
     * service that keeps running is only logged again about once a day, so the lookback
     * covers that. Only time inside the window is reported.
     */
    private fun readUsage(now: Long): UsageSnapshot? = try {
        val windowStart = now - WINDOW_MS
        val read = readUsageEvents(now - USAGE_LOOKBACK_MS, now)
        val summary = aggregateUsage(read.activity, windowStart, now, read.resets)
        val services = foregroundServicePackages(read.services, windowStart, now, read.resets)
        UsageSnapshot(summary.foregroundApp, summary.recentApps, services)
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        Log.w(TAG, "Usage stats collection failed", e)
        null
    }

    private fun readUsageEvents(start: Long, end: Long): UsageRead {
        val empty = UsageRead(emptyList(), emptyList(), emptyList())
        val usm = context.getSystemService(UsageStatsManager::class.java) ?: return empty
        val raw = usm.queryEvents(start, end) ?: return empty
        val event = UsageEvents.Event()
        val activity = ArrayList<UsageEvent>()
        val services = ArrayList<ServiceEvent>()
        val resets = ArrayList<Long>()
        while (raw.hasNextEvent()) {
            raw.getNextEvent(event)
            val time = event.timeStamp
            if (isDeviceReset(event.eventType)) {
                resets += time
                continue
            }
            val pkg = event.packageName ?: continue
            activityForeground(event.eventType)?.let { activity += UsageEvent(pkg, it, time) }
            serviceForeground(event.eventType)?.let { services += ServiceEvent(pkg, event.className.orEmpty(), it, time) }
        }
        return UsageRead(activity, services, resets)
    }

    private data class Memory(
        val totalMb: Int,
        val availableMb: Int,
        val usedPercent: Int,
        val lowMemory: Boolean,
        val thresholdMb: Int,
        val swapTotalMb: Int?,
        val swapFreeMb: Int?,
        val agentPssMb: Int,
    )

    private data class UsageSnapshot(
        val foregroundApp: String,
        val recentApps: List<String>,
        val services: List<String>,
    )

    private data class UsageRead(val activity: List<UsageEvent>, val services: List<ServiceEvent>, val resets: List<Long>)

    private companion object {
        const val TAG = "WazuhAgent"
        const val KEY_ROOT_FAILED_AT = "root_failed_at"
        const val KEY_ROOT_BACKOFF_MS = "root_backoff_ms"
        const val WINDOW_MINUTES = 15
        const val WINDOW_MS = WINDOW_MINUTES * 60 * 1000L
        /** Covers the daily foreground-service continuation event as well as recent app switches. */
        const val USAGE_LOOKBACK_MS = 26 * 60 * 60 * 1000L
        /** Magisk's grant dialog counts down from 10 seconds. Leave room to answer it. */
        const val SU_TIMEOUT_MS = 20_000L

        val lock = Mutex()
    }
}

internal const val PROCESS_LIST_LIMIT = 25

internal const val ROOT_DENIAL_BACKOFF_MS = 24 * 60 * 60 * 1000L

internal const val ROOT_RETRY_BACKOFF_MS = 60 * 60 * 1000L

/** Faster than a person can answer a prompt, so the root manager answered from a saved rule. */
internal const val QUICK_DENIAL_MS = 2_000L

/**
 * A quick non-zero exit is a saved denial: retrying shows no prompt, so a day is enough.
 * A slow one means a prompt was shown and then denied or left to expire, which cannot be
 * told apart, so it is tried again after an hour. If the user saved a denial, the next try
 * exits quickly and falls into the day-long wait. A timeout is also retried after an hour.
 */
internal fun rootBackoffMs(exitCode: Int?, elapsedMs: Long): Long =
    if (exitCode != null && exitCode != 0 && elapsedMs < QUICK_DENIAL_MS) ROOT_DENIAL_BACKOFF_MS else ROOT_RETRY_BACKOFF_MS

internal data class PsSnapshot(val processCount: Int, val rssKbByName: Map<String, Long>)

internal data class UsageEvent(val packageName: String, val resumed: Boolean, val timeMillis: Long)

/** [serviceName] tells apart several foreground services of one package. */
internal data class ServiceEvent(val packageName: String, val serviceName: String, val running: Boolean, val timeMillis: Long)

internal data class UsageSummary(val foregroundApp: String, val recentApps: List<String>)

/** Sums RSS kilobytes by process name. The header and malformed lines are ignored. */
internal fun parsePs(output: String): PsSnapshot {
    val totals = HashMap<String, Long>()
    var count = 0
    for (line in output.lineSequence()) {
        val trimmed = line.trim()
        if (trimmed.isEmpty()) continue
        val parts = trimmed.split(Regex("\\s+"), limit = 2)
        if (parts.size != 2) continue
        val rss = parts[0].toLongOrNull() ?: continue
        if (rss < 0) continue
        val name = parts[1].trim()
        if (name.isEmpty()) continue
        totals[name] = (totals[name] ?: 0L) + rss
        count++
    }
    return PsSnapshot(count, totals)
}

internal fun topByRss(snapshot: PsSnapshot, limit: Int = PROCESS_LIST_LIMIT): List<Pair<String, Long>> =
    snapshot.rssKbByName.entries
        .sortedWith(compareByDescending<Map.Entry<String, Long>> { it.value }.thenBy { it.key })
        .take(limit)
        .map { it.key to it.value }

internal fun formatRss(name: String, rssKb: Long): String {
    val mb = rssKb / 1024
    return if (mb >= 1) "$name ${mb}MB" else "$name ${rssKb}KB"
}

/**
 * Foreground time per package inside [windowStart, windowEnd]. A resume before the window
 * still counts from the window start. A pause with no earlier resume is ignored. The
 * foreground app is the resume that is still open and started latest. At each of
 * [resets] (device shutdown or startup) every open resume is dropped uncounted, because
 * Android never logs when it actually ended.
 */
internal fun aggregateUsage(
    events: List<UsageEvent>,
    windowStart: Long,
    windowEnd: Long,
    resets: List<Long> = emptyList(),
): UsageSummary {
    val open = HashMap<String, Long>()
    val durations = HashMap<String, Long>()
    val pendingResets = resets.sorted().iterator()
    var nextReset = if (pendingResets.hasNext()) pendingResets.next() else null
    for (event in events.sortedBy { it.timeMillis }) {
        while (nextReset != null && nextReset <= event.timeMillis) {
            open.clear()
            nextReset = if (pendingResets.hasNext()) pendingResets.next() else null
        }
        if (event.packageName.isEmpty()) continue
        if (event.resumed) {
            val previous = open[event.packageName]
            if (previous != null) addOverlap(durations, event.packageName, previous, event.timeMillis, windowStart, windowEnd)
            open[event.packageName] = event.timeMillis
        } else {
            val previous = open.remove(event.packageName) ?: continue
            addOverlap(durations, event.packageName, previous, event.timeMillis, windowStart, windowEnd)
        }
    }
    if (nextReset != null) open.clear()
    for ((pkg, started) in open) {
        addOverlap(durations, pkg, started, windowEnd, windowStart, windowEnd)
    }
    val foreground = open.entries
        .maxWithOrNull(compareBy<Map.Entry<String, Long>> { it.value }.thenBy { it.key })
        ?.key
        .orEmpty()
    val recent = durations.entries
        .filter { it.value >= 1_000L }
        .sortedWith(compareByDescending<Map.Entry<String, Long>> { it.value }.thenBy { it.key })
        .take(PROCESS_LIST_LIMIT)
        .map { "${it.key} ${formatDuration(it.value)}" }
    return UsageSummary(foreground, recent)
}

internal fun formatDuration(ms: Long): String {
    val minutes = ms / 60_000
    return if (minutes >= 1) "${minutes}m" else "${ms / 1_000}s"
}

/** SwapTotal and SwapFree from `/proc/meminfo`, in megabytes. Missing keys stay null. */
internal fun parseSwapMb(meminfo: String): Pair<Int?, Int?> {
    var total: Long? = null
    var free: Long? = null
    for (line in meminfo.lineSequence()) {
        val parts = line.trim().split(Regex("\\s+"))
        if (parts.size < 2) continue
        val kb = parts[1].toLongOrNull() ?: continue
        when (parts[0].removeSuffix(":")) {
            "SwapTotal" -> total = kb
            "SwapFree" -> free = kb
        }
    }
    return total?.let { (it / 1024).toInt() } to free?.let { (it / 1024).toInt() }
}

private fun addOverlap(
    durations: MutableMap<String, Long>,
    packageName: String,
    start: Long,
    end: Long,
    windowStart: Long,
    windowEnd: Long,
) {
    val from = maxOf(start, windowStart)
    val to = minOf(end, windowEnd)
    if (to > from) durations[packageName] = (durations[packageName] ?: 0L) + (to - from)
}

private fun bytesToMb(bytes: Long) = (bytes / (1024 * 1024)).toInt()

/**
 * Resume and pause only. [UsageEvents.Event.ACTIVITY_STOPPED] is not a pause: moving from
 * one screen to another in the same app stops the first screen after the next one resumes,
 * and treating that as a pause would close the app the user is still in.
 * ACTIVITY_RESUMED and ACTIVITY_PAUSED share the values of the older constants.
 */
@Suppress("DEPRECATION")
internal fun activityForeground(type: Int): Boolean? = when (type) {
    UsageEvents.Event.MOVE_TO_FOREGROUND -> true
    UsageEvents.Event.MOVE_TO_BACKGROUND -> false
    else -> null
}

/**
 * Start, and the hidden continuation (21) and rollover (22) events, mean a foreground
 * service is running. Rollover is written because the service is still started when the
 * stats roll to the next day, not because it stopped. Stop closes it.
 */
internal fun serviceForeground(type: Int): Boolean? = when (type) {
    UsageEvents.Event.FOREGROUND_SERVICE_START, FGS_CONTINUING, FGS_ROLLOVER -> true
    UsageEvents.Event.FOREGROUND_SERVICE_STOP -> false
    else -> null
}

/** [UsageEvents.Event] values hidden from the SDK. Continuation opens a new day; rollover marks the service still started. */
private const val FGS_CONTINUING = 21
private const val FGS_ROLLOVER = 22

/**
 * Packages that ran a foreground service during the window, including one that started
 * before the window and is still running. Each service of a package is tracked on its own.
 * A stop with no earlier start is ignored. At each of [resets] (device shutdown or startup)
 * open services are dropped, because Android does not log a stop for them; one that runs
 * again after boot logs a new start.
 */
internal fun foregroundServicePackages(
    events: List<ServiceEvent>,
    windowStart: Long,
    windowEnd: Long,
    resets: List<Long> = emptyList(),
): List<String> {
    val open = HashMap<Pair<String, String>, Long>()
    val seen = HashSet<String>()
    val pendingResets = resets.sorted().iterator()
    var nextReset = if (pendingResets.hasNext()) pendingResets.next() else null
    for (event in events.sortedBy { it.timeMillis }) {
        while (nextReset != null && nextReset <= event.timeMillis) {
            open.clear()
            nextReset = if (pendingResets.hasNext()) pendingResets.next() else null
        }
        if (event.packageName.isEmpty()) continue
        val key = event.packageName to event.serviceName
        if (event.running) {
            if (key !in open) open[key] = event.timeMillis
        } else {
            val started = open.remove(key) ?: continue
            if (overlaps(started, event.timeMillis, windowStart, windowEnd)) seen += event.packageName
        }
    }
    if (nextReset != null) open.clear()
    for ((key, started) in open) {
        if (overlaps(started, windowEnd, windowStart, windowEnd)) seen += key.first
    }
    return seen.sorted().take(PROCESS_LIST_LIMIT)
}

/** [UsageEvents.Event.DEVICE_SHUTDOWN] and DEVICE_STARTUP, public only from API 30. */
internal fun isDeviceReset(type: Int): Boolean = type == DEVICE_SHUTDOWN || type == DEVICE_STARTUP

private const val DEVICE_SHUTDOWN = 26
private const val DEVICE_STARTUP = 27

private fun overlaps(start: Long, end: Long, windowStart: Long, windowEnd: Long): Boolean =
    minOf(end, windowEnd) > maxOf(start, windowStart)

/** [exitCode] is null when the command did not start, timed out, or its output was cut off. */
private data class CommandResult(val exitCode: Int?, val elapsedMs: Long, val output: String?)

/** Reads combined stdout and stderr. [CommandResult.output] is only set on exit code 0. */
private fun runProcess(argv: List<String>, timeoutMs: Long): CommandResult {
    val startedAt = System.nanoTime()
    fun elapsed() = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt)
    val process = try {
        ProcessBuilder(argv).redirectErrorStream(true).start()
    } catch (_: IOException) {
        return CommandResult(exitCode = null, elapsedMs = elapsed(), output = null)
    }
    val output = StringBuilder()
    val reader = Thread {
        try {
            process.inputStream.bufferedReader().use { source ->
                val buf = CharArray(4096)
                while (output.length < MAX_COMMAND_OUTPUT) {
                    val n = source.read(buf)
                    if (n < 0) break
                    output.append(buf, 0, minOf(n, MAX_COMMAND_OUTPUT - output.length))
                }
            }
        } catch (_: IOException) {
        }
    }
    reader.isDaemon = true
    reader.name = "process-collector-ps"
    return try {
        reader.start()
        val finished = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
        val waited = elapsed()
        if (!finished) process.destroyForcibly()
        joinReader(reader)
        when {
            !finished || reader.isAlive -> CommandResult(exitCode = null, elapsedMs = waited, output = null)
            else -> {
                val code = process.exitValue()
                CommandResult(code, waited, if (code == 0) output.toString().ifBlank { null } else null)
            }
        }
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
        CommandResult(exitCode = null, elapsedMs = elapsed(), output = null)
    } finally {
        if (process.isAlive) process.destroyForcibly()
        joinReader(reader)
    }
}

private fun joinReader(reader: Thread) {
    try {
        reader.join(1_000)
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
    }
}

private const val MAX_COMMAND_OUTPUT = 256_000
