package io.github.hannescoetzee.wazuhagent.collectors

import org.junit.Assert.assertEquals
import org.junit.Test

class ProcessCollectorTest {
    @Test
    fun parsePsSumsRssSkipsHeaderAndMalformedLines() {
        val snapshot = parsePs(
            """
            RSS NAME
            1000 com.app
            not-a-number ignored
            2048 com.app
            512 com.other

            """.trimIndent(),
        )
        assertEquals(3, snapshot.processCount)
        assertEquals(3048L, snapshot.rssKbByName["com.app"])
        assertEquals(512L, snapshot.rssKbByName["com.other"])
        assertEquals(listOf("com.app" to 3048L, "com.other" to 512L), topByRss(snapshot))
    }

    @Test
    fun topProcessesOrdersByRssAndCapsTheList() {
        val lines = (1..30).joinToString("\n") { "$it proc$it" }
        val top = topByRss(parsePs(lines))
        assertEquals(25, top.size)
        assertEquals("proc30" to 30L, top.first())
        assertEquals("proc6" to 6L, top.last())
    }

    @Test
    fun formatRssUsesMegabytesPastOneMegabyte() {
        assertEquals("com.app 1MB", formatRss("com.app", 1024))
        assertEquals("com.app 512KB", formatRss("com.app", 512))
    }

    @Test
    fun aggregateUsageSumsResumePausePairs() {
        val summary = aggregateUsage(
            listOf(
                UsageEvent("com.a", resumed = true, timeMillis = 0),
                UsageEvent("com.a", resumed = false, timeMillis = 6 * 60_000L),
                UsageEvent("com.b", resumed = true, timeMillis = 6 * 60_000L),
                UsageEvent("com.b", resumed = false, timeMillis = 7 * 60_000L),
            ),
            windowStart = 0,
            windowEnd = 10 * 60_000L,
        )
        assertEquals("", summary.foregroundApp)
        assertEquals(listOf("com.a 6m", "com.b 1m"), summary.recentApps)
    }

    @Test
    fun appStillForegroundAtWindowEndIsCountedAndReported() {
        val summary = aggregateUsage(
            listOf(UsageEvent("com.a", resumed = true, timeMillis = 0)),
            windowStart = 0,
            windowEnd = 6 * 60_000L,
        )
        assertEquals("com.a", summary.foregroundApp)
        assertEquals(listOf("com.a 6m"), summary.recentApps)
    }

    @Test
    fun pauseWithoutResumeIsIgnored() {
        val summary = aggregateUsage(
            listOf(
                UsageEvent("com.a", resumed = false, timeMillis = 5_000),
                UsageEvent("com.b", resumed = true, timeMillis = 1_000),
                UsageEvent("com.b", resumed = false, timeMillis = 61_000),
            ),
            windowStart = 0,
            windowEnd = 120_000,
        )
        assertEquals("", summary.foregroundApp)
        assertEquals(listOf("com.b 1m"), summary.recentApps)
    }

    @Test
    fun foregroundAppIsTheLatestResumeThatWasNotPaused() {
        val summary = aggregateUsage(
            listOf(
                UsageEvent("com.a", resumed = true, timeMillis = 1_000),
                UsageEvent("com.b", resumed = true, timeMillis = 2_000),
            ),
            windowStart = 0,
            windowEnd = 62_000,
        )
        assertEquals("com.b", summary.foregroundApp)
        assertEquals("com.a 1m", summary.recentApps.first())
    }

    @Test
    fun resumeBeforeTheWindowCountsOnlyTheOverlap() {
        val summary = aggregateUsage(
            listOf(UsageEvent("com.a", resumed = true, timeMillis = -10_000)),
            windowStart = 0,
            windowEnd = 60_000,
        )
        assertEquals("com.a", summary.foregroundApp)
        assertEquals(listOf("com.a 1m"), summary.recentApps)
    }

    @Test
    fun parseSwapMbReadsKilobytes() {
        val meminfo = """
            MemTotal:        8000000 kB
            SwapTotal:       4194304 kB
            SwapFree:        3174400 kB
        """.trimIndent()
        assertEquals(4096 to 3100, parseSwapMb(meminfo))
    }

    @Test
    fun parseSwapMbReturnsNullWhenSwapIsAbsent() {
        assertEquals(null to null, parseSwapMb("MemTotal: 8000000 kB\n"))
    }

    @Test
    fun parseSwapMbKeepsFreeNullWhenOnlyTotalIsPresent() {
        assertEquals(4096 to null, parseSwapMb("SwapTotal: 4194304 kB\n"))
    }

    @Test
    fun stoppingOneScreenIsNotLeavingTheApp() {
        assertEquals(true, activityForeground(1))
        assertEquals(false, activityForeground(2))
        assertEquals(null, activityForeground(23))
    }

    @Test
    fun foregroundServiceEventsOpenOnStartAndContinuation() {
        assertEquals(true, serviceForeground(19))
        assertEquals(true, serviceForeground(21))
        assertEquals(true, serviceForeground(22))
        assertEquals(false, serviceForeground(20))
        assertEquals(null, serviceForeground(26))
    }

    @Test
    fun serviceStillRunningFromBeforeTheWindowIsReported() {
        val packages = foregroundServicePackages(
            listOf(service("com.music", running = true, timeMillis = -60_000)),
            windowStart = 0,
            windowEnd = 60_000,
        )
        assertEquals(listOf("com.music"), packages)
    }

    @Test
    fun serviceThatStoppedBeforeTheWindowIsIgnored() {
        val packages = foregroundServicePackages(
            listOf(
                service("com.music", running = true, timeMillis = -120_000),
                service("com.music", running = false, timeMillis = -60_000),
            ),
            windowStart = 0,
            windowEnd = 60_000,
        )
        assertEquals(emptyList<String>(), packages)
    }

    @Test
    fun serviceRolloverThenContinuationStaysOpen() {
        val packages = foregroundServicePackages(
            listOf(
                service("com.vpn", running = true, timeMillis = -30_000),
                service("com.vpn", running = true, timeMillis = -29_000),
                service("com.done", running = true, timeMillis = 0),
                service("com.done", running = false, timeMillis = 10_000),
            ),
            windowStart = 0,
            windowEnd = 60_000,
        )
        assertEquals(listOf("com.done", "com.vpn"), packages)
    }

    @Test
    fun stoppingOneServiceKeepsTheOtherServiceOfThePackageRunning() {
        val packages = foregroundServicePackages(
            listOf(
                service("com.app", "Sync", running = true, timeMillis = -120_000),
                service("com.app", "Upload", running = true, timeMillis = -110_000),
                service("com.app", "Sync", running = false, timeMillis = -100_000),
            ),
            windowStart = 0,
            windowEnd = 60_000,
        )
        assertEquals(listOf("com.app"), packages)
    }

    @Test
    fun serviceOpenAtShutdownIsDroppedButOneStartedAfterBootIsKept() {
        val packages = foregroundServicePackages(
            listOf(
                service("com.stale", running = true, timeMillis = -600_000),
                service("com.fresh", running = true, timeMillis = -100_000),
            ),
            windowStart = 0,
            windowEnd = 60_000,
            resets = listOf(-300_000, -290_000),
        )
        assertEquals(listOf("com.fresh"), packages)
    }

    @Test
    fun resetAfterTheLastEventStillDropsOpenServices() {
        val packages = foregroundServicePackages(
            listOf(service("com.stale", running = true, timeMillis = -600_000)),
            windowStart = 0,
            windowEnd = 60_000,
            resets = listOf(-300_000),
        )
        assertEquals(emptyList<String>(), packages)
    }

    @Test
    fun appOpenAtShutdownIsNotCountedAfterBoot() {
        val summary = aggregateUsage(
            listOf(
                UsageEvent("com.stale", resumed = true, timeMillis = -600_000),
                UsageEvent("com.launcher", resumed = true, timeMillis = 10_000),
            ),
            windowStart = 0,
            windowEnd = 70_000,
            resets = listOf(-300_000),
        )
        assertEquals("com.launcher", summary.foregroundApp)
        assertEquals(listOf("com.launcher 1m"), summary.recentApps)
    }

    @Test
    fun deviceShutdownAndStartupAreResets() {
        assertEquals(true, isDeviceReset(26))
        assertEquals(true, isDeviceReset(27))
        assertEquals(false, isDeviceReset(23))
    }

    @Test
    fun quickRootDenialWaitsADay() {
        assertEquals(ROOT_DENIAL_BACKOFF_MS, rootBackoffMs(exitCode = 1, elapsedMs = 300))
    }

    @Test
    fun slowRootDenialMeansAPromptWasShownAndRetriesAfterAnHour() {
        assertEquals(ROOT_RETRY_BACKOFF_MS, rootBackoffMs(exitCode = 1, elapsedMs = 10_500))
    }

    @Test
    fun rootTimeoutRetriesAfterAnHour() {
        assertEquals(ROOT_RETRY_BACKOFF_MS, rootBackoffMs(exitCode = null, elapsedMs = 20_000))
    }

    private fun service(packageName: String, serviceName: String = "Main", running: Boolean, timeMillis: Long) =
        ServiceEvent(packageName, serviceName, running, timeMillis)
}
