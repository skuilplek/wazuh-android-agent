package io.github.hannescoetzee.wazuhagent.service

import android.annotation.SuppressLint
import android.app.AlarmManager
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import io.github.hannescoetzee.wazuhagent.DeviceInfo
import io.github.hannescoetzee.wazuhagent.admin.DeviceCommands
import io.github.hannescoetzee.wazuhagent.app
import io.github.hannescoetzee.wazuhagent.collectors.AgentLog
import io.github.hannescoetzee.wazuhagent.collectors.CollectorManager
import io.github.hannescoetzee.wazuhagent.protocol.AgentConnection
import io.github.hannescoetzee.wazuhagent.protocol.AgentIdentity
import io.github.hannescoetzee.wazuhagent.protocol.ProtocolException
import io.github.hannescoetzee.wazuhagent.protocol.SenderCounter
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Keeps the TCP session to the manager alive: handshake, keepalives, and draining the
 * event queue. Collectors run for as long as the service does.
 *
 * A partial wake lock and a Wi-Fi lock are held for the whole run, the same way Termux
 * keeps a session alive with the screen off. Stop is what releases them.
 */
class AgentForegroundService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var loop: Job? = null
    private var collectors: CollectorManager? = null
    private val reconnectNow = Channel<Unit>(Channel.CONFLATED)
    @Volatile private var connection: AgentConnection? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        startInForeground()
        scope.launch {
            AgentState.status.collectLatest { status ->
                getSystemService(NotificationManager::class.java)
                    .notify(Notifications.ID_AGENT, notification(status))
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // A startForegroundService that only reaches stopSelf still has to enter the foreground.
        startInForeground()
        if (intent?.action == ACTION_STOP) {
            wantsToStop = true
            app.store.agentEnabled = false
            cancelRestart(this)
            stopSelf()
            return START_NOT_STICKY
        }
        if (!app.store.agentEnabled || app.store.agentKey == null || app.store.config == null) {
            AgentState.set(ConnectionState.STOPPED, if (app.store.agentKey == null) "Not enrolled" else "Stopped")
            stopSelf()
            return START_NOT_STICKY
        }
        wantsToStop = false
        isRunning = true
        acquireLocks()
        startInForeground()
        if (loop?.isActive != true) {
            collectors = CollectorManager(this, app.queue, onNetworkAvailable = { reconnectNow.trySend(Unit) })
                .also { it.start() }
            loop = scope.launch { runLoop() }
        }
        return START_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        if (!wantsToStop && app.store.agentEnabled && app.store.agentKey != null && app.store.config != null) {
            AgentLog.info("Task removed, scheduling agent restart")
            scheduleRestart(applicationContext)
        }
        super.onTaskRemoved(rootIntent)
    }

    private fun startInForeground() {
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        val current = AgentState.status.value
        val shown = if (current.state == ConnectionState.STOPPED && !wantsToStop) {
            current.copy(state = ConnectionState.CONNECTING)
        } else {
            current
        }
        ServiceCompat.startForeground(this, Notifications.ID_AGENT, notification(shown), type)
    }

    private fun notification(status: AgentStatus) =
        Notifications.agent(this, status, wakeLockHeld = wakeLock?.isHeld == true)

    /** Held until [onDestroy]. Doze still ignores these unless battery optimization is off. */
    @SuppressLint("WakelockTimeout")
    private fun acquireLocks() {
        val power = wakeLock ?: getSystemService(PowerManager::class.java)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, WAKELOCK_TAG)
            .apply { setReferenceCounted(false) }
            .also { wakeLock = it }
        if (!power.isHeld) power.acquire()

        val wifi = wifiLock ?: applicationContext.getSystemService(WifiManager::class.java)
            .createWifiLock(WIFILOCK_MODE, WIFILOCK_TAG)
            .apply { setReferenceCounted(false) }
            .also { wifiLock = it }
        if (!wifi.isHeld) {
            runCatching { wifi.acquire() }
                .onFailure { AgentLog.warn("Could not acquire Wi-Fi lock: ${it.message}") }
        }
    }

    private fun releaseLocks() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
        wifiLock?.let { if (it.isHeld) it.release() }
        wifiLock = null
    }

    private suspend fun runLoop() {
        var backoffMs = INITIAL_BACKOFF_MS
        AgentLog.info("Agent service started")
        val counter = SenderCounter(app.store.counterStore)
        while (scope.isActive) {
            val store = app.store
            val key = store.agentKey
            val config = store.config
            if (key == null || config == null) {
                AgentState.set(ConnectionState.STOPPED, "Not enrolled")
                stopSelf()
                return
            }
            val version = store.agentVersion ?: AgentIdentity.DEFAULT_AGENT_VERSION
            val disconnected = CompletableDeferred<Throwable?>()
            val conn = AgentConnection(
                host = config.host,
                port = config.port,
                key = key,
                counter = counter,
                identity = DeviceInfo.identity(version),
                listener = object : AgentConnection.Listener {
                    override fun onAck() = AgentState.acked(System.currentTimeMillis())
                    override fun onDisconnected(cause: Throwable?) {
                        disconnected.complete(cause)
                    }
                    override fun onForceReconnect() {
                        disconnected.complete(null)
                    }
                    override fun onSharedFileReceived(name: String, md5: String) {
                        if (name == "merged.mg") store.mergedSum = md5
                    }
                    override fun onExec(payload: String) {
                        scope.launch {
                            try {
                                DeviceCommands.handle(this@AgentForegroundService, app.queue, payload)
                            } catch (e: CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                AgentLog.error("Device command failed", e)
                            }
                        }
                    }
                },
            )

            AgentState.set(ConnectionState.CONNECTING, "${config.host}:${config.port}")
            try {
                conn.connect()
                connection = conn
                backoffMs = INITIAL_BACKOFF_MS
                AgentState.set(ConnectionState.CONNECTED, "Agent ${key.id}")
                coroutineScope {
                    val intervalMs = config.keepaliveSeconds * 1000L
                    val keepalive = launch { keepaliveLoop(conn, intervalMs) }
                    val drain = launch { drainLoop(conn) }
                    val watchdog = launch { ackWatchdog(conn, intervalMs, disconnected) }
                    val cause = disconnected.await()
                    keepalive.cancel()
                    drain.cancel()
                    watchdog.cancel()
                    if (cause != null) throw cause
                }
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: ProtocolException) {
                AgentState.set(ConnectionState.WAITING_RETRY, e.message ?: "Protocol error")
                AgentLog.warn("Manager connection failed: ${e.message}")
            } catch (e: Exception) {
                AgentState.set(ConnectionState.WAITING_RETRY, e.message ?: e.javaClass.simpleName)
            } finally {
                connection = null
                withContext(NonCancellable + Dispatchers.IO) { conn.close() }
            }

            // Wait for backoff, or retry immediately when the network comes back.
            withTimeoutOrNull(backoffMs) { reconnectNow.receive() }
            backoffMs = (backoffMs * 2).coerceAtMost(MAX_BACKOFF_MS)
        }
    }

    private suspend fun keepaliveLoop(conn: AgentConnection, intervalMs: Long) {
        val labels = DeviceInfo.labels()
        while (true) {
            conn.sendKeepalive(labels, app.store.mergedSum)
            delay(intervalMs)
        }
    }

    /**
     * Runs apart from the senders because a write on a half-open socket can block them
     * indefinitely; closing the socket is what unblocks them.
     */
    private suspend fun ackWatchdog(conn: AgentConnection, intervalMs: Long, disconnected: CompletableDeferred<Throwable?>) {
        while (true) {
            delay(WATCHDOG_TICK_MS)
            val silentFor = System.currentTimeMillis() - conn.lastAckAtMillis
            if (silentFor > intervalMs * 3 + ACK_GRACE_MS) {
                withContext(NonCancellable) { conn.close() }
                disconnected.complete(java.io.IOException("No ack from manager for ${silentFor / 1000}s"))
                return
            }
        }
    }

    private suspend fun drainLoop(conn: AgentConnection) {
        val queue = app.queue
        while (true) {
            val batch = queue.oldest(BATCH_SIZE)
            if (batch.isEmpty()) {
                queue.awaitNew(IDLE_POLL_MS)
                continue
            }
            for (event in batch) {
                conn.sendEvent(event.location, event.message)
                delay(SEND_SPACING_MS)
            }
            queue.remove(batch)
            AgentState.sent(batch.size)
        }
    }

    override fun onDestroy() {
        isRunning = false
        collectors?.stop()
        val conn = connection
        // shutdown() sends before it closes. A blocked write ignores the timeout, so the
        // flush runs as its own job and the socket is closed if that send does not return.
        // Closing the socket fails the stuck write, so the flush job ends without a second wait.
        val flushScope = CoroutineScope(Dispatchers.IO)
        val flush = flushScope.launch { conn?.shutdown() }
        try {
            runBlocking(Dispatchers.IO) {
                if (withTimeoutOrNull(FLUSH_TIMEOUT_MS) { flush.join() } == null) conn?.close()
            }
        } finally {
            flush.cancel()
            flushScope.cancel()
            releaseLocks()
            scope.cancel()
            AgentState.set(ConnectionState.STOPPED)
            super.onDestroy()
        }
    }

    companion object {
        private const val ACTION_STOP = "io.github.hannescoetzee.wazuhagent.STOP"
        private const val WAKELOCK_TAG = "wazuhagent:service-wakelock"
        private const val WIFILOCK_TAG = "wazuhagent:service-wifilock"
        /**
         * Not LOW_LATENCY: that lock is only active with the screen on and the app in the
         * foreground. Newer Wi-Fi modules turn HIGH_PERF into LOW_LATENCY by themselves.
         */
        @Suppress("DEPRECATION")
        private const val WIFILOCK_MODE = WifiManager.WIFI_MODE_FULL_HIGH_PERF
        private const val RESTART_REQUEST_CODE = 2
        private const val RESTART_DELAY_MS = 1_000L
        private const val INITIAL_BACKOFF_MS = 5_000L
        private const val MAX_BACKOFF_MS = 120_000L
        private const val ACK_GRACE_MS = 30_000L
        private const val WATCHDOG_TICK_MS = 10_000L
        private const val BATCH_SIZE = 100
        private const val IDLE_POLL_MS = 30_000L
        /** Keeps bursts (e.g. the first package inventory) well under the manager's EPS limits. */
        private const val SEND_SPACING_MS = 10L
        /**
         * onDestroy blocks the main thread for this plus the 2 s reader join in
         * [io.github.hannescoetzee.wazuhagent.protocol.AgentConnection.close]. Keep the sum under
         * the 5 s input-dispatch ANR.
         */
        private const val FLUSH_TIMEOUT_MS = 2_000L

        /** Set by Stop. onDestroy does not clear agentEnabled. */
        @Volatile private var wantsToStop = false

        /**
         * True from a successful start until [onDestroy]. A killed process comes back false,
         * so the posture worker can schedule a restart. Task removal does not check this.
         */
        @Volatile var isRunning: Boolean = false
            private set

        fun start(context: Context) {
            ContextCompat.startForegroundService(context, Intent(context, AgentForegroundService::class.java))
        }

        fun stopIntent(context: Context) = Intent(context, AgentForegroundService::class.java).setAction(ACTION_STOP)

        fun stop(context: Context) {
            wantsToStop = true
            context.app.store.agentEnabled = false
            cancelRestart(context)
            context.stopService(Intent(context, AgentForegroundService::class.java))
        }

        /**
         * An exact alarm is one of the cases where Android 12+ still allows a background
         * process to start a foreground service. An inexact alarm is not.
         */
        fun scheduleRestart(context: Context) {
            if (!context.app.store.agentEnabled) return
            if (!canScheduleRestart(context)) {
                AgentLog.warn("Exact alarms are not allowed, so the agent cannot restart from the background")
                return
            }
            val alarm = context.getSystemService(AlarmManager::class.java)
            val pending = restartPendingIntent(context, PendingIntent.FLAG_UPDATE_CURRENT) ?: return
            if (!context.app.store.agentEnabled) return
            runCatching {
                alarm.setExactAndAllowWhileIdle(
                    AlarmManager.ELAPSED_REALTIME_WAKEUP,
                    SystemClock.elapsedRealtime() + RESTART_DELAY_MS,
                    pending,
                )
            }.onFailure { AgentLog.warn("Could not schedule agent restart: ${it.message}") }
            // Stop can land while the alarm is being armed.
            if (!context.app.store.agentEnabled) cancelRestart(context)
        }

        /** False on Android 12 when the user has turned off "Alarms and reminders". */
        fun canScheduleRestart(context: Context): Boolean =
            Build.VERSION.SDK_INT < Build.VERSION_CODES.S ||
                context.getSystemService(AlarmManager::class.java).canScheduleExactAlarms()

        private fun cancelRestart(context: Context) {
            val pending = restartPendingIntent(context, PendingIntent.FLAG_NO_CREATE) ?: return
            context.getSystemService(AlarmManager::class.java).cancel(pending)
            pending.cancel()
        }

        private fun restartPendingIntent(context: Context, mutabilityExtra: Int): PendingIntent? {
            val intent = Intent(context, AgentForegroundService::class.java)
            return PendingIntent.getForegroundService(
                context, RESTART_REQUEST_CODE, intent,
                PendingIntent.FLAG_IMMUTABLE or mutabilityExtra,
            )
        }
    }
}
