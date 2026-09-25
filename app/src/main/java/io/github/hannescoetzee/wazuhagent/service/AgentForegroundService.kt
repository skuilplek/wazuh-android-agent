package io.github.hannescoetzee.wazuhagent.service

import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import io.github.hannescoetzee.wazuhagent.DeviceInfo
import io.github.hannescoetzee.wazuhagent.app
import io.github.hannescoetzee.wazuhagent.collectors.AgentLog
import io.github.hannescoetzee.wazuhagent.collectors.CollectorManager
import io.github.hannescoetzee.wazuhagent.protocol.AgentConnection
import io.github.hannescoetzee.wazuhagent.protocol.AgentIdentity
import io.github.hannescoetzee.wazuhagent.protocol.ProtocolException
import io.github.hannescoetzee.wazuhagent.protocol.SenderCounter
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
 */
class AgentForegroundService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var loop: Job? = null
    private var collectors: CollectorManager? = null
    private val reconnectNow = Channel<Unit>(Channel.CONFLATED)
    @Volatile private var connection: AgentConnection? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        startInForeground()
        scope.launch {
            AgentState.status.collectLatest { status ->
                getSystemService(NotificationManager::class.java)
                    .notify(Notifications.ID_AGENT, Notifications.agent(this@AgentForegroundService, status))
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            app.store.agentEnabled = false
            stopSelf()
            return START_NOT_STICKY
        }
        if (app.store.agentKey == null || app.store.config == null) {
            AgentState.set(ConnectionState.STOPPED, "Not enrolled")
            stopSelf()
            return START_NOT_STICKY
        }
        if (loop?.isActive != true) {
            collectors = CollectorManager(this, app.queue, onNetworkAvailable = { reconnectNow.trySend(Unit) })
                .also { it.start() }
            loop = scope.launch { runLoop() }
        }
        return START_STICKY
    }

    private fun startInForeground() {
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(
            this, Notifications.ID_AGENT,
            Notifications.agent(this, AgentState.status.value.copy(state = ConnectionState.CONNECTING)), type,
        )
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
        collectors?.stop()
        val conn = connection
        runBlocking(Dispatchers.IO) {
            withTimeoutOrNull(3_000) { conn?.shutdown() }
        }
        scope.cancel()
        AgentState.set(ConnectionState.STOPPED)
        super.onDestroy()
    }

    companion object {
        private const val ACTION_STOP = "io.github.hannescoetzee.wazuhagent.STOP"
        private const val INITIAL_BACKOFF_MS = 5_000L
        private const val MAX_BACKOFF_MS = 120_000L
        private const val ACK_GRACE_MS = 30_000L
        private const val WATCHDOG_TICK_MS = 10_000L
        private const val BATCH_SIZE = 100
        private const val IDLE_POLL_MS = 30_000L
        /** Keeps bursts (e.g. the first package inventory) well under the manager's EPS limits. */
        private const val SEND_SPACING_MS = 10L

        fun start(context: Context) {
            ContextCompat.startForegroundService(context, Intent(context, AgentForegroundService::class.java))
        }

        fun stopIntent(context: Context) = Intent(context, AgentForegroundService::class.java).setAction(ACTION_STOP)

        fun stop(context: Context) {
            context.app.store.agentEnabled = false
            context.stopService(Intent(context, AgentForegroundService::class.java))
        }
    }
}
