package io.github.hannescoetzee.wazuhagent.protocol

import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/**
 * A single TCP session with `wazuh-remoted` (default port 1514).
 *
 * [connect] performs the startup handshake synchronously; afterwards a reader thread
 * handles manager messages until the socket closes.
 */
class AgentConnection(
    private val host: String,
    private val port: Int,
    private val key: AgentKey,
    private val counter: SenderCounter,
    private val identity: AgentIdentity,
    private val listener: Listener = object : Listener {},
    private val connectTimeoutMs: Int = 10_000,
    private val ackTimeoutMs: Int = 30_000,
) : Closeable {

    interface Listener {
        fun onAck() {}
        fun onDisconnected(cause: Throwable?) {}
        fun onForceReconnect() {}
        /** Manager pushed a new shared config (merged.mg); report this sum in future keepalives. */
        fun onSharedFileReceived(name: String, md5: String) {}
        fun onUnhandled(text: String) {}
    }

    private val codec = MessageCodec(key)
    private val sendLock = Any()
    private var socket: Socket? = null
    private var output: OutputStream? = null
    private var reader: Thread? = null
    private var pendingFile: Pair<String, String>? = null

    @Volatile var lastAckAtMillis: Long = 0
        private set

    @Volatile var isConnected: Boolean = false
        private set

    /** Local address of the socket, reported to the manager as `_agent_ip`. */
    val localAddress: String?
        get() = socket?.localAddress?.hostAddress

    @Throws(IOException::class, ProtocolException::class)
    fun connect() {
        check(socket == null) { "AgentConnection instances are single-use" }
        val s = Socket()
        socket = s
        try {
            s.tcpNoDelay = true
            s.keepAlive = true
            s.connect(InetSocketAddress(host, port), connectTimeoutMs)
            output = s.getOutputStream()
            val input = s.getInputStream()

            send(Control.startup(identity.agentVersion))
            awaitAck(s, input)
            isConnected = true

            s.soTimeout = 0
            reader = Thread({ readLoop(input) }, "wazuh-remoted-reader").apply {
                isDaemon = true
                start()
            }
            send(Control.agentStarted(key))
        } catch (e: Exception) {
            closeQuietly()
            throw e
        }
    }

    private fun awaitAck(s: Socket, input: InputStream) {
        s.soTimeout = ackTimeoutMs
        while (true) {
            val frame = try {
                TcpFraming.read(input)
            } catch (e: SocketTimeoutException) {
                throw IOException("Timed out waiting for manager ack", e)
            } ?: throw IOException("Manager closed the connection without acknowledging startup")
            val text = codec.decode(frame).text
            when {
                text == Control.HEADER + Control.ACK -> {
                    lastAckAtMillis = System.currentTimeMillis()
                    listener.onAck()
                    return
                }
                text.startsWith(Control.HEADER + Control.ERROR) -> throw ProtocolException(errorMessage(text))
                else -> handleMessage(text)
            }
        }
    }

    fun sendEvent(location: String, message: String) = send(Control.event(location, message))

    fun sendKeepalive(labels: Map<String, String>, mergedSum: String) =
        send(Control.keepalive(identity, labels, mergedSum, localAddress))

    @Throws(IOException::class, ProtocolException::class)
    fun send(message: String) {
        synchronized(sendLock) {
            val out = output ?: throw IOException("Not connected")
            val payload = codec.encode(message, counter.next())
            TcpFraming.write(out, payload)
        }
    }

    private fun readLoop(input: InputStream) {
        var cause: Throwable? = null
        try {
            while (true) {
                val frame = TcpFraming.read(input) ?: break
                val text = try {
                    codec.decode(frame).text
                } catch (e: ProtocolException) {
                    listener.onUnhandled("undecodable frame: ${e.message}")
                    continue
                }
                handleMessage(text)
            }
        } catch (e: Exception) {
            cause = e
        } finally {
            val wasConnected = isConnected
            closeQuietly()
            if (wasConnected) listener.onDisconnected(cause)
        }
    }

    private fun handleMessage(text: String) {
        if (!Control.isControl(text)) {
            // File content lines follow an "up file" header.
            if (pendingFile == null) listener.onUnhandled(text)
            return
        }
        val body = text.substring(Control.HEADER.length)
        when {
            body == Control.ACK -> {
                lastAckAtMillis = System.currentTimeMillis()
                listener.onAck()
            }
            body.startsWith(Control.FILE_UPDATE) -> {
                val parts = body.removePrefix(Control.FILE_UPDATE).trim().split(' ', limit = 2)
                pendingFile = if (parts.size == 2) parts[1].trim() to parts[0] else null
            }
            body.startsWith(Control.FILE_CLOSE) -> {
                pendingFile?.let { (name, md5) -> listener.onSharedFileReceived(name, md5) }
                pendingFile = null
            }
            body.startsWith(Control.FORCE_RECONNECT) -> listener.onForceReconnect()
            body.startsWith(Control.REQUEST) -> replyToRequest(body.removePrefix(Control.REQUEST))
            else -> listener.onUnhandled(text)
        }
    }

    /** Remote config/state queries (`req <counter> <payload>`) are not supported; answer so the API does not hang. */
    private fun replyToRequest(rest: String) {
        val counterId = rest.substringBefore(' ')
        if (counterId.isEmpty() || rest.substringAfter(' ', "").startsWith("ack")) return
        runCatching { send(Control.requestReply(counterId, "err Not supported by the Android agent")) }
    }

    private fun errorMessage(text: String): String {
        val json = text.substringAfter('{', "")
        val msg = Regex("\"message\"\\s*:\\s*\"([^\"]*)\"").find("{$json")?.groupValues?.get(1)
        return "Manager rejected agent: ${msg ?: text.removePrefix(Control.HEADER)}"
    }

    /** Tells the manager we are going away, then closes the socket. */
    fun shutdown() {
        if (isConnected) runCatching { send(Control.shutdown()) }
        close()
    }

    /** Safe from any thread; unblocks a send stuck on a half-open socket. */
    override fun close() {
        closeQuietly()
        reader?.let { if (it !== Thread.currentThread()) it.join(2_000) }
    }

    private fun closeQuietly() {
        isConnected = false
        runCatching { socket?.close() }
        output = null
    }
}
