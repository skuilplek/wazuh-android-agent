package io.github.hannescoetzee.wazuhagent.protocol

import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

data class EnrollmentRequest(
    val host: String,
    val port: Int = 1515,
    val agentName: String,
    val password: String? = null,
    val groups: String? = null,
    val agentVersion: String? = null,
    /**
     * SHA-256 of the manager's TLS certificate (hex). When null the certificate is accepted
     * and reported back so the caller can pin it (trust on first use).
     */
    val pinnedCertSha256: String? = null,
    val timeoutMs: Int = 15_000,
)

data class EnrollmentResult(val key: AgentKey, val serverCertSha256: String, val agentVersion: String? = null)

class EnrollmentException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Client side of `wazuh-authd` (see `src/shared/enrollment_op.c`).
 */
object Enrollment {
    /** Newest first. The manager refuses agents that claim a newer version than itself. */
    val VERSION_CANDIDATES = listOf(
        "v4.14.0", "v4.13.0", "v4.12.0", "v4.11.0", "v4.10.0", "v4.9.2", "v4.8.0", "v4.7.0", "v4.5.0", "v4.3.0",
    )

    /**
     * Enrolls with the newest agent version the manager accepts, so the same key can be used
     * for the startup handshake (which enforces the same rule).
     */
    fun enrollNegotiatingVersion(req: EnrollmentRequest, candidates: List<String> = VERSION_CANDIDATES): EnrollmentResult {
        var lastError: EnrollmentException? = null
        for (version in candidates) {
            try {
                return enroll(req.copy(agentVersion = version)).copy(agentVersion = version)
            } catch (e: EnrollmentException) {
                if (!isVersionRejection(e)) throw e
                lastError = e
            }
        }
        throw lastError ?: EnrollmentException("No agent version accepted by manager")
    }

    fun isVersionRejection(e: Exception): Boolean {
        val msg = e.message ?: return false
        return msg.contains("version", ignoreCase = true) &&
            (msg.contains("lower or equal", ignoreCase = true) || msg.contains("incompatible", ignoreCase = true))
    }

    fun buildRequest(req: EnrollmentRequest): String = buildString {
        if (!req.password.isNullOrEmpty()) append("OSSEC PASS: ").append(req.password).append(' ')
        append("OSSEC A:'").append(req.agentName).append('\'')
        if (!req.agentVersion.isNullOrEmpty()) append(" V:'").append(req.agentVersion).append('\'')
        if (!req.groups.isNullOrBlank()) append(" G:'").append(req.groups.trim()).append('\'')
        append('\n')
    }

    fun parseResponse(response: String): AgentKey {
        val error = response.indexOf("ERROR: ")
        if (error >= 0) {
            throw EnrollmentException(response.substring(error + 7).trim().ifEmpty { "Manager refused enrollment" })
        }
        val start = response.indexOf("OSSEC K:'")
        if (start < 0) throw EnrollmentException("Unexpected response from manager")
        val end = response.indexOf('\'', start + 9)
        if (end < 0) throw EnrollmentException("Truncated key in manager response")
        return try {
            AgentKey.parse(response.substring(start + 9, end))
        } catch (e: IllegalArgumentException) {
            throw EnrollmentException("Invalid key format received", e)
        }
    }

    fun enroll(req: EnrollmentRequest): EnrollmentResult {
        if (!AgentNames.isValid(req.agentName)) {
            throw EnrollmentException("Agent name must be 2-128 chars of letters, digits, '.', '_' or '-'")
        }
        if (req.password?.any { it == '\n' || it == '\r' } == true || req.groups?.any { it == '\n' || it == '\'' } == true) {
            throw EnrollmentException("Password and groups must not contain line breaks or quotes")
        }
        val trust = PinningTrustManager(req.pinnedCertSha256)
        val context = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), null) }

        try {
            (context.socketFactory.createSocket() as SSLSocket).use { socket ->
                socket.connect(InetSocketAddress(req.host, req.port), req.timeoutMs)
                socket.soTimeout = req.timeoutMs
                socket.startHandshake()

                socket.outputStream.apply {
                    write(buildRequest(req).toByteArray(Charsets.UTF_8))
                    flush()
                }

                val response = readResponse(socket)
                val key = parseResponse(response)
                return EnrollmentResult(key, trust.seenSha256 ?: "", req.agentVersion)
            }
        } catch (e: EnrollmentException) {
            throw e
        } catch (e: javax.net.ssl.SSLHandshakeException) {
            val reason = if (trust.pinMismatch) "Manager certificate does not match the pinned fingerprint" else "TLS handshake failed"
            throw EnrollmentException("$reason: ${e.message}", e)
        } catch (e: Exception) {
            throw EnrollmentException("Enrollment failed: ${e.message ?: e.javaClass.simpleName}", e)
        }
    }

    private fun readResponse(socket: SSLSocket): String {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        while (true) {
            val n = try {
                socket.inputStream.read(buf)
            } catch (e: javax.net.ssl.SSLException) {
                // authd closes without close_notify after replying.
                if (out.size() > 0) -1 else throw e
            }
            if (n < 0) break
            out.write(buf, 0, n)
            val text = out.toString(Charsets.UTF_8.name())
            if (text.contains("ERROR: ") && text.endsWith("\n")) break
            val k = text.indexOf("OSSEC K:'")
            if (k >= 0 && text.indexOf('\'', k + 9) >= 0) break
            if (out.size() > 65536) break
        }
        return out.toString(Charsets.UTF_8.name())
    }

    private class PinningTrustManager(private val pinnedSha256: String?) : X509TrustManager {
        @Volatile var seenSha256: String? = null
        @Volatile var pinMismatch = false

        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            throw CertificateException("Client certificates are not accepted")
        }

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            val leaf = chain?.firstOrNull() ?: throw CertificateException("Empty certificate chain")
            leaf.checkValidity()
            val sha = Hashing.sha256Hex(leaf.encoded)
            seenSha256 = sha
            if (pinnedSha256 != null && !pinnedSha256.replace(":", "").equals(sha, ignoreCase = true)) {
                pinMismatch = true
                throw CertificateException("Pinned certificate mismatch")
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
}
