package io.github.hannescoetzee.wazuhagent.collectors

import java.io.File
import java.security.MessageDigest

/**
 * Signer and APK digests for package events. The signer is stable across updates.
 * The APK digest is the content hash threat-intel feeds match.
 */
internal fun sha256Hex(bytes: ByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
    return toHex(digest)
}

internal fun sha256File(path: String?): String? {
    if (path.isNullOrEmpty()) return null
    val file = File(path)
    if (!file.isFile) return null
    return runCatching {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(65536)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        toHex(digest.digest())
    }.getOrNull()
}

/**
 * [digests] is signing-certificate history, oldest first, except when [multipleSigners] is
 * set: then every entry signs the APK and there is no single current certificate.
 */
internal fun currentSigner(digests: List<String>, multipleSigners: Boolean): String? =
    if (multipleSigners) digests.firstOrNull() else digests.lastOrNull()

private fun toHex(bytes: ByteArray): String {
    val hex = "0123456789abcdef"
    val out = CharArray(bytes.size * 2)
    bytes.forEachIndexed { index, byte ->
        val value = byte.toInt() and 0xff
        out[index * 2] = hex[value ushr 4]
        out[index * 2 + 1] = hex[value and 0x0f]
    }
    return String(out)
}
