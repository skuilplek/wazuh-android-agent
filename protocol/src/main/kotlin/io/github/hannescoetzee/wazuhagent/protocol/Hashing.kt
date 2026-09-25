package io.github.hannescoetzee.wazuhagent.protocol

import java.security.MessageDigest

internal object Hashing {
    private val HEX = "0123456789abcdef".toCharArray()

    fun md5Hex(input: String): String = md5Hex(input.toByteArray(Charsets.UTF_8))

    fun md5Hex(input: ByteArray, offset: Int = 0, length: Int = input.size - offset): String {
        val digest = MessageDigest.getInstance("MD5")
        digest.update(input, offset, length)
        return toHex(digest.digest())
    }

    fun sha256Hex(input: ByteArray): String = toHex(MessageDigest.getInstance("SHA-256").digest(input))

    fun toHex(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        bytes.forEachIndexed { i, b ->
            val v = b.toInt() and 0xff
            out[i * 2] = HEX[v ushr 4]
            out[i * 2 + 1] = HEX[v and 0x0f]
        }
        return String(out)
    }
}
