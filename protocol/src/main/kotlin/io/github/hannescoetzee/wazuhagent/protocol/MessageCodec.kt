package io.github.hannescoetzee.wazuhagent.protocol

import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Locale
import java.util.zip.Deflater
import java.util.zip.Inflater
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class ProtocolException(message: String, cause: Throwable? = null) : Exception(message, cause)

data class DecodedMessage(val global: Long, val local: Int, val text: String)

/**
 * Encodes and decodes secure messages exactly like `CreateSecMSG()` / `ReadSecMSG()`
 * in `src/os_crypto/shared/msgs.c` (AES variant).
 */
class MessageCodec(
    key: AgentKey,
    private val random: SecureRandom = SecureRandom(),
) {
    private val secretKey = SecretKeySpec(KeyDerivation.aesKey(key), "AES")
    private val header = (if (key.isDynamicIp) "!${key.id}!$AES_TOKEN" else AES_TOKEN).toByteArray(Charsets.US_ASCII)

    fun encode(message: String, counter: CounterValue): ByteArray =
        encode(message.toByteArray(Charsets.UTF_8), counter)

    fun encode(message: ByteArray, counter: CounterValue): ByteArray {
        if (message.isEmpty() || message.size > MAX_MESSAGE_SIZE) {
            throw ProtocolException("Message size ${message.size} outside 1..$MAX_MESSAGE_SIZE")
        }

        val rand = random.nextInt(0x10000)
        val prefix = String.format(Locale.ROOT, "%05d%010d:%04d:", rand, counter.global, counter.local)
        val tmp = prefix.toByteArray(Charsets.US_ASCII) + message
        val checksummed = Hashing.md5Hex(tmp).toByteArray(Charsets.US_ASCII) + tmp

        val compressed = deflate(checksummed)
        val cmpSize = compressed.size + 1
        val padding = (8 - cmpSize % 8) % 8
        val plaintext = ByteArray(padding + 1) { '!'.code.toByte() } + compressed

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, IvParameterSpec(IV))
        return header + cipher.doFinal(plaintext)
    }

    /** Decodes a frame payload such as `#AES:<ciphertext>` sent by the manager. */
    fun decode(payload: ByteArray): DecodedMessage {
        var offset = 0
        if (payload.isNotEmpty() && payload[0] == '!'.code.toByte()) {
            val end = indexOf(payload, '!'.code.toByte(), 1)
            if (end < 0) throw ProtocolException("Malformed agent id prefix")
            offset = end + 1
        }
        val token = AES_TOKEN.toByteArray(Charsets.US_ASCII)
        if (payload.size < offset + token.size || !token.indices.all { payload[offset + it] == token[it] }) {
            throw ProtocolException("Message is not AES encoded")
        }
        offset += token.size

        val plaintext = try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(IV))
            cipher.doFinal(payload, offset, payload.size - offset)
        } catch (e: Exception) {
            throw ProtocolException("Decryption failed (wrong key?)", e)
        }

        if (plaintext.isEmpty() || plaintext[0] != '!'.code.toByte()) {
            throw ProtocolException("Unsupported (uncompressed) message format")
        }
        var start = 0
        while (start < plaintext.size && plaintext[start] == '!'.code.toByte()) start++
        val data = inflate(plaintext, start, plaintext.size - start)

        if (data.size < HEADER_LENGTH) throw ProtocolException("Message too short")
        val receivedSum = String(data, 0, 32, Charsets.US_ASCII)
        if (Hashing.md5Hex(data, 32, data.size - 32) != receivedSum) {
            throw ProtocolException("Checksum mismatch")
        }
        if (data[47] != ':'.code.toByte() || data[52] != ':'.code.toByte()) {
            throw ProtocolException("Malformed counter section")
        }
        val global = String(data, 37, 10, Charsets.US_ASCII).trim().toLongOrNull()
            ?: throw ProtocolException("Malformed global counter")
        val local = String(data, 48, 4, Charsets.US_ASCII).trim().toIntOrNull()
            ?: throw ProtocolException("Malformed local counter")
        val text = String(data, HEADER_LENGTH, data.size - HEADER_LENGTH, Charsets.UTF_8).trimEnd('\u0000')
        return DecodedMessage(global, local, text)
    }

    private fun deflate(input: ByteArray): ByteArray {
        val deflater = Deflater(Deflater.BEST_COMPRESSION)
        try {
            deflater.setInput(input)
            deflater.finish()
            val out = ByteArrayOutputStream(input.size / 2 + 64)
            val buf = ByteArray(8192)
            while (!deflater.finished()) {
                out.write(buf, 0, deflater.deflate(buf))
            }
            return out.toByteArray()
        } finally {
            deflater.end()
        }
    }

    private fun inflate(input: ByteArray, offset: Int, length: Int): ByteArray {
        val inflater = Inflater()
        try {
            inflater.setInput(input, offset, length)
            val out = ByteArrayOutputStream(length * 4)
            val buf = ByteArray(8192)
            while (!inflater.finished()) {
                val n = inflater.inflate(buf)
                if (n == 0 && (inflater.needsInput() || inflater.needsDictionary())) {
                    throw ProtocolException("Truncated compressed message")
                }
                out.write(buf, 0, n)
                if (out.size() > MAX_FRAME_SIZE) throw ProtocolException("Decompressed message too large")
            }
            return out.toByteArray()
        } catch (e: java.util.zip.DataFormatException) {
            throw ProtocolException("Invalid compressed message", e)
        } finally {
            inflater.end()
        }
    }

    private fun indexOf(bytes: ByteArray, value: Byte, from: Int): Int {
        for (i in from until bytes.size) if (bytes[i] == value) return i
        return -1
    }

    companion object {
        const val AES_TOKEN = "#AES:"
        /** `OS_MAXSTR - OS_HEADER_SIZE` */
        const val MAX_MESSAGE_SIZE = 65536 - 128
        const val MAX_FRAME_SIZE = 65536 + 4096

        /** md5(32) + random(5) + global(10) + ':' + local(4) + ':' */
        private const val HEADER_LENGTH = 53
        private const val TRANSFORMATION = "AES/CBC/PKCS5Padding"
        private val IV = "FEDCBA0987654321".toByteArray(Charsets.US_ASCII)
    }
}
