package io.github.hannescoetzee.wazuhagent.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Base64

/**
 * Vectors were produced with Python hashlib/zlib and the `openssl enc -aes-256-cbc` CLI,
 * following `OS_AddKey()` and `CreateSecMSG()` from the wazuh C sources.
 */
class MessageCodecTest {
    private val key = AgentKey(
        "001", "pixel-8", "any",
        "0f8a3c9e5b1d2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a",
    )

    @Test
    fun encryptionKeyMatchesWazuhDerivation() {
        assertEquals("dc009bcd91fdedde21b47fbfc0c537782f1c242bc1a3082", KeyDerivation.encryptionKey(key))
        assertArrayEquals("dc009bcd91fdedde21b47fbfc0c53778".toByteArray(), KeyDerivation.aesKey(key))
    }

    @Test
    fun decodesFrameProducedByReferenceImplementation() {
        val frame = Base64.getDecoder().decode(
            "I0FFUzqpqkZ0wBLb5wnKrvPLXWKPeeIY4FMDWsnOEPRZ0p0osqT9tAoRkAAAU4KEY7J8nCzmoBb2XfKfOOrEAMLkv/svBHrZ3Gh7/FmTTpSoMNLDBA==",
        )
        val decoded = MessageCodec(key).decode(frame)
        assertEquals("#!-agent ack ", decoded.text)
        assertEquals(5L, decoded.global)
        assertEquals(12, decoded.local)
    }

    @Test
    fun encodeRoundTripsAndUsesDynamicIdHeader() {
        val codec = MessageCodec(key)
        val encoded = codec.encode("1:android:{\"android\":{\"type\":\"test\"}}", CounterValue(3, 9))
        assertTrue(String(encoded, 0, 10, Charsets.US_ASCII).startsWith("!001!#AES:"))

        val decoded = codec.decode(encoded)
        assertEquals("1:android:{\"android\":{\"type\":\"test\"}}", decoded.text)
        assertEquals(3L, decoded.global)
        assertEquals(9, decoded.local)
    }

    @Test
    fun staticIpKeysOmitIdHeader() {
        val staticKey = AgentKey("002", "phone", "192.168.1.20", "abc123")
        assertFalse(staticKey.isDynamicIp)
        val encoded = MessageCodec(staticKey).encode("hello", CounterValue(0, 1))
        assertEquals("#AES:", String(encoded, 0, 5, Charsets.US_ASCII))
        assertTrue(AgentKey("003", "phone", "10.0.0.0/24", "abc").isDynamicIp)
    }

    @Test(expected = ProtocolException::class)
    fun wrongKeyFailsToDecode() {
        val encoded = MessageCodec(key).encode("secret", CounterValue(0, 1))
        MessageCodec(AgentKey("001", "pixel-8", "any", "other")).decode(encoded)
    }

    @Test
    fun counterRollsOverLikeWazuh() {
        val store = InMemoryCounterStore()
        val counter = SenderCounter(store)
        assertEquals(CounterValue(0, 1), counter.next())
        repeat(9995) { counter.next() }
        assertEquals(CounterValue(0, 9997), counter.next())
        assertEquals(CounterValue(1, 1), counter.next())
        assertEquals(CounterValue(1, 1), store.load())
    }

    @Test
    fun restartedCounterSkipsAheadOfUnsavedMessages() {
        val store = InMemoryCounterStore(CounterValue(7, 42))
        assertEquals(CounterValue(8, 1), SenderCounter(store).next())
    }

    @Test
    fun framingIsLittleEndianLengthPrefixed() {
        val out = ByteArrayOutputStream()
        TcpFraming.write(out, ByteArray(300) { 1 })
        val bytes = out.toByteArray()
        assertArrayEquals(byteArrayOf(0x2c, 0x01, 0, 0), bytes.copyOf(4))
        assertEquals(300, TcpFraming.read(ByteArrayInputStream(bytes))!!.size)
        assertEquals(null, TcpFraming.read(ByteArrayInputStream(ByteArray(0))))
    }
}
