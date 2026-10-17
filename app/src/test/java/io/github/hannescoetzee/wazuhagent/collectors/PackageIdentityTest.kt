package io.github.hannescoetzee.wazuhagent.collectors

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.File

class PackageIdentityTest {
    @Test
    fun sha256OfAbcMatchesTheKnownDigest() {
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            sha256Hex("abc".toByteArray()),
        )
    }

    @Test
    fun fileDigestMatchesTheByteDigest() {
        val file = File.createTempFile("apk", ".bin")
        try {
            file.writeBytes("abc".toByteArray())
            assertEquals(sha256Hex("abc".toByteArray()), sha256File(file.path))
        } finally {
            file.delete()
        }
    }

    @Test
    fun missingFileHasNoDigest() {
        assertNull(sha256File("/no/such/apk.apk"))
        assertNull(sha256File(null))
    }

    @Test
    fun currentSignerIsTheLastHistoryEntry() {
        assertEquals("new", currentSigner(listOf("old", "new"), multipleSigners = false))
    }

    @Test
    fun apkHashIsReportedOncePerProcessUntilItChanges() {
        val known = mutableMapOf<String, String>()
        val hash = "ab".repeat(32)
        val next = "cd".repeat(32)
        assertEquals(true, rememberApkHash(known, "com.example", hash))
        assertEquals(false, rememberApkHash(known, "com.example", hash))
        assertEquals(true, rememberApkHash(known, "com.example", next))
        assertEquals(false, rememberApkHash(known, "", hash))
        assertEquals(false, rememberApkHash(known, "com.example", ""))
    }

    @Test
    fun multipleSignersUseTheFirstCertificate() {
        assertEquals("one", currentSigner(listOf("one", "two"), multipleSigners = true))
        assertNull(currentSigner(emptyList(), multipleSigners = false))
    }
}
