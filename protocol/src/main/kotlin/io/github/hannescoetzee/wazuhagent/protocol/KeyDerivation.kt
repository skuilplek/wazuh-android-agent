package io.github.hannescoetzee.wazuhagent.protocol

/**
 * Same derivation as `OS_AddKey()` in `src/os_crypto/shared/keys.c`.
 */
object KeyDerivation {
    /** The 47-character string wazuh stores as `encryption_key`. */
    fun encryptionKey(key: AgentKey): String {
        val nameIdSum = Hashing.md5Hex(Hashing.md5Hex(key.name) + Hashing.md5Hex(key.id)).substring(0, 15)
        return Hashing.md5Hex(key.key) + nameIdSum
    }

    /** `EVP_aes_256_cbc` only reads the first 32 bytes of `encryption_key`. */
    fun aesKey(key: AgentKey): ByteArray =
        encryptionKey(key).toByteArray(Charsets.US_ASCII).copyOf(32)
}
