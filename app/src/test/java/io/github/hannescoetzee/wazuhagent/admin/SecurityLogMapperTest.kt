package io.github.hannescoetzee.wazuhagent.admin

import android.app.admin.SecurityLog
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SecurityLogMapperTest {
    @Test
    fun adbShellCommandTakesTheCommandFromAPlainStringPayload() {
        val mapped = SecurityLogMapper.map(SecurityLog.TAG_ADB_SHELL_CMD, "pm list packages")
        assertEquals("adb_shell_cmd", mapped?.tag)
        assertEquals(mapOf("command" to "pm list packages"), mapped?.fields)
    }

    @Test
    fun certAuthorityInstalledReadsResultAndSubjectFromArrayPayload() {
        val mapped = SecurityLogMapper.map(SecurityLog.TAG_CERT_AUTHORITY_INSTALLED, arrayOf<Any>(1, "CN=Evil Proxy", 0))
        assertEquals("cert_authority_installed", mapped?.tag)
        assertEquals(mapOf("success" to true, "subject" to "CN=Evil Proxy"), mapped?.fields)
    }

    @Test
    fun failedCryptoSelfTestIsReportedAsUnsuccessful() {
        val mapped = SecurityLogMapper.map(SecurityLog.TAG_CRYPTO_SELF_TEST_COMPLETED, 0)
        assertEquals(mapOf("success" to false), mapped?.fields)
    }

    @Test
    fun missingPayloadFieldsBecomeEmptyStrings() {
        val mapped = SecurityLogMapper.map(SecurityLog.TAG_MEDIA_MOUNT, arrayOf<Any>("/mnt/media_rw/1234"))
        assertEquals(mapOf("mount_point" to "/mnt/media_rw/1234", "volume_label" to ""), mapped?.fields)
    }

    @Test
    fun noPayloadTagsHaveNoFields() {
        assertEquals(emptyMap<String, Any>(), SecurityLogMapper.map(SecurityLog.TAG_LOGGING_STOPPED, null)?.fields)
    }

    @Test
    fun keyguardAndProcessStartTagsAreSkipped() {
        assertNull(SecurityLogMapper.map(SecurityLog.TAG_KEYGUARD_DISMISS_AUTH_ATTEMPT, arrayOf<Any>(0, 1)))
        assertNull(SecurityLogMapper.map(SecurityLog.TAG_APP_PROCESS_START, arrayOf<Any>("com.example", 0L, 10001, 123, "", "")))
    }
}
