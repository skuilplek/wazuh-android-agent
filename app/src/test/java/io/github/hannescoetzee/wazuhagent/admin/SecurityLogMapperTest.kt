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
    fun keyguardTagsAreSkipped() {
        assertNull(SecurityLogMapper.map(SecurityLog.TAG_KEYGUARD_DISMISS_AUTH_ATTEMPT, arrayOf<Any>(0, 1)))
    }

    @Test
    fun processStartKeepsTheProcessNameAndApkHash() {
        val hash = "ab".repeat(32)
        val mapped = SecurityLogMapper.map(
            SecurityLog.TAG_APP_PROCESS_START,
            arrayOf<Any>("com.example.app", 0L, 10001, 123, "untrusted", hash.uppercase()),
        )
        assertEquals("app_apk_hash", mapped?.tag)
        assertEquals(mapOf("process" to "com.example.app", "apk_sha256" to hash), mapped?.fields)
    }

    @Test
    fun keyImportReadsSuccessAliasAndUid() {
        val mapped = SecurityLogMapper.map(SecurityLog.TAG_KEY_IMPORT, arrayOf<Any>(1, "vpn", 10123))
        assertEquals(mapOf("success" to true, "key_alias" to "vpn", "uid" to "10123"), mapped?.fields)
    }

    @Test
    fun backupToggleReadsWhetherTheServiceIsEnabled() {
        val mapped = SecurityLogMapper.map(SecurityLog.TAG_BACKUP_SERVICE_TOGGLED, arrayOf<Any>("com.admin", 0, 0))
        assertEquals("backup_service_toggled", mapped?.tag)
        assertEquals(false, mapped?.fields?.get("enabled"))
    }

    @Test
    fun bluetoothConnectionReadsAddressAndResult() {
        val mapped = SecurityLogMapper.map(
            SecurityLog.TAG_BLUETOOTH_CONNECTION,
            arrayOf<Any>("00:11:22:33:44:55", 0, "timeout"),
        )
        assertEquals(
            mapOf("address" to "00:11:22:33:44:55", "success" to false, "reason" to "timeout"),
            mapped?.fields,
        )
    }

    @Test
    fun packageInstallReadsNameAndVersion() {
        val mapped = SecurityLogMapper.map(SecurityLog.TAG_PACKAGE_INSTALLED, arrayOf<Any>("com.example.tool", 12L, 0))
        assertEquals("package_installed", mapped?.tag)
        assertEquals("com.example.tool", mapped?.fields?.get("package"))
        assertEquals(12L, mapped?.fields?.get("version_code"))
    }
}
