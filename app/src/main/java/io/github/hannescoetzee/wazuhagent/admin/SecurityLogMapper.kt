package io.github.hannescoetzee.wazuhagent.admin

import android.annotation.SuppressLint
import android.app.admin.SecurityLog

/**
 * Picks the security log tags worth sending and names their payload fields. Keyguard tags
 * are left out because the device admin callbacks already report unlocks, and app process
 * starts are left out because every app launch logs one.
 */
// Tag constants are inlined ints, so newer tags are safe to compare on older releases.
@SuppressLint("InlinedApi")
object SecurityLogMapper {
    data class Mapped(val tag: String, val fields: Map<String, Any>)

    fun map(tag: Int, data: Any?): Mapped? {
        fun arg(i: Int): Any? = if (data is Array<*>) data.getOrNull(i) else if (i == 0) data else null
        fun str(i: Int): String = arg(i)?.toString().orEmpty()
        fun success(i: Int): Boolean = (arg(i) as? Number)?.toInt() == 1

        return when (tag) {
            SecurityLog.TAG_ADB_SHELL_INTERACTIVE -> Mapped("adb_shell_interactive", emptyMap())
            SecurityLog.TAG_ADB_SHELL_CMD -> Mapped("adb_shell_cmd", mapOf("command" to str(0)))
            SecurityLog.TAG_SYNC_RECV_FILE -> Mapped("adb_pull", mapOf("path" to str(0)))
            SecurityLog.TAG_SYNC_SEND_FILE -> Mapped("adb_push", mapOf("path" to str(0)))
            SecurityLog.TAG_OS_STARTUP -> Mapped("os_startup", mapOf("verified_boot_state" to str(0), "dm_verity_mode" to str(1)))
            SecurityLog.TAG_OS_SHUTDOWN -> Mapped("os_shutdown", emptyMap())
            SecurityLog.TAG_LOGGING_STARTED -> Mapped("logging_started", emptyMap())
            SecurityLog.TAG_LOGGING_STOPPED -> Mapped("logging_stopped", emptyMap())
            SecurityLog.TAG_LOG_BUFFER_SIZE_CRITICAL -> Mapped("log_buffer_size_critical", emptyMap())
            SecurityLog.TAG_MEDIA_MOUNT -> Mapped("media_mount", mapOf("mount_point" to str(0), "volume_label" to str(1)))
            SecurityLog.TAG_MEDIA_UNMOUNT -> Mapped("media_unmount", mapOf("mount_point" to str(0), "volume_label" to str(1)))
            SecurityLog.TAG_CERT_AUTHORITY_INSTALLED -> Mapped("cert_authority_installed", mapOf("success" to success(0), "subject" to str(1)))
            SecurityLog.TAG_CERT_AUTHORITY_REMOVED -> Mapped("cert_authority_removed", mapOf("success" to success(0), "subject" to str(1)))
            SecurityLog.TAG_CERT_VALIDATION_FAILURE -> Mapped("cert_validation_failure", mapOf("reason" to str(0)))
            SecurityLog.TAG_CRYPTO_SELF_TEST_COMPLETED -> Mapped("crypto_self_test_completed", mapOf("success" to success(0)))
            SecurityLog.TAG_KEY_INTEGRITY_VIOLATION -> Mapped("key_integrity_violation", mapOf("key_alias" to str(0), "uid" to str(1)))
            SecurityLog.TAG_WIPE_FAILURE -> Mapped("wipe_failure", emptyMap())
            SecurityLog.TAG_PASSWORD_CHANGED -> Mapped("password_changed", mapOf("user_id" to str(1)))
            else -> null
        }
    }
}
