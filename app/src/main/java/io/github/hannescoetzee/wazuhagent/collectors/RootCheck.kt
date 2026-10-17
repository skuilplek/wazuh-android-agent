package io.github.hannescoetzee.wazuhagent.collectors

import android.content.Context
import android.os.Build
import java.io.File
import java.util.concurrent.TimeUnit

/** Root indicators shared by posture reporting and the process collector. */
object RootCheck {
    fun indicators(context: Context): List<String> {
        val found = mutableListOf<String>()
        SU_PATHS.filter { File(it).exists() }.forEach { found += "su:$it" }
        if (Build.TAGS?.contains("test-keys") == true) found += "build:test-keys"
        if (readSystemProperty("ro.debuggable") == "1") found += "prop:ro.debuggable"
        if (readSystemProperty("ro.secure") == "0") found += "prop:ro.secure=0"
        val pm = context.packageManager
        ROOT_PACKAGES.filter { pkg ->
            runCatching { pm.getPackageInfo(pkg, 0); true }.getOrDefault(false)
        }.forEach { found += "package:$it" }
        return found
    }

    /** First `su` binary among the indicator paths. Directories such as `/data/adb/magisk` are skipped. */
    fun suBinary(): String? = SU_PATHS.firstOrNull { path -> File(path).isFile }

    private val SU_PATHS = listOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su", "/su/bin/su",
        "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su", "/system/sbin/su", "/vendor/bin/su",
        "/data/adb/magisk", "/data/adb/ksu",
    )
    private val ROOT_PACKAGES = listOf(
        "com.topjohnwu.magisk", "io.github.huskydg.magisk", "io.github.vvb2060.magisk",
        "me.weishu.kernelsu", "com.rifsxd.ksunext", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.noshufou.android.su", "com.kingroot.kinguser",
    )
}

internal fun readSystemProperty(name: String): String = runCatching {
    val process = ProcessBuilder("getprop", name).redirectErrorStream(true).start()
    val value = process.inputStream.bufferedReader().use { it.readText().trim() }
    if (!process.waitFor(2, TimeUnit.SECONDS)) process.destroyForcibly()
    value
}.getOrDefault("")
