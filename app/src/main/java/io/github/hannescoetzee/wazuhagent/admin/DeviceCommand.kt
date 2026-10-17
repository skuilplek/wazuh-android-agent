package io.github.hannescoetzee.wazuhagent.admin

import org.json.JSONObject

/** Commands the Device Owner handler will run. Anything else from `#!-execd` is ignored. */
internal val DEVICE_COMMANDS = setOf(
    "android-suspend",
    "android-unsuspend",
    "android-hide",
    "android-unhide",
    "android-clear",
    "android-uninstall",
    "android-lock",
    "android-locate",
    "android-wipe",
)

internal const val WIPE_CONFIRM = "confirm-wipe"

internal const val DEFAULT_LOCK_MESSAGE = "This device is locked. Contact your administrator."

internal data class ExecRequest(
    val command: String,
    val extraArgs: List<String>,
    val alert: JSONObject?,
)

/** `android-lock0` is the Wazuh timeout suffix on `android-lock`. Other commands stay unchanged. */
internal fun canonicalCommand(raw: String): String {
    val stripped = raw.replace(Regex("\\d+$"), "")
    return if (stripped in DEVICE_COMMANDS) stripped else raw
}

internal fun parseExec(payload: String): ExecRequest? {
    val json = runCatching { JSONObject(payload) }.getOrNull() ?: return null
    val command = json.optString("command")
    if (command.isEmpty()) return null
    val parameters = json.optJSONObject("parameters")
    val argsJson = parameters?.optJSONArray("extra_args")
    val extraArgs = buildList {
        if (argsJson != null) {
            for (index in 0 until argsJson.length()) {
                val value = argsJson.optString(index)
                if (value.isNotEmpty()) add(value)
            }
        }
    }
    return ExecRequest(canonicalCommand(command), extraArgs, parameters?.optJSONObject("alert"))
}

internal fun isPackageName(value: String): Boolean =
    value.matches(Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$"))

/** Package from the command arguments, then from the Wazuh alert that triggered it. */
internal fun packageNameFrom(extraArgs: List<String>, alert: JSONObject?): String? {
    extraArgs.firstOrNull { isPackageName(it) }?.let { return it }
    val data = alert?.optJSONObject("data")
    val nested = data?.optJSONObject("android")?.optString("package").orEmpty()
    if (isPackageName(nested)) return nested
    val flat = data?.optString("package").orEmpty()
    if (isPackageName(flat)) return flat
    val full = alert?.optString("full_log").orEmpty()
    if (!full.startsWith("{")) return null
    val fromLog = runCatching { JSONObject(full).optJSONObject("android")?.optString("package") }.getOrNull().orEmpty()
    return fromLog.takeIf { isPackageName(it) }
}

internal fun lockMessage(extraArgs: List<String>): String {
    val text = extraArgs.filter { it != WIPE_CONFIRM && !isPackageName(it) }.joinToString(" ").trim()
    return text.ifEmpty { DEFAULT_LOCK_MESSAGE }.take(200)
}

internal fun orgPolicyRequested(value: String): Boolean =
    value.equals("true", ignoreCase = true) || value.equals("yes", ignoreCase = true) || value == "1"
