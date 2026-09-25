package io.github.hannescoetzee.wazuhagent.ui.components

import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.runtime.produceState
import kotlinx.coroutines.delay
import org.json.JSONArray
import org.json.JSONObject
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Date

private val HIDDEN_SUMMARY_KEYS = setOf("type", "event_time", "app_version")

fun formatTime(millis: Long): String = DateFormat.getTimeInstance(DateFormat.MEDIUM).format(Date(millis))

fun formatCount(value: Number): String = NumberFormat.getIntegerInstance().format(value)

fun relativeTime(now: Long, then: Long): String {
    val seconds = ((now - then) / 1000).coerceAtLeast(0)
    return when {
        seconds < 5 -> "just now"
        seconds < 60 -> "${seconds}s ago"
        seconds < 3600 -> "${seconds / 60}m ago"
        seconds < 86_400 -> "${seconds / 3600}h ago"
        else -> DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(then))
    }
}

@Composable
fun rememberNow(intervalMillis: Long = 1_000): State<Long> = produceState(System.currentTimeMillis()) {
    while (true) {
        delay(intervalMillis)
        value = System.currentTimeMillis()
    }
}

/** The fields under `android` minus the envelope, as `key: value` pairs for a one-line preview. */
fun summarizeEvent(message: String): String = runCatching {
    val root = JSONObject(message)
    val body = root.optJSONObject("android") ?: root
    body.keys().asSequence()
        .filter { it !in HIDDEN_SUMMARY_KEYS }
        .take(4)
        .joinToString("  ·  ") { key ->
            when (val value = body.get(key)) {
                is JSONObject -> "$key: {…}"
                is JSONArray -> "$key: [${value.length()}]"
                else -> "$key: $value"
            }
        }
        .ifEmpty { message }
}.getOrDefault(message)

fun prettyJson(message: String): String = runCatching { JSONObject(message).toString(2) }.getOrDefault(message)
