package io.github.hannescoetzee.wazuhagent.collectors

import io.github.hannescoetzee.wazuhagent.DeviceInfo
import org.json.JSONArray
import org.json.JSONObject
import java.time.OffsetDateTime
import java.time.format.DateTimeFormatter

/**
 * Every event is `{"android": {"type": "...", ...}}` so manager rules can match on
 * `android.type` and the fields below it.
 */
object Events {
    fun build(type: String, fill: JSONObject.() -> Unit): JSONObject {
        val body = JSONObject()
            .put("type", type)
            .put("event_time", OffsetDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME))
            .put("app_version", DeviceInfo.appVersion)
        body.fill()
        return JSONObject().put("android", body)
    }

    fun array(values: Collection<String>): JSONArray = JSONArray().apply { values.forEach { put(it) } }
}
