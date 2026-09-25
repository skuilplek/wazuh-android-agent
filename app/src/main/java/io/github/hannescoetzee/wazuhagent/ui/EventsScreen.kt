package io.github.hannescoetzee.wazuhagent.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.hannescoetzee.wazuhagent.queue.RecentEvent
import org.json.JSONObject
import java.text.DateFormat
import java.util.Date

@Composable
fun EventsScreen(
    events: List<RecentEvent>,
    onBack: () -> Unit,
    onClear: () -> Unit,
) {
    var filter by rememberSaveable { mutableStateOf("") }
    var frozen by remember { mutableStateOf<List<RecentEvent>?>(null) }
    val visible = frozen ?: events
    val needle = filter.trim()
    val shown = if (needle.isEmpty()) {
        visible
    } else {
        visible.filter { it.type.contains(needle, ignoreCase = true) || it.message.contains(needle, ignoreCase = true) }
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("Back") }
            Text("Recent events", style = MaterialTheme.typography.headlineSmall)
        }
        Text(
            "Showing ${shown.size} of ${visible.size} events since the app started. Clear only empties this view, not the queue.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedTextField(
            value = filter, onValueChange = { filter = it },
            label = { Text("Filter") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { frozen = if (frozen == null) events else null }) {
                Text(if (frozen == null) "Pause" else "Resume")
            }
            OutlinedButton(onClick = {
                onClear()
                if (frozen != null) frozen = emptyList()
            }) { Text("Clear") }
        }

        if (shown.isEmpty()) {
            Box(Modifier.fillMaxWidth().padding(top = 24.dp), contentAlignment = Alignment.Center) {
                Text(
                    if (visible.isEmpty()) "No events since the app started" else "No events match the filter",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(shown, key = { it.id }) { EventRow(it) }
            }
        }
    }
}

@Composable
private fun EventRow(event: RecentEvent) {
    var expanded by rememberSaveable(event.id) { mutableStateOf(false) }
    Card(modifier = Modifier.fillMaxWidth().clickable { expanded = !expanded }) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(
                    "${DateFormat.getTimeInstance().format(Date(event.createdAt))}  ${event.type.ifEmpty { "unknown" }}",
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    if (event.sent) "Sent" else "Queued",
                    color = if (event.sent) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.labelMedium,
                )
            }
            if (expanded) {
                SelectionContainer {
                    Text(
                        remember(event.id) { prettyJson(event.message) },
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            } else {
                Text(
                    event.message,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

private fun prettyJson(message: String): String = runCatching { JSONObject(message).toString(2) }.getOrDefault(message)
