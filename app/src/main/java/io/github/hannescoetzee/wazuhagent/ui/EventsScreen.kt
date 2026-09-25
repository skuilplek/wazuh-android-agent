package io.github.hannescoetzee.wazuhagent.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.github.hannescoetzee.wazuhagent.queue.RecentEvent
import io.github.hannescoetzee.wazuhagent.ui.components.EventCard
import io.github.hannescoetzee.wazuhagent.ui.components.EventTypeIcon
import io.github.hannescoetzee.wazuhagent.ui.components.ScreenHeader
import io.github.hannescoetzee.wazuhagent.ui.components.StatusPill
import io.github.hannescoetzee.wazuhagent.ui.theme.AppIcons
import io.github.hannescoetzee.wazuhagent.ui.theme.WazuhThemeColors

@Composable
fun EventsScreen(events: List<RecentEvent>, onClear: () -> Unit) {
    var filter by rememberSaveable { mutableStateOf("") }
    var selectedType by rememberSaveable { mutableStateOf<String?>(null) }
    var frozen by remember { mutableStateOf<List<RecentEvent>?>(null) }
    val visible = frozen ?: events

    val types = remember(visible) {
        visible.groupingBy { it.type.ifEmpty { "unknown" } }.eachCount().entries.sortedByDescending { it.value }.map { it.key }
    }
    val needle = filter.trim()
    val shown = visible.filter { event ->
        (selectedType == null || event.type.ifEmpty { "unknown" } == selectedType) &&
            (needle.isEmpty() || event.type.contains(needle, ignoreCase = true) || event.message.contains(needle, ignoreCase = true))
    }

    Column(Modifier.fillMaxSize()) {
        ScreenHeader("Events") {
            IconButton(onClick = { frozen = if (frozen == null) events else null }) {
                if (frozen == null) {
                    Icon(AppIcons.Pause, contentDescription = "Pause")
                } else {
                    Icon(Icons.Filled.PlayArrow, contentDescription = "Resume")
                }
            }
            IconButton(onClick = {
                onClear()
                if (frozen != null) frozen = emptyList()
            }) {
                Icon(Icons.Filled.Delete, contentDescription = "Clear view")
            }
        }

        OutlinedTextField(
            value = filter,
            onValueChange = { filter = it },
            placeholder = { Text("Search events") },
            leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
            trailingIcon = {
                if (filter.isNotEmpty()) {
                    IconButton(onClick = { filter = "" }) { Icon(Icons.Filled.Close, contentDescription = "Clear search") }
                }
            },
            singleLine = true,
            shape = CircleShape,
            colors = OutlinedTextFieldDefaults.colors(
                unfocusedContainerColor = MaterialTheme.colorScheme.surfaceContainerLow,
                focusedContainerColor = MaterialTheme.colorScheme.surfaceContainerLow,
                unfocusedBorderColor = MaterialTheme.colorScheme.outlineVariant,
            ),
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
        )

        if (types.isNotEmpty()) {
            LazyRow(
                contentPadding = PaddingValues(horizontal = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.padding(top = 8.dp),
            ) {
                item {
                    FilterChip(selected = selectedType == null, onClick = { selectedType = null }, label = { Text("All") })
                }
                items(types, key = { it }) { type ->
                    FilterChip(
                        selected = selectedType == type,
                        onClick = { selectedType = if (selectedType == type) null else type },
                        label = { Text(type) },
                        leadingIcon = { EventTypeIcon(type, size = 18.dp) },
                    )
                }
            }
        }

        Box(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp)) {
            Text(
                "Showing ${shown.size} of ${visible.size} since the app started",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.align(Alignment.CenterStart),
            )
            if (frozen != null) {
                val status = WazuhThemeColors.status
                StatusPill(
                    "Paused",
                    status.warning,
                    status.warningContainer,
                    compact = true,
                    modifier = Modifier.align(Alignment.CenterEnd),
                )
            }
        }

        if (shown.isEmpty()) {
            EmptyEvents(if (visible.isEmpty()) "No events since the app started" else "No events match the filter")
        } else {
            LazyColumn(
                contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(shown, key = { it.id }) { EventCard(it) }
            }
        }
    }
}

@Composable
private fun EmptyEvents(message: String) {
    Column(
        Modifier.fillMaxWidth().padding(top = 48.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(
            AppIcons.VerifiedUser,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.outlineVariant,
            modifier = Modifier.size(56.dp),
        )
        Text(message, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodyMedium)
        Text(
            "Clear only empties this view, not the upload queue.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodySmall,
        )
    }
}
