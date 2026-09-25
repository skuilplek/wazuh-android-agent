package io.github.hannescoetzee.wazuhagent.ui.components

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import io.github.hannescoetzee.wazuhagent.queue.RecentEvent
import io.github.hannescoetzee.wazuhagent.ui.theme.AppIcons
import io.github.hannescoetzee.wazuhagent.ui.theme.WazuhBlue

enum class EventKind(val color: Color) {
    POSTURE(WazuhBlue),
    PACKAGE(Color(0xFF26A69A)),
    NETWORK(Color(0xFF7986CB)),
    SECURITY(Color(0xFFE57373)),
    DEVICE(Color(0xFFFFB300)),
    AGENT(Color(0xFF90A4AE)),
    OTHER(Color(0xFF90A4AE));

    val icon: ImageVector
        get() = when (this) {
            POSTURE -> AppIcons.VerifiedUser
            PACKAGE -> AppIcons.Apps
            NETWORK -> AppIcons.Public
            SECURITY -> AppIcons.Shield
            DEVICE -> Icons.Filled.Lock
            AGENT, OTHER -> Icons.Filled.Info
        }

    companion object {
        fun of(type: String): EventKind = when {
            type.startsWith("posture") -> POSTURE
            type.startsWith("package") -> PACKAGE
            type.startsWith("network") -> NETWORK
            type == "security_log" -> SECURITY
            type == "unlock" || type == "agent_admin" -> DEVICE
            type == "agent_log" -> AGENT
            else -> OTHER
        }
    }
}

@Composable
fun EventTypeIcon(type: String, modifier: Modifier = Modifier, size: Dp = 36.dp) {
    val kind = EventKind.of(type)
    Box(
        modifier = modifier.size(size).background(kind.color.copy(alpha = 0.16f), CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        Icon(kind.icon, contentDescription = null, tint = kind.color, modifier = Modifier.size(size / 2))
    }
}

/** One-line row for previews: icon, type, time and delivery state. */
@Composable
fun CompactEventRow(event: RecentEvent, onClick: () -> Unit, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        EventTypeIcon(event.type)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(
                event.type.ifEmpty { "unknown" },
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                formatTime(event.createdAt),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        SentBadge(event.sent)
    }
}

/** Expandable card for the events list: a field summary when collapsed, the full JSON when expanded. */
@Composable
fun EventCard(event: RecentEvent, modifier: Modifier = Modifier) {
    var expanded by rememberSaveable(event.id) { mutableStateOf(false) }
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = CardShape,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
        border = cardBorder(),
        onClick = { expanded = !expanded },
    ) {
        Column(
            Modifier.padding(12.dp).animateContentSize(),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                EventTypeIcon(event.type, size = 32.dp)
                Spacer(Modifier.width(10.dp))
                Text(
                    event.type.ifEmpty { "unknown" },
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    formatTime(event.createdAt),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.width(8.dp))
                SentBadge(event.sent)
            }
            if (expanded) {
                ExpandedJson(event)
            } else {
                Text(
                    remember(event.id) { summarizeEvent(event.message) },
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun ExpandedJson(event: RecentEvent) {
    val pretty = remember(event.id) { prettyJson(event.message) }
    val clipboard = LocalClipboardManager.current
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Surface(
            color = MaterialTheme.colorScheme.surfaceContainer,
            shape = RoundedCornerShape(10.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            SelectionContainer {
                Text(
                    pretty,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(12.dp),
                )
            }
        }
        TextButton(onClick = { clipboard.setText(AnnotatedString(pretty)) }) {
            Icon(AppIcons.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(Modifier.width(6.dp))
            Text("Copy JSON")
        }
    }
}
