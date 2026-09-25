package io.github.hannescoetzee.wazuhagent.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.hannescoetzee.wazuhagent.DeviceInfo
import io.github.hannescoetzee.wazuhagent.collectors.Capability
import io.github.hannescoetzee.wazuhagent.queue.RecentEvent
import io.github.hannescoetzee.wazuhagent.service.AgentStatus
import io.github.hannescoetzee.wazuhagent.service.ConnectionState
import io.github.hannescoetzee.wazuhagent.ui.components.CardShape
import io.github.hannescoetzee.wazuhagent.ui.components.CompactEventRow
import io.github.hannescoetzee.wazuhagent.ui.components.ScreenHeader
import io.github.hannescoetzee.wazuhagent.ui.components.SectionCard
import io.github.hannescoetzee.wazuhagent.ui.components.StatTile
import io.github.hannescoetzee.wazuhagent.ui.components.StatusPill
import io.github.hannescoetzee.wazuhagent.ui.components.formatCount
import io.github.hannescoetzee.wazuhagent.ui.components.relativeTime
import io.github.hannescoetzee.wazuhagent.ui.components.rememberNow
import io.github.hannescoetzee.wazuhagent.ui.theme.AppIcons
import io.github.hannescoetzee.wazuhagent.ui.theme.WazuhThemeColors

private const val PREVIEW_EVENTS = 5

@Composable
fun StatusScreen(
    ui: UiState,
    status: AgentStatus,
    queueSize: Int,
    capabilities: List<Capability>,
    events: List<RecentEvent>,
    permissions: PermissionActions,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onOpenEvents: () -> Unit,
    onOpenSettings: () -> Unit,
) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        ScreenHeader("Wazuh Agent", icon = AppIcons.Shield, trailingLabel = "v${DeviceInfo.appVersion}")
        Column(
            Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            HeroCard(ui, status, onOpenSettings)

            if (ui.enrollment != null) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    StatTile("Queued", formatCount(queueSize), Modifier.weight(1f), caption = "waiting to send")
                    StatTile("Sent", formatCount(status.eventsSent), Modifier.weight(1f), caption = "this session")
                }
                if (ui.agentEnabled) {
                    OutlinedButton(onClick = onStop, modifier = Modifier.fillMaxWidth().height(48.dp)) {
                        Icon(AppIcons.Stop, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Stop agent")
                    }
                } else {
                    Button(onClick = onStart, modifier = Modifier.fillMaxWidth().height(48.dp)) {
                        Icon(Icons.Filled.PlayArrow, contentDescription = null, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Start agent")
                    }
                }
            }

            AttentionCard(capabilities.missingGrantable(), permissions)

            SectionCard(
                title = "Recent events",
                action = {
                    TextButton(onClick = onOpenEvents) {
                        Text("See all")
                        Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null, modifier = Modifier.size(18.dp))
                    }
                },
            ) {
                if (events.isEmpty()) {
                    Text(
                        "No events since the app started",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    Column {
                        events.take(PREVIEW_EVENTS).forEachIndexed { index, event ->
                            if (index > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                            CompactEventRow(event, onClick = onOpenEvents)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun HeroCard(ui: UiState, status: AgentStatus, onOpenSettings: () -> Unit) {
    val onHero = Color.White
    val muted = Color(0xFFB9C9DD)
    Box(
        Modifier
            .fillMaxWidth()
            .clip(CardShape)
            .background(WazuhThemeColors.status.hero)
            .padding(20.dp),
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            val enrollment = ui.enrollment
            if (enrollment == null) {
                StatusPill("Not enrolled", Color(0xFFFFC266), Color(0x33FFC266))
                Spacer(Modifier.height(4.dp))
                Text("Connect to your manager", style = MaterialTheme.typography.headlineSmall, color = onHero)
                Text(
                    "Enter the manager address in Settings and enroll this phone to start reporting.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = muted,
                )
                Spacer(Modifier.height(4.dp))
                Button(
                    onClick = onOpenSettings,
                    colors = ButtonDefaults.buttonColors(containerColor = onHero, contentColor = MaterialTheme.colorScheme.primary),
                ) { Text("Set up connection") }
                return@Column
            }

            val (label, dot) = when (status.state) {
                ConnectionState.CONNECTED -> "Connected" to Color(0xFF5DD68A)
                ConnectionState.CONNECTING -> "Connecting" to Color(0xFF7DBBF7)
                ConnectionState.WAITING_RETRY -> "Retrying" to Color(0xFFFFC266)
                ConnectionState.STOPPED -> "Stopped" to muted
            }
            StatusPill(label, dot, dot.copy(alpha = 0.18f))
            Spacer(Modifier.height(4.dp))
            Text(
                "Agent ${enrollment.agentId} · ${enrollment.agentName}",
                style = MaterialTheme.typography.headlineSmall,
                color = onHero,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (ui.form.host.isNotEmpty()) {
                Text(
                    "${ui.form.host}:${ui.form.port}",
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodyMedium,
                    color = muted,
                )
            }
            if (status.lastAckAt > 0) {
                val now by rememberNow()
                Text("Last ack ${relativeTime(now, status.lastAckAt)}", style = MaterialTheme.typography.bodyMedium, color = muted)
            }
            if (status.detail.isNotEmpty()) {
                Text(status.detail, style = MaterialTheme.typography.bodySmall, color = muted)
            }
        }
    }
}

@Composable
private fun AttentionCard(missing: List<Capability>, permissions: PermissionActions) {
    if (missing.isEmpty()) return
    val colors = WazuhThemeColors.status
    SectionCard(
        title = "Needs attention",
        icon = Icons.Filled.Warning,
        iconTint = colors.warning,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            missing.forEach { capability ->
                val onAllow = permissions.forCapability(capability.name)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(MaterialTheme.shapes.medium)
                        .background(colors.warningContainer)
                        .then(if (onAllow != null) Modifier.clickable(onClick = onAllow) else Modifier)
                        .padding(horizontal = 12.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Box(
                        Modifier.size(32.dp).background(colors.warning.copy(alpha = 0.18f), CircleShape),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            PermissionActions.icon(capability.name),
                            contentDescription = null,
                            tint = colors.warning,
                            modifier = Modifier.size(18.dp),
                        )
                    }
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(capability.label, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(
                            capability.reason,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    if (onAllow != null) {
                        Spacer(Modifier.width(8.dp))
                        Text("Allow", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                    }
                }
            }
        }
    }
}
