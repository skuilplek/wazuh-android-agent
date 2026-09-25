package io.github.hannescoetzee.wazuhagent.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import io.github.hannescoetzee.wazuhagent.DeviceInfo
import io.github.hannescoetzee.wazuhagent.collectors.Capabilities
import io.github.hannescoetzee.wazuhagent.collectors.Capability
import io.github.hannescoetzee.wazuhagent.service.AgentStatus
import io.github.hannescoetzee.wazuhagent.service.ConnectionState
import java.text.DateFormat
import java.util.Date

@Composable
fun SetupScreen(
    ui: UiState,
    status: AgentStatus,
    queueSize: Int,
    capabilities: List<Capability>,
    onFormChange: ((SetupForm) -> SetupForm) -> Unit,
    onEnroll: () -> Unit,
    onSave: () -> Unit,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onForget: () -> Unit,
    onRequestNotifications: () -> Unit,
    onRequestBattery: () -> Unit,
    onRequestLocation: () -> Unit,
    onRequestDeviceAdmin: () -> Unit,
) {
    val byName = capabilities.associateBy { it.name }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Column {
            Text("Wazuh Android Agent", style = MaterialTheme.typography.headlineSmall)
            Text(
                "Version ${DeviceInfo.appVersion}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        StatusCard(ui, status, queueSize, onStart, onStop)

        ui.message?.let {
            Text(
                it,
                color = if (ui.isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Manager", style = MaterialTheme.typography.titleMedium)
                val form = ui.form
                OutlinedTextField(
                    value = form.host, onValueChange = { v -> onFormChange { it.copy(host = v) } },
                    label = { Text("Manager address") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = form.enrollPort, onValueChange = { v -> onFormChange { it.copy(enrollPort = v) } },
                        label = { Text("Enroll port") }, singleLine = true, modifier = Modifier.weight(1f),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    )
                    OutlinedTextField(
                        value = form.port, onValueChange = { v -> onFormChange { it.copy(port = v) } },
                        label = { Text("Agent port") }, singleLine = true, modifier = Modifier.weight(1f),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    )
                }
                OutlinedTextField(
                    value = form.password, onValueChange = { v -> onFormChange { it.copy(password = v) } },
                    label = { Text("Enrollment password (optional)") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                )
                OutlinedTextField(
                    value = form.agentName, onValueChange = { v -> onFormChange { it.copy(agentName = v) } },
                    label = { Text("Agent name") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = form.groups, onValueChange = { v -> onFormChange { it.copy(groups = v) } },
                    label = { Text("Groups (optional, must exist on manager)") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = form.keepaliveSeconds, onValueChange = { v -> onFormChange { it.copy(keepaliveSeconds = v) } },
                    label = { Text("Keepalive (seconds)") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = onEnroll, enabled = !ui.busy) {
                        Text(if (ui.enrollment == null) "Enroll" else "Re-enroll")
                    }
                    OutlinedButton(onClick = onSave, enabled = !ui.busy) { Text("Save") }
                }
            }
        }

        ui.enrollment?.let { info ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Enrollment", style = MaterialTheme.typography.titleMedium)
                    Text("Agent ${info.agentId} · ${info.agentName}")
                    Text("Wazuh protocol version: ${info.agentVersion ?: "default"}")
                    info.certSha256?.let {
                        Text("Pinned manager certificate (SHA-256):", style = MaterialTheme.typography.labelMedium)
                        Text(it.chunked(2).joinToString(":"), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                    }
                    TextButton(onClick = onForget) { Text("Forget enrollment") }
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Permissions", style = MaterialTheme.typography.titleMedium)
                byName[Capabilities.NOTIFICATIONS]?.let { PermissionRow(it, onRequestNotifications) }
                byName[Capabilities.BATTERY_UNRESTRICTED]?.let { PermissionRow(it, onRequestBattery) }
                byName[Capabilities.LOCATION]?.let { PermissionRow(it, onRequestLocation) }
                byName[Capabilities.DEVICE_ADMIN]?.let { PermissionRow(it, onRequestDeviceAdmin) }
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Capabilities", style = MaterialTheme.typography.titleMedium)
                listOf(Capabilities.DEVICE_OWNER, Capabilities.SECURITY_LOGGING, Capabilities.NETWORK_LOGGING)
                    .mapNotNull { byName[it] }
                    .forEach { CapabilityRow(it) }
            }
        }
    }
}

@Composable
private fun CapabilityRow(capability: Capability) {
    Column {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(capability.label, modifier = Modifier.weight(1f))
            Text(
                if (capability.available) "Available" else "Limited",
                color = if (capability.available) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (!capability.available) {
            Text(capability.reason, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun StatusCard(ui: UiState, status: AgentStatus, queueSize: Int, onStart: () -> Unit, onStop: () -> Unit) {
    val color = when (status.state) {
        ConnectionState.CONNECTED -> MaterialTheme.colorScheme.primaryContainer
        ConnectionState.WAITING_RETRY -> MaterialTheme.colorScheme.errorContainer
        else -> MaterialTheme.colorScheme.surfaceVariant
    }
    Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = color)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(status.state.name.replace('_', ' '), style = MaterialTheme.typography.titleMedium)
            if (status.detail.isNotEmpty()) Text(status.detail, style = MaterialTheme.typography.bodySmall)
            if (status.lastAckAt > 0) {
                Text("Last manager ack: ${DateFormat.getTimeInstance().format(Date(status.lastAckAt))}")
            }
            Text("Queued events: $queueSize · sent this session: ${status.eventsSent}")
            if (ui.enrollment != null) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (ui.agentEnabled) {
                        OutlinedButton(onClick = onStop) { Text("Stop agent") }
                    } else {
                        Button(onClick = onStart) { Text("Start agent") }
                    }
                }
            }
        }
    }
}

@Composable
private fun PermissionRow(capability: Capability, onRequest: () -> Unit) {
    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(capability.label, modifier = Modifier.weight(1f).padding(top = 12.dp))
            if (capability.available) {
                Text("Granted", color = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(top = 12.dp))
            } else {
                TextButton(onClick = onRequest) { Text("Allow") }
            }
        }
        if (!capability.available) {
            Text(capability.reason, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
