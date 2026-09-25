package io.github.hannescoetzee.wazuhagent.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.github.hannescoetzee.wazuhagent.DeviceInfo
import io.github.hannescoetzee.wazuhagent.collectors.Capabilities
import io.github.hannescoetzee.wazuhagent.collectors.Capability
import io.github.hannescoetzee.wazuhagent.ui.components.ScreenHeader
import io.github.hannescoetzee.wazuhagent.ui.components.SectionCard
import io.github.hannescoetzee.wazuhagent.ui.theme.WazuhThemeColors

private val DEVICE_OWNER_CAPABILITIES = listOf(
    Capabilities.DEVICE_OWNER,
    Capabilities.SECURITY_LOGGING,
    Capabilities.NETWORK_LOGGING,
)

@Composable
fun SettingsScreen(
    ui: UiState,
    capabilities: List<Capability>,
    permissions: PermissionActions,
    onFormChange: ((SetupForm) -> SetupForm) -> Unit,
    onEnroll: () -> Unit,
    onSave: () -> Unit,
    onForget: () -> Unit,
) {
    val byName = capabilities.associateBy { it.name }
    Column(Modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState())) {
        ScreenHeader("Settings")
        Column(
            Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            ManagerCard(ui, onFormChange, onEnroll, onSave)
            ui.enrollment?.let { EnrollmentCard(it, onForget) }

            SectionCard(title = "Permissions") {
                PermissionActions.GRANTABLE.mapNotNull { byName[it] }.forEachIndexed { index, capability ->
                    if (index > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    PermissionRow(capability, permissions.forCapability(capability.name))
                }
            }

            SectionCard(title = "Device Owner features") {
                Text(
                    "Security and network logs need the app provisioned as Device Owner on a factory-reset phone.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                DEVICE_OWNER_CAPABILITIES.mapNotNull { byName[it] }.forEachIndexed { index, capability ->
                    if (index > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    PermissionRow(capability, onRequest = null)
                }
            }

            Text(
                "Wazuh Android Agent ${DeviceInfo.appVersion}",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
            )
        }
    }
}

@Composable
private fun ManagerCard(
    ui: UiState,
    onFormChange: ((SetupForm) -> SetupForm) -> Unit,
    onEnroll: () -> Unit,
    onSave: () -> Unit,
) {
    val form = ui.form
    var showPassword by rememberSaveable { mutableStateOf(false) }
    SectionCard(title = "Manager connection") {
        if (ui.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        OutlinedTextField(
            value = form.host, onValueChange = { v -> onFormChange { it.copy(host = v) } },
            label = { Text("Manager address") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
            placeholder = { Text("wazuh.example.com") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
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
            visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
            trailingIcon = {
                if (form.password.isNotEmpty()) {
                    TextButton(onClick = { showPassword = !showPassword }) { Text(if (showPassword) "Hide" else "Show") }
                }
            },
            modifier = Modifier.fillMaxWidth(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        )
        OutlinedTextField(
            value = form.agentName, onValueChange = { v -> onFormChange { it.copy(agentName = v) } },
            label = { Text("Agent name") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedTextField(
                value = form.groups, onValueChange = { v -> onFormChange { it.copy(groups = v) } },
                label = { Text("Groups") }, singleLine = true, modifier = Modifier.weight(2f),
                supportingText = { Text("Must exist on the manager") },
            )
            OutlinedTextField(
                value = form.keepaliveSeconds, onValueChange = { v -> onFormChange { it.copy(keepaliveSeconds = v) } },
                label = { Text("Keepalive") }, singleLine = true, modifier = Modifier.weight(1f),
                suffix = { Text("s") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = onEnroll, enabled = !ui.busy, modifier = Modifier.weight(1f).height(48.dp)) {
                Text(if (ui.enrollment == null) "Enroll" else "Re-enroll")
            }
            OutlinedButton(onClick = onSave, enabled = !ui.busy, modifier = Modifier.weight(1f).height(48.dp)) {
                Text("Save")
            }
        }
    }
}

@Composable
private fun EnrollmentCard(info: EnrollmentInfo, onForget: () -> Unit) {
    var confirming by rememberSaveable { mutableStateOf(false) }
    SectionCard(title = "Enrollment", icon = Icons.Filled.Lock) {
        LabeledValue("Agent", "${info.agentId} · ${info.agentName}")
        LabeledValue("Wazuh protocol version", info.agentVersion ?: "default")
        info.certSha256?.let {
            LabeledValue("Pinned manager certificate (SHA-256)", it.chunked(2).joinToString(":"), monospace = true)
        }
        TextButton(
            onClick = { confirming = true },
            colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
        ) { Text("Forget enrollment") }
    }
    if (confirming) {
        AlertDialog(
            onDismissRequest = { confirming = false },
            title = { Text("Forget enrollment?") },
            text = {
                Text(
                    "This deletes the agent key and any queued events from this phone. " +
                        "Also remove agent ${info.agentId} on the manager to free the name ${info.agentName}.",
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirming = false
                        onForget()
                    },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                ) { Text("Forget") }
            },
            dismissButton = { TextButton(onClick = { confirming = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun LabeledValue(label: String, value: String, monospace: Boolean = false) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(
            value,
            style = if (monospace) MaterialTheme.typography.bodySmall else MaterialTheme.typography.bodyLarge,
            fontFamily = if (monospace) FontFamily.Monospace else null,
        )
    }
}

/** A capability with its state; [onRequest] adds an Allow button when the user can grant it. */
@Composable
private fun PermissionRow(capability: Capability, onRequest: (() -> Unit)?) {
    val status = WazuhThemeColors.status
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Icon(
            PermissionActions.icon(capability.name),
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(20.dp),
        )
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(capability.label, style = MaterialTheme.typography.bodyMedium)
            if (!capability.available) {
                Text(capability.reason, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Spacer(Modifier.width(8.dp))
        when {
            capability.available -> Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.CheckCircle, contentDescription = null, tint = status.success, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(4.dp))
                Text(
                    if (onRequest != null) "Granted" else "Active",
                    style = MaterialTheme.typography.labelLarge,
                    color = status.success,
                )
            }
            onRequest != null -> FilledTonalButton(onClick = onRequest) { Text("Allow") }
            else -> Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.Info, contentDescription = null, tint = status.neutral, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(4.dp))
                Text("Limited", style = MaterialTheme.typography.labelLarge, color = status.neutral)
            }
        }
    }
}
