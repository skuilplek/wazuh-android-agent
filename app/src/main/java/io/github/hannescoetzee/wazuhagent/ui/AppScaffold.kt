package io.github.hannescoetzee.wazuhagent.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Snackbar
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.hannescoetzee.wazuhagent.collectors.Capability
import io.github.hannescoetzee.wazuhagent.ui.theme.AppIcons

enum class Tab(val label: String) {
    STATUS("Status"),
    EVENTS("Events"),
    SETTINGS("Settings");

    val icon: ImageVector
        get() = when (this) {
            STATUS -> AppIcons.VerifiedUser
            EVENTS -> Icons.AutoMirrored.Filled.List
            SETTINGS -> Icons.Filled.Settings
        }
}

@Composable
fun AppScaffold(viewModel: MainViewModel, capabilities: List<Capability>, permissions: PermissionActions) {
    val ui by viewModel.ui.collectAsStateWithLifecycle()
    val status by viewModel.status.collectAsStateWithLifecycle()
    val queueSize by viewModel.queueSize.collectAsStateWithLifecycle()
    val events by viewModel.recentEvents.collectAsStateWithLifecycle()

    var tab by rememberSaveable { mutableStateOf<Tab?>(null) }
    LaunchedEffect(ui.loaded) {
        if (ui.loaded && tab == null) tab = if (ui.enrollment == null) Tab.SETTINGS else Tab.STATUS
    }
    BackHandler(tab != null && tab != Tab.STATUS) { tab = Tab.STATUS }

    val snackbar = remember { SnackbarHostState() }
    var snackIsError by remember { mutableStateOf(false) }
    LaunchedEffect(ui.message) {
        val message = ui.message ?: return@LaunchedEffect
        snackIsError = ui.isError
        snackbar.showSnackbar(
            message,
            withDismissAction = true,
            duration = if (ui.isError) SnackbarDuration.Long else SnackbarDuration.Short,
        )
        viewModel.consumeMessage(message)
    }

    val attentionCount = capabilities.missingGrantable().size
    val stateHolder = rememberSaveableStateHolder()

    Scaffold(
        snackbarHost = {
            SnackbarHost(snackbar) { data ->
                val colors = MaterialTheme.colorScheme
                Snackbar(
                    data,
                    containerColor = if (snackIsError) colors.errorContainer else colors.inverseSurface,
                    contentColor = if (snackIsError) colors.onErrorContainer else colors.inverseOnSurface,
                    dismissActionContentColor = if (snackIsError) colors.onErrorContainer else colors.inverseOnSurface,
                )
            }
        },
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { item ->
                    NavigationBarItem(
                        selected = tab == item,
                        onClick = { tab = item },
                        icon = {
                            BadgedBox(badge = { if (item == Tab.SETTINGS && attentionCount > 0) Badge() }) {
                                Icon(item.icon, contentDescription = null)
                            }
                        },
                        label = { Text(item.label) },
                    )
                }
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding).consumeWindowInsets(padding)) {
            val current = tab ?: return@Box
            stateHolder.SaveableStateProvider(current.name) {
                when (current) {
                    Tab.STATUS -> StatusScreen(
                        ui = ui,
                        status = status,
                        queueSize = queueSize,
                        capabilities = capabilities,
                        events = events,
                        permissions = permissions,
                        onStart = viewModel::startAgent,
                        onStop = viewModel::stopAgent,
                        onOpenEvents = { tab = Tab.EVENTS },
                        onOpenSettings = { tab = Tab.SETTINGS },
                    )
                    Tab.EVENTS -> EventsScreen(events = events, onClear = viewModel::clearRecentEvents)
                    Tab.SETTINGS -> SettingsScreen(
                        ui = ui,
                        capabilities = capabilities,
                        permissions = permissions,
                        onFormChange = viewModel::updateForm,
                        onEnroll = viewModel::enroll,
                        onSave = viewModel::saveSettings,
                        onForget = viewModel::forgetEnrollment,
                    )
                }
            }
        }
    }
}
