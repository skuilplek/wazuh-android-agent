package io.github.hannescoetzee.wazuhagent.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import io.github.hannescoetzee.wazuhagent.ui.theme.WazuhThemeColors

@Composable
fun StatusPill(
    label: String,
    color: Color,
    container: Color,
    modifier: Modifier = Modifier,
    compact: Boolean = false,
) {
    Row(
        modifier = modifier
            .background(container, CircleShape)
            .padding(horizontal = if (compact) 8.dp else 12.dp, vertical = if (compact) 2.dp else 5.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(if (compact) 5.dp else 7.dp),
    ) {
        Box(Modifier.size(if (compact) 6.dp else 8.dp).background(color, CircleShape))
        Text(
            label,
            color = color,
            style = if (compact) MaterialTheme.typography.labelSmall else MaterialTheme.typography.labelLarge,
        )
    }
}

@Composable
fun SentBadge(sent: Boolean, modifier: Modifier = Modifier) {
    val status = WazuhThemeColors.status
    if (sent) {
        StatusPill("Sent", status.success, status.successContainer, modifier, compact = true)
    } else {
        StatusPill("Queued", status.neutral, status.neutralContainer, modifier, compact = true)
    }
}
