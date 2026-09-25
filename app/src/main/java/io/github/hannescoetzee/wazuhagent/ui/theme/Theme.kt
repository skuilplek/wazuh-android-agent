package io.github.hannescoetzee.wazuhagent.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color

/** Colors outside the Material scheme, used only to signal state. */
@Immutable
data class StatusColors(
    val success: Color,
    val successContainer: Color,
    val warning: Color,
    val warningContainer: Color,
    val neutral: Color,
    val neutralContainer: Color,
    val hero: Brush,
)

private val LightStatus = StatusColors(
    success = Color(0xFF1E8E3E),
    successContainer = Color(0xFFDDF3E4),
    warning = Color(0xFFB26A00),
    warningContainer = Color(0xFFFFF1D6),
    neutral = Color(0xFF5F6F86),
    neutralContainer = Color(0xFFE4EAF2),
    hero = Brush.linearGradient(listOf(Navy800, Color(0xFF15457A))),
)

private val DarkStatus = StatusColors(
    success = Color(0xFF5DD68A),
    successContainer = Color(0xFF123D2A),
    warning = Color(0xFFFFC266),
    warningContainer = Color(0xFF3D2E0F),
    neutral = Color(0xFF9DB0C8),
    neutralContainer = Navy500,
    hero = Brush.linearGradient(listOf(Color(0xFF17457C), Navy700)),
)

private val LocalStatusColors = staticCompositionLocalOf { LightStatus }

object WazuhThemeColors {
    val status: StatusColors
        @Composable @ReadOnlyComposable get() = LocalStatusColors.current
}

@Composable
fun WazuhTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    CompositionLocalProvider(LocalStatusColors provides if (dark) DarkStatus else LightStatus) {
        MaterialTheme(
            colorScheme = if (dark) DarkColors else LightColors,
            typography = WazuhTypography,
            content = content,
        )
    }
}
