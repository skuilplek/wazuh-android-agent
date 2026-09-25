package io.github.hannescoetzee.wazuhagent.ui.theme

import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color

val WazuhBlue = Color(0xFF3595F2)
val Navy950 = Color(0xFF050F20)
val Navy900 = Color(0xFF07142A)
val Navy800 = Color(0xFF0B1F3A)
val Navy700 = Color(0xFF102744)
val Navy600 = Color(0xFF132B4D)
val Navy500 = Color(0xFF1A3558)
val Navy400 = Color(0xFF1C3A63)

val LightColors = lightColorScheme(
    primary = Color(0xFF1A73CF),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD6E8FC),
    onPrimaryContainer = Navy800,
    secondary = Color(0xFF4F6078),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFD6E8FC),
    onSecondaryContainer = Navy800,
    tertiary = Color(0xFF00897B),
    onTertiary = Color.White,
    background = Color(0xFFF3F6FA),
    onBackground = Navy800,
    surface = Color(0xFFF3F6FA),
    onSurface = Navy800,
    surfaceVariant = Color(0xFFE4EAF2),
    onSurfaceVariant = Color(0xFF4F6078),
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color.White,
    surfaceContainer = Color(0xFFEBF0F6),
    surfaceContainerHigh = Color(0xFFE4EAF2),
    surfaceContainerHighest = Color(0xFFDCE3EC),
    outline = Color(0xFF8A9AB0),
    outlineVariant = Color(0xFFD3DCE7),
    error = Color(0xFFC62828),
    onError = Color.White,
    errorContainer = Color(0xFFFDE2E1),
    onErrorContainer = Color(0xFF5F1412),
    inverseSurface = Navy800,
    inverseOnSurface = Color(0xFFE3EAF4),
    inversePrimary = Color(0xFF5AABF5),
)

val DarkColors = darkColorScheme(
    primary = Color(0xFF5AABF5),
    onPrimary = Color(0xFF002A52),
    primaryContainer = Color(0xFF154A80),
    onPrimaryContainer = Color(0xFFD6E8FC),
    secondary = Color(0xFF9DB0C8),
    onSecondary = Navy800,
    secondaryContainer = Navy400,
    onSecondaryContainer = Color(0xFFD6E8FC),
    tertiary = Color(0xFF4DB6AC),
    onTertiary = Navy900,
    background = Navy900,
    onBackground = Color(0xFFE3EAF4),
    surface = Navy900,
    onSurface = Color(0xFFE3EAF4),
    surfaceVariant = Navy500,
    onSurfaceVariant = Color(0xFF9DB0C8),
    surfaceContainerLowest = Navy950,
    surfaceContainerLow = Navy700,
    surfaceContainer = Navy800,
    surfaceContainerHigh = Navy600,
    surfaceContainerHighest = Navy500,
    outline = Color(0xFF4A6488),
    outlineVariant = Color(0xFF22395A),
    error = Color(0xFFFF8A80),
    onError = Color(0xFF5F1412),
    errorContainer = Color(0xFF5C1B1B),
    onErrorContainer = Color(0xFFFDE2E1),
    inverseSurface = Color(0xFFE3EAF4),
    inverseOnSurface = Navy800,
    inversePrimary = Color(0xFF1A73CF),
)
