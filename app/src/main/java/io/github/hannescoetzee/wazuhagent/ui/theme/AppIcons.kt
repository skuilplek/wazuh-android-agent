package io.github.hannescoetzee.wazuhagent.ui.theme

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.addPathNodes
import androidx.compose.ui.unit.dp

/** Material icons that are only in the (large) extended icon artifact. */
object AppIcons {
    val Shield by lazy {
        icon("Shield", "M12,1L3,5v6c0,5.55 3.84,10.74 9,12 5.16,-1.26 9,-6.45 9,-12V5l-9,-4z")
    }
    val VerifiedUser by lazy {
        icon(
            "VerifiedUser",
            "M12,1L3,5v6c0,5.55 3.84,10.74 9,12 5.16,-1.26 9,-6.45 9,-12V5l-9,-4zM10,17l-4,-4 1.41,-1.41L10,14.17l6.59,-6.59L18,9l-8,8z",
        )
    }
    val Pause by lazy { icon("Pause", "M6,19h4V5H6v14zM14,5v14h4V5h-4z") }
    val Stop by lazy { icon("Stop", "M6,6h12v12H6z") }
    val ContentCopy by lazy {
        icon(
            "ContentCopy",
            "M16,1H4c-1.1,0 -2,0.9 -2,2v14h2V3h12V1zM19,5H8c-1.1,0 -2,0.9 -2,2v14c0,1.1 0.9,2 2,2h11c1.1,0 2,-0.9 2,-2V7c0,-1.1 -0.9,-2 -2,-2zM19,21H8V7h11v14z",
        )
    }
    val Public by lazy {
        icon(
            "Public",
            "M12,2C6.48,2 2,6.48 2,12s4.48,10 10,10 10,-4.48 10,-10S17.52,2 12,2zM11,19.93c-3.95,-0.49 -7,-3.85 -7,-7.93 0,-0.62 0.08,-1.21 0.21,-1.79L9,15v1c0,1.1 0.9,2 2,2v1.93zM17.9,17.39c-0.26,-0.81 -1,-1.39 -1.9,-1.39h-1v-3c0,-0.55 -0.45,-1 -1,-1H8v-2h2c0.55,0 1,-0.45 1,-1V7h2c1.1,0 2,-0.9 2,-2v-0.41c2.93,1.19 5,4.06 5,7.41 0,2.08 -0.8,3.97 -2.1,5.39z",
        )
    }
    val Apps by lazy {
        icon(
            "Apps",
            "M4,8h4V4H4v4zM10,20h4v-4h-4v4zM4,20h4v-4H4v4zM4,14h4v-4H4v4zM10,14h4v-4h-4v4zM16,4v4h4V4h-4zM10,8h4V4h-4v4zM16,14h4v-4h-4v4zM16,20h4v-4h-4v4z",
        )
    }
    val Battery by lazy {
        icon(
            "Battery",
            "M15.67,4H14V2h-4v2H8.33C7.6,4 7,4.6 7,5.33v15.33C7,21.4 7.6,22 8.33,22h7.33c0.74,0 1.34,-0.6 1.34,-1.33V5.33C17,4.6 16.4,4 15.67,4z",
        )
    }
    val Dns by lazy {
        icon(
            "Dns",
            "M20,13H4c-0.55,0 -1,0.45 -1,1v6c0,0.55 0.45,1 1,1h16c0.55,0 1,-0.45 1,-1v-6c0,-0.55 -0.45,-1 -1,-1zM7,19c-1.1,0 -2,-0.9 -2,-2s0.9,-2 2,-2 2,0.9 2,2 -0.9,2 -2,2zM20,3H4c-0.55,0 -1,0.45 -1,1v6c0,0.55 0.45,1 1,1h16c0.55,0 1,-0.45 1,-1V4c0,-0.55 -0.45,-1 -1,-1zM7,9c-1.1,0 -2,-0.9 -2,-2s0.9,-2 2,-2 2,0.9 2,2 -0.9,2 -2,2z",
        )
    }

    private fun icon(name: String, pathData: String) = ImageVector.Builder(
        name = name,
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f,
    ).addPath(pathData = addPathNodes(pathData), fill = SolidColor(Color.Black)).build()
}
