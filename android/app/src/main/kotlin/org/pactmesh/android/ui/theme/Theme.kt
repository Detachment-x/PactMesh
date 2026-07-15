package org.pactmesh.android.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

private val Teal = Color(0xFF00A38C)
private val TealDark = Color(0xFF4FD8C0)
private val Slate = Color(0xFF3F5B72)

private val Light = lightColorScheme(primary = Teal, secondary = Slate)
private val Dark = darkColorScheme(primary = TealDark, secondary = Slate)

/** Monet where the phone has it; a teal of our own where it does not. */
@Composable
fun PactMeshTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val context = LocalContext.current
    val colors = when {
        Build.VERSION.SDK_INT >= 31 ->
            if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)

        dark -> Dark
        else -> Light
    }
    MaterialTheme(colorScheme = colors, content = content)
}
