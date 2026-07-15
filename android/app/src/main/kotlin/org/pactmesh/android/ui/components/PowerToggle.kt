package org.pactmesh.android.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp

/**
 * The one control that matters: on means this phone holds the VPN slot.
 */
@Composable
fun PowerToggle(
    on: Boolean,
    busy: Boolean,
    onToggle: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val background by animateColorAsState(
        if (on) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
        label = "power-bg",
    )
    val foreground by animateColorAsState(
        if (on) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurfaceVariant,
        label = "power-fg",
    )
    val halo = rememberInfiniteTransition(label = "power-halo").animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(1_400), RepeatMode.Restart),
        label = "power-halo-phase",
    )

    Box(modifier = modifier.size(200.dp), contentAlignment = Alignment.Center) {
        if (busy) {
            val ring = MaterialTheme.colorScheme.primary
            Canvas(Modifier.size(200.dp)) {
                val phase = halo.value
                drawCircle(
                    color = ring.copy(alpha = (1f - phase) * 0.35f),
                    radius = size.minDimension / 2f * (0.9f + phase * 0.1f),
                    style = Stroke(width = 4.dp.toPx()),
                )
            }
        }
        Surface(
            shape = CircleShape,
            color = background,
            tonalElevation = if (on) 6.dp else 0.dp,
            modifier = Modifier
                .size(176.dp)
                .scale(if (pressed) 0.94f else 1f)
                .clickable(
                    interactionSource = interaction,
                    indication = null,
                    enabled = !busy,
                    onClick = onToggle,
                ),
        ) {
            Canvas(Modifier.size(176.dp)) {
                val stroke = Stroke(width = 6.dp.toPx())
                val radius = size.minDimension * 0.18f
                val center = Offset(size.width / 2f, size.height / 2f)
                drawArc(
                    color = foreground,
                    startAngle = -60f,
                    sweepAngle = 300f,
                    useCenter = false,
                    topLeft = Offset(center.x - radius, center.y - radius + radius * 0.15f),
                    size = Size(radius * 2, radius * 2),
                    style = stroke,
                )
                drawLine(
                    color = foreground,
                    start = Offset(center.x, center.y - radius * 1.15f),
                    end = Offset(center.x, center.y + radius * 0.1f),
                    strokeWidth = 6.dp.toPx(),
                )
            }
        }
    }
}
