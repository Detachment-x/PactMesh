package org.pactmesh.android.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp

/**
 * Two smoothed series on a shared scale, drawn by hand. A chart library would be an
 * order of magnitude more code and dependency than sixty points deserve.
 */
@Composable
fun TrafficChart(history: List<Pair<Float, Float>>, modifier: Modifier = Modifier) {
    val down = MaterialTheme.colorScheme.primary
    val up = MaterialTheme.colorScheme.tertiary
    Canvas(
        modifier
            .fillMaxWidth()
            .height(120.dp)
    ) {
        if (history.size < 2) return@Canvas
        val peak = history.maxOf { maxOf(it.first, it.second) }.coerceAtLeast(1f)
        series(history.map { it.first }, peak, down, fill = true)
        series(history.map { it.second }, peak, up, fill = false)
    }
}

private fun DrawScope.series(values: List<Float>, peak: Float, color: Color, fill: Boolean) {
    val step = size.width / (values.size - 1)
    val points = values.mapIndexed { index, value ->
        Offset(index * step, size.height - (value / peak) * size.height * 0.9f)
    }

    val line = Path().apply {
        moveTo(points.first().x, points.first().y)
        points.zipWithNext { a, b ->
            val midX = (a.x + b.x) / 2
            quadraticTo(a.x, a.y, midX, (a.y + b.y) / 2)
            quadraticTo(b.x, b.y, b.x, b.y)
        }
    }
    drawPath(line, color, style = Stroke(width = 2.dp.toPx()))

    if (!fill) return
    val area = Path().apply {
        addPath(line)
        lineTo(points.last().x, size.height)
        lineTo(points.first().x, size.height)
        close()
    }
    drawPath(
        area,
        Brush.verticalGradient(listOf(color.copy(alpha = 0.28f), Color.Transparent)),
    )
}
