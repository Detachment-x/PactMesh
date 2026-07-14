package org.pactmesh.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.isSystemInDarkTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.pactmesh.android.net.ApiClient

/**
 * S2's whole job: prove the core runs inside the app and answers its own HTTP.
 * The real UI lands in S5 — this screen is a probe, not a design.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val context = LocalContext.current
            val colors = if (isSystemInDarkTheme()) {
                dynamicDarkColorScheme(context)
            } else {
                dynamicLightColorScheme(context)
            }
            MaterialTheme(colorScheme = colors) { ProbeScreen() }
        }
    }
}

@Composable
private fun ProbeScreen() {
    val scope = rememberCoroutineScope()
    var output by remember { mutableStateOf("") }

    Scaffold(modifier = Modifier.fillMaxSize()) { insets ->
        Column(
            modifier = Modifier
                .padding(insets)
                .padding(16.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Button(onClick = {
                scope.launch {
                    output = runCatching {
                        withContext(Dispatchers.IO) { Core.start() }
                        ApiClient.get("/api/instances")
                    }.getOrElse { "failed: ${it.message}" }
                }
            }) {
                Text(stringResource(R.string.probe_start))
            }
            Text(output, style = MaterialTheme.typography.bodySmall)
        }
    }
}
