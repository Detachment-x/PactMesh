package org.pactmesh.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import org.pactmesh.android.net.Route

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val context = LocalContext.current
            val dark = isSystemInDarkTheme()
            val colors = if (android.os.Build.VERSION.SDK_INT >= 31) {
                if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
            } else {
                if (dark) darkColorScheme() else lightColorScheme()
            }
            MaterialTheme(colorScheme = colors) { JoinScreen() }
        }
    }
}

@Composable
private fun JoinScreen(model: MainViewModel = viewModel()) {
    val state by model.state.collectAsState()
    val peers by model.peers.collectAsState()
    val address by model.address.collectAsState()

    Scaffold(modifier = Modifier.fillMaxSize()) { insets ->
        Column(
            modifier = Modifier
                .padding(insets)
                .padding(16.dp)
                .fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            when (val current = state) {
                UiState.Starting -> Busy(stringResource(R.string.starting))
                UiState.Idle -> InviteEntry(onSubmit = model::preview)
                is UiState.Confirming -> Confirm(current, onJoin = model::join, onCancel = model::reset)
                is UiState.Pending -> Busy(stringResource(R.string.awaiting_admin, current.networkName))
                is UiState.Online -> Online(current.networkName, address, peers)
                is UiState.Failed -> Failure(current.message, onRetry = model::reset)
            }
        }
    }
}

@Composable
private fun InviteEntry(onSubmit: (String) -> Unit) {
    var invite by remember { mutableStateOf("") }
    val scanner = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.let { onSubmit(it) }
    }

    OutlinedTextField(
        value = invite,
        onValueChange = { invite = it },
        label = { Text(stringResource(R.string.invite_link)) },
        modifier = Modifier.fillMaxWidth(),
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = { onSubmit(invite) }, enabled = invite.isNotBlank()) {
            Text(stringResource(R.string.join))
        }
        OutlinedButton(onClick = {
            scanner.launch(
                ScanOptions()
                    .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                    .setPrompt("")
                    .setBeepEnabled(false)
            )
        }) {
            Text(stringResource(R.string.scan))
        }
    }
}

@Composable
private fun Confirm(state: UiState.Confirming, onJoin: () -> Unit, onCancel: () -> Unit) {
    val preview = state.preview
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(preview.networkName.orEmpty(), style = MaterialTheme.typography.titleLarge)
            Text(
                stringResource(R.string.domain, preview.domainLabel.orEmpty()),
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                stringResource(R.string.seeds, preview.seedCount),
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = onJoin) { Text(stringResource(R.string.join)) }
        OutlinedButton(onClick = onCancel) { Text(stringResource(R.string.cancel)) }
    }
}

@Composable
private fun Busy(message: String) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        CircularProgressIndicator()
        Text(message)
    }
}

@Composable
private fun Online(hostname: String, address: String, peers: List<Route>) {
    Text(hostname, style = MaterialTheme.typography.titleLarge)
    Text(address, style = MaterialTheme.typography.bodyLarge)
    Text(stringResource(R.string.peers, peers.size), style = MaterialTheme.typography.labelLarge)
    LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(peers) { peer ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(peer.hostname, style = MaterialTheme.typography.bodyLarge)
                    Text(
                        stringResource(R.string.hops, peer.cost),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
    }
}

@Composable
private fun Failure(message: String, onRetry: () -> Unit) {
    Text(message, color = MaterialTheme.colorScheme.error)
    Button(onClick = onRetry) { Text(stringResource(R.string.back)) }
}
