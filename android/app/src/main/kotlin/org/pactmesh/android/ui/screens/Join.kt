package org.pactmesh.android.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import org.pactmesh.android.MainViewModel
import org.pactmesh.android.R
import org.pactmesh.android.UiState

/** Everything before the network exists on this device. */
@Composable
fun JoinScreen(model: MainViewModel, state: UiState, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .padding(16.dp)
            .fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        when (state) {
            UiState.Starting -> Busy(stringResource(R.string.starting))
            UiState.Idle -> InviteEntry(onSubmit = model::preview)
            is UiState.Confirming -> Confirm(state, onJoin = { model.join() }, onCancel = model::reset)
            is UiState.Pending -> Busy(stringResource(R.string.awaiting_admin, state.networkName))
            is UiState.Failed -> Failure(state.message, onRetry = model::reset)
            UiState.Joined -> Unit
        }
    }
}

@Composable
private fun InviteEntry(onSubmit: (String) -> Unit) {
    var invite by remember { mutableStateOf("") }
    val scanner = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.let { onSubmit(it) }
    }

    Text(stringResource(R.string.join_title), style = MaterialTheme.typography.headlineSmall)
    Text(stringResource(R.string.join_hint), style = MaterialTheme.typography.bodyMedium)
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
private fun Failure(message: String, onRetry: () -> Unit) {
    Text(message, color = MaterialTheme.colorScheme.error)
    Button(onClick = onRetry) { Text(stringResource(R.string.back)) }
}
