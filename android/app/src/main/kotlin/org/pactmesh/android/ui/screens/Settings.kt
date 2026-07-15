package org.pactmesh.android.ui.screens

import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import org.pactmesh.android.BuildConfig
import org.pactmesh.android.MainViewModel
import org.pactmesh.android.Prefs
import org.pactmesh.android.R
import org.pactmesh.android.RunMode

@Composable
fun Settings(model: MainViewModel, onRequestVpn: () -> Unit, modifier: Modifier = Modifier) {
    val mode by model.mode.collectAsState()
    val busy by model.busy.collectAsState()
    val config by model.config.collectAsState()
    var purge by remember { mutableStateOf<Boolean?>(null) }

    Column(
        modifier = modifier
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Section(stringResource(R.string.run_mode)) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = mode == RunMode.COEXIST,
                    enabled = !busy,
                    onClick = { model.setMode(RunMode.COEXIST) },
                    label = { Text(stringResource(R.string.mode_coexist)) },
                )
                FilterChip(
                    selected = mode == RunMode.VPN,
                    enabled = !busy,
                    onClick = { if (mode != RunMode.VPN) onRequestVpn() },
                    label = { Text(stringResource(R.string.mode_vpn)) },
                )
            }
            Text(
                stringResource(R.string.single_vpn_slot),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        Section(stringResource(R.string.proxy_title)) {
            var port by remember { mutableStateOf(Prefs.socks5Port.toString()) }
            OutlinedTextField(
                value = port,
                onValueChange = { port = it.filter(Char::isDigit).take(5) },
                label = { Text(stringResource(R.string.socks5_port)) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth(),
            )
            val parsed = port.toIntOrNull()
            OutlinedButton(
                enabled = !busy && parsed != null && parsed in 1024..65535 &&
                    parsed != Prefs.socks5Port && mode == RunMode.COEXIST,
                onClick = { parsed?.let(model::setSocks5Port) },
            ) {
                Text(stringResource(R.string.apply))
            }
            Text(
                stringResource(R.string.socks5_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        Section(stringResource(R.string.this_device)) {
            Text(Build.MODEL, style = MaterialTheme.typography.bodyLarge)
            Text(
                config?.networkName.orEmpty(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            HorizontalDivider(Modifier.padding(vertical = 8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { purge = false }) {
                    Text(stringResource(R.string.leave_network))
                }
                OutlinedButton(onClick = { purge = true }) {
                    Text(stringResource(R.string.purge_network))
                }
            }
        }

        Text(
            stringResource(R.string.version, BuildConfig.VERSION_NAME),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }

    purge?.let { deleteCertificates ->
        AlertDialog(
            onDismissRequest = { purge = null },
            title = {
                Text(
                    stringResource(
                        if (deleteCertificates) R.string.purge_network else R.string.leave_network
                    )
                )
            },
            text = {
                Text(
                    stringResource(
                        if (deleteCertificates) R.string.purge_confirm else R.string.leave_confirm
                    )
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    model.leave(deleteCertificates)
                    purge = null
                }) {
                    Text(stringResource(R.string.confirm))
                }
            },
            dismissButton = {
                TextButton(onClick = { purge = null }) { Text(stringResource(R.string.cancel)) }
            },
        )
    }
}

@Composable
private fun Section(title: String, content: @Composable () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            content()
        }
    }
}
