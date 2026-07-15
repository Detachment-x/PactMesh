package org.pactmesh.android.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import org.pactmesh.android.MainViewModel
import org.pactmesh.android.R
import org.pactmesh.android.RunMode
import org.pactmesh.android.ui.components.PowerToggle
import org.pactmesh.android.ui.components.StatCard
import org.pactmesh.android.ui.components.TrafficChart
import org.pactmesh.android.ui.components.formatRate

@Composable
fun Dashboard(model: MainViewModel, onRequestVpn: () -> Unit, modifier: Modifier = Modifier) {
    val mode by model.mode.collectAsState()
    val busy by model.busy.collectAsState()
    val node by model.node.collectAsState()
    val config by model.config.collectAsState()
    val peers by model.peers.collectAsState()
    val rx by model.rx.collectAsState()
    val tx by model.tx.collectAsState()
    val history by model.history.collectAsState()

    Column(
        modifier = modifier
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        PowerToggle(
            on = mode == RunMode.VPN,
            busy = busy,
            onToggle = {
                if (mode == RunMode.VPN) model.setMode(RunMode.COEXIST) else onRequestVpn()
            },
        )
        Text(
            stringResource(if (mode == RunMode.VPN) R.string.mode_vpn else R.string.mode_coexist),
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            stringResource(
                if (mode == RunMode.VPN) R.string.mode_vpn_hint else R.string.mode_coexist_hint
            ),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCard(stringResource(R.string.download), formatRate(rx), Modifier.weight(1f))
            StatCard(stringResource(R.string.upload), formatRate(tx), Modifier.weight(1f))
        }
        TrafficChart(history)

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    node?.hostname.orEmpty(),
                    style = MaterialTheme.typography.titleMedium,
                )
                val address = node?.ipv4Addr.orEmpty()
                Text(
                    address.ifEmpty { stringResource(R.string.awaiting_ip) },
                    style = MaterialTheme.typography.bodyLarge,
                    color = if (address.isEmpty()) {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    } else {
                        MaterialTheme.colorScheme.onSurface
                    },
                )
                Text(
                    stringResource(R.string.peers, peers.size),
                    style = MaterialTheme.typography.labelLarge,
                )
            }
        }

        val socks5Port = config?.socks5Port
        if (mode == RunMode.COEXIST && socks5Port != null && config?.enableSocks5 == true) {
            ProxyCard(port = socks5Port, subnets = meshSubnets(model))
        }
    }
}

/**
 * The proxy is how the mesh stays reachable while another VPN holds the slot: point that
 * VPN's rules for these subnets at this address and its traffic comes in here.
 */
@Composable
private fun ProxyCard(port: Int, subnets: List<String>) {
    val clipboard = LocalClipboardManager.current
    val endpoint = "socks5://127.0.0.1:$port"
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(stringResource(R.string.proxy_title), style = MaterialTheme.typography.titleMedium)
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(endpoint, style = MaterialTheme.typography.bodyLarge)
                TextButton(onClick = { clipboard.setText(AnnotatedString(endpoint)) }) {
                    Text(stringResource(R.string.copy))
                }
            }
            if (subnets.isNotEmpty()) {
                Row(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(subnets.joinToString(" "), style = MaterialTheme.typography.bodyMedium)
                    TextButton(onClick = {
                        clipboard.setText(AnnotatedString(subnets.joinToString(",")))
                    }) {
                        Text(stringResource(R.string.copy))
                    }
                }
            }
            Text(
                stringResource(R.string.proxy_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** The overlay subnet plus whatever the peers export — what the other VPN must route here. */
@Composable
private fun meshSubnets(model: MainViewModel): List<String> {
    val node by model.node.collectAsState()
    val peers by model.peers.collectAsState()
    val overlay = node?.ipv4Addr.orEmpty().takeIf { it.contains('/') }?.let { address ->
        val prefix = address.substringAfter('/').toIntOrNull() ?: return@let null
        val octets = address.substringBefore('/').split('.').mapNotNull { it.toIntOrNull() }
        if (octets.size != 4) return@let null
        val bits = octets.fold(0L) { acc, octet -> (acc shl 8) or octet.toLong() }
        val mask = if (prefix == 0) 0L else (0xffffffffL shl (32 - prefix)) and 0xffffffffL
        val network = bits and mask
        (24 downTo 0 step 8).joinToString(".") { ((network shr it) and 0xff).toString() } + "/$prefix"
    }
    val exported = peers.flatMap { it.proxyCidrs }.map { it.substringBefore("->").trim() }
    return (listOfNotNull(overlay) + exported).filter { it.isNotEmpty() }.distinct()
}
