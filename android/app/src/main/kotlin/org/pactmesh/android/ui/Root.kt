package org.pactmesh.android.ui

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import org.pactmesh.android.MainViewModel
import org.pactmesh.android.R
import org.pactmesh.android.UiState
import org.pactmesh.android.ui.screens.Dashboard
import org.pactmesh.android.ui.screens.JoinScreen
import org.pactmesh.android.ui.screens.Peers
import org.pactmesh.android.ui.screens.Settings

private enum class Tab(val label: Int, val icon: ImageVector) {
    DASHBOARD(R.string.tab_dashboard, Icons.Default.Home),
    PEERS(R.string.tab_peers, Icons.AutoMirrored.Filled.List),
    SETTINGS(R.string.tab_settings, Icons.Default.Settings),
}

@Composable
fun Root(model: MainViewModel, onRequestVpn: () -> Unit) {
    val state by model.state.collectAsState()
    val error by model.vpnError.collectAsState()
    val snackbar = remember { SnackbarHostState() }
    var tab by remember { mutableStateOf(Tab.DASHBOARD) }

    LaunchedEffect(error) {
        error?.let {
            snackbar.showSnackbar(it)
            model.clearError()
        }
    }

    val joined = state is UiState.Joined

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        snackbarHost = { SnackbarHost(snackbar) },
        bottomBar = {
            // The tabs only mean anything once a network exists; before that the join
            // flow is the whole app.
            if (joined) {
                NavigationBar {
                    Tab.entries.forEach { entry ->
                        NavigationBarItem(
                            selected = tab == entry,
                            onClick = { tab = entry },
                            icon = { Icon(entry.icon, contentDescription = null) },
                            label = { Text(stringResource(entry.label)) },
                        )
                    }
                }
            }
        },
    ) { insets ->
        val content = Modifier.padding(insets)
        if (!joined) {
            JoinScreen(model, state, content)
            return@Scaffold
        }
        when (tab) {
            Tab.DASHBOARD -> Dashboard(model, onRequestVpn, content)
            Tab.PEERS -> Peers(model, content)
            Tab.SETTINGS -> Settings(model, onRequestVpn, content)
        }
    }
}
