package org.pactmesh.android

import android.os.Build
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.pactmesh.android.net.InvitePreview
import org.pactmesh.android.net.NetworkConfig
import org.pactmesh.android.net.NodeInfo
import org.pactmesh.android.net.Repository
import org.pactmesh.android.net.Route
import org.pactmesh.android.vpn.VpnController

sealed interface UiState {
    data object Starting : UiState

    /** No network on this device yet. */
    data object Idle : UiState

    /** The invite parsed; the user has not committed to anything yet. */
    data class Confirming(val preview: InvitePreview, val inviteUrl: String) : UiState

    /** Submitted. The network administrator has not decided yet. */
    data class Pending(val networkName: String) : UiState

    /**
     * Mounted. Not the same as having an address: the network administrator assigns
     * those separately, and a member can sit here a while without one.
     */
    data object Joined : UiState

    data class Failed(val message: String) : UiState
}

/** Two samples of a counter, a subtraction apart. */
private data class Sample(val rx: Long, val tx: Long, val at: Long)

class MainViewModel : ViewModel() {
    private val _state = MutableStateFlow<UiState>(UiState.Starting)
    val state: StateFlow<UiState> = _state.asStateFlow()

    private val _node = MutableStateFlow<NodeInfo?>(null)
    val node: StateFlow<NodeInfo?> = _node.asStateFlow()

    private val _config = MutableStateFlow<NetworkConfig?>(null)
    val config: StateFlow<NetworkConfig?> = _config.asStateFlow()

    private val _peers = MutableStateFlow<List<Route>>(emptyList())
    val peers: StateFlow<List<Route>> = _peers.asStateFlow()

    private val _rx = MutableStateFlow(0L)
    val rx: StateFlow<Long> = _rx.asStateFlow()

    private val _tx = MutableStateFlow(0L)
    val tx: StateFlow<Long> = _tx.asStateFlow()

    /** Recent (rx, tx) rates, oldest first. */
    private val _history = MutableStateFlow<List<Pair<Float, Float>>>(emptyList())
    val history: StateFlow<List<Pair<Float, Float>>> = _history.asStateFlow()

    val mode = VpnController.mode
    val busy = VpnController.busy
    val vpnError = VpnController.error

    private var last: Sample? = null

    init {
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { Core.start() } }
                .onFailure {
                    _state.value = UiState.Failed(it.message.orEmpty())
                    return@launch
                }
            VpnController.resume()
            watch()
        }
    }

    fun preview(inviteUrl: String) = viewModelScope.launch {
        runCatching { Repository.previewInvite(inviteUrl) }
            .onSuccess { _state.value = UiState.Confirming(it, inviteUrl) }
            .onFailure { _state.value = UiState.Failed(it.message.orEmpty()) }
    }

    fun join() = viewModelScope.launch {
        val confirming = _state.value as? UiState.Confirming ?: return@launch
        _state.value = UiState.Pending(confirming.preview.networkName.orEmpty())
        runCatching { Repository.join(confirming.inviteUrl, Build.MODEL, Prefs.socks5Port) }
            .onFailure { _state.value = UiState.Failed(it.message.orEmpty()) }
    }

    fun reset() {
        _state.value = UiState.Idle
    }

    fun setMode(target: RunMode) = VpnController.setMode(target)

    fun setSocks5Port(port: Int) {
        Prefs.socks5Port = port
        VpnController.reapplySocks5Port()
    }

    fun clearError() = VpnController.clearError()

    /** Leaves the network; [purge] deletes this device's certificates with it. */
    fun leave(purge: Boolean) = viewModelScope.launch {
        val cfg = _config.value ?: return@launch
        runCatching {
            VpnController.releaseTun()
            if (purge) {
                Repository.purgeLocal(cfg.trustDomainId, cfg.networkLocalId)
            } else {
                Repository.leave(cfg.trustDomainId, cfg.networkLocalId)
            }
        }.onSuccess {
            _node.value = null
            _config.value = null
            _peers.value = emptyList()
            _state.value = UiState.Idle
        }.onFailure { _state.value = UiState.Failed(it.message.orEmpty()) }
    }

    /**
     * Polling join-status is not observation, it is the mechanism: the console mounts
     * the network from inside that handler once the certificate lands. Stop asking and
     * an approved network never comes up.
     */
    private suspend fun watch() {
        while (true) {
            runCatching { poll() }
            delay(POLL_MS)
        }
    }

    private suspend fun poll() {
        val join = runCatching { Repository.joinStatus().firstOrNull() }.getOrNull()
        when (join?.status) {
            "submitting", "pending" -> _state.value = UiState.Pending(join.networkName.orEmpty())
            "error", "timeout" -> _state.value = UiState.Failed(join.error ?: "join timed out")
            else -> Unit
        }

        val mounted = runCatching { Repository.instanceCount() }.getOrNull() ?: return
        if (mounted == 0) {
            // Every mode switch passes through zero instances. That is a remount in
            // flight, not a network that went away.
            if (!busy.value && join == null && _state.value !is UiState.Confirming) {
                _state.value = UiState.Idle
            }
            return
        }

        val node = runCatching { Repository.node() }.getOrNull() ?: return
        _node.value = node
        _config.value = runCatching { Repository.config() }.getOrNull()
        _peers.value = runCatching { Repository.routes() }.getOrDefault(emptyList())
            .filter { it.peerId != node.peerId }
        sampleTraffic()
        if (_state.value !is UiState.Confirming) _state.value = UiState.Joined
    }

    private suspend fun sampleTraffic() {
        val metrics = runCatching { Repository.stats() }.getOrNull() ?: return
        val now = Sample(
            rx = metrics["traffic_bytes_rx"] ?: 0,
            tx = metrics["traffic_bytes_tx"] ?: 0,
            at = System.currentTimeMillis(),
        )
        last?.let { previous ->
            val seconds = (now.at - previous.at).coerceAtLeast(1) / 1000f
            _rx.value = ((now.rx - previous.rx).coerceAtLeast(0) / seconds).toLong()
            _tx.value = ((now.tx - previous.tx).coerceAtLeast(0) / seconds).toLong()
            _history.value =
                (_history.value + (_rx.value.toFloat() to _tx.value.toFloat())).takeLast(HISTORY)
        }
        last = now
    }

    private companion object {
        const val POLL_MS = 2_000L
        const val HISTORY = 60
    }
}
