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
import org.pactmesh.android.net.Repository
import org.pactmesh.android.net.Route

sealed interface UiState {
    data object Starting : UiState

    data object Idle : UiState

    /** The invite parsed; the user has not committed to anything yet. */
    data class Confirming(val preview: InvitePreview, val inviteUrl: String) : UiState

    /** Submitted. The network administrator has not decided yet. */
    data class Pending(val networkName: String) : UiState

    data class Online(val networkName: String) : UiState

    data class Failed(val message: String) : UiState
}

class MainViewModel : ViewModel() {
    private val _state = MutableStateFlow<UiState>(UiState.Starting)
    val state: StateFlow<UiState> = _state.asStateFlow()

    private val _peers = MutableStateFlow<List<Route>>(emptyList())
    val peers: StateFlow<List<Route>> = _peers.asStateFlow()

    private val _address = MutableStateFlow("")
    val address: StateFlow<String> = _address.asStateFlow()

    init {
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { Core.start() } }
                .onFailure { _state.value = UiState.Failed(it.message.orEmpty()); return@launch }
            // A join survives the app being killed, so on every launch we adopt
            // whatever the console already knows rather than assuming a clean slate.
            _state.value = UiState.Idle
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
        runCatching { Repository.join(confirming.inviteUrl, Build.MODEL) }
            .onFailure { _state.value = UiState.Failed(it.message.orEmpty()) }
    }

    fun reset() {
        _state.value = UiState.Idle
    }

    /**
     * Polling join-status is not observation, it is the mechanism: the console mounts
     * the network from inside that handler once the certificate lands. Stop asking and
     * an approved network never comes up.
     */
    private suspend fun watch() {
        while (true) {
            runCatching {
                val join = Repository.joinStatus().firstOrNull()
                when (join?.status) {
                    "submitting", "pending" ->
                        _state.value = UiState.Pending(join.networkName.orEmpty())

                    "error", "timeout" ->
                        _state.value = UiState.Failed(join.error ?: "join timed out")

                    // The join is gone from the pending list once mounted, so an
                    // online network is one the daemon reports, not one listed here.
                    else -> Unit
                }

                val node = Repository.node()
                if (node != null && node.ipv4Addr.isNotEmpty()) {
                    _address.value = node.ipv4Addr
                    _peers.value = Repository.routes().filter { it.peerId != node.peerId }
                    if (_state.value !is UiState.Confirming) {
                        _state.value = UiState.Online(node.hostname)
                    }
                }
            }
            delay(POLL_MS)
        }
    }

    private companion object {
        const val POLL_MS = 2_000L
    }
}
