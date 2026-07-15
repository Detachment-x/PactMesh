package org.pactmesh.android.vpn

import android.content.Context
import android.content.Intent
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.pactmesh.android.Prefs
import org.pactmesh.android.RunMode
import org.pactmesh.android.net.Repository

/** Everything the VPN service needs to build a tun. Compared as a whole to decide
 *  whether the current tun is still the right one. */
data class TunParams(
    val instanceId: String,
    val ipv4: String,
    val prefix: Int,
    val mtu: Int,
    val routes: List<String>,
)

/**
 * Owns the run mode: which of the two ways the phone carries mesh traffic is in force,
 * and the remount each switch costs.
 *
 * The remount is not optional. `/api/network/mount` starts a *new* instance every time
 * it is called, so a mode switch is always leave -> wait for the instance list to empty
 * -> mount with the new flags. Mounting straight over a live instance leaves two of them
 * and every instance-scoped endpoint starts failing.
 */
object VpnController {
    private const val TAG = "pactmesh"
    private const val RECONCILE_MS = 2_000L
    private const val AWAIT_MS = 30_000L
    private const val DEFAULT_MTU = 1380

    private lateinit var app: Context
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _mode = MutableStateFlow(RunMode.COEXIST)
    val mode: StateFlow<RunMode> = _mode.asStateFlow()

    private val _busy = MutableStateFlow(false)
    val busy: StateFlow<Boolean> = _busy.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    private var tunJob: Job? = null

    fun init(context: Context) {
        app = context.applicationContext
        _mode.value = Prefs.mode
    }

    fun clearError() {
        _error.value = null
    }

    /**
     * The daemon re-mounts persisted instances by itself on launch, so a phone that was
     * in VPN mode comes back with a live instance and no tun — the descriptor died with
     * the process. Hand it a new one rather than remounting.
     */
    fun resume() {
        scope.launch {
            // The daemon restores persisted instances asynchronously — it is up before they
            // are. Deciding on the first read would always read zero.
            if (!awaitAnyInstance()) return@launch
            if (Prefs.mode == RunMode.VPN) {
                startTunJob()
                return@launch
            }
            // Co-existence promises a proxy on a specific port. An instance the daemon
            // persisted before that promise existed — or on the port it was mounted with,
            // not the one now configured — is not listening on it. Remount instead of
            // showing an address nothing answers.
            val cfg = runCatching { Repository.config() }.getOrNull() ?: return@launch
            if (!cfg.enableSocks5 || cfg.socks5Port != Prefs.socks5Port) switch(RunMode.COEXIST)
        }
    }

    fun setMode(target: RunMode) {
        if (_busy.value || _mode.value == target) return
        scope.launch { switch(target) }
    }

    /** Applies a socks5 port change: only meaningful in co-existence mode, and only a
     *  remount makes the core listen on it. */
    fun reapplySocks5Port() {
        if (_busy.value || _mode.value != RunMode.COEXIST) return
        scope.launch { switch(RunMode.COEXIST) }
    }

    private suspend fun switch(target: RunMode) {
        if (_busy.value) return
        _busy.value = true
        try {
            val cfg = Repository.config() ?: error("network not mounted")
            val td = cfg.trustDomainId
            val nid = cfg.networkLocalId
            require(td.isNotEmpty() && nid.isNotEmpty()) { "bad network name: ${cfg.networkName}" }
            // leave drops the persisted instance and its connectors with it; the remount
            // is Standalone unless we hand the seeds back. Capture them while they still exist.
            val peers = cfg.peerUrls

            stopTun()
            Repository.leave(td, nid)
            awaitInstances(0)
            val coexist = target == RunMode.COEXIST
            Repository.mount(
                td,
                nid,
                noTun = coexist,
                socks5Port = if (coexist) Prefs.socks5Port else null,
                peers = peers,
            )
            awaitInstances(1)

            Prefs.mode = target
            _mode.value = target
            _error.value = null
            if (!coexist) startTunJob()
        } catch (e: Throwable) {
            Log.e(TAG, "mode switch failed", e)
            _error.value = e.message ?: e.toString()
        } finally {
            _busy.value = false
        }
    }

    /**
     * Drops the tun without remounting anything — for callers who are about to take the
     * network away entirely, where a remount would be a race against their own leave.
     */
    fun releaseTun() {
        stopTun()
        Prefs.mode = RunMode.COEXIST
        _mode.value = RunMode.COEXIST
    }

    /** True once at least one instance is mounted; false if none shows up in time. */
    private suspend fun awaitAnyInstance(): Boolean {
        val deadline = System.currentTimeMillis() + AWAIT_MS
        while (System.currentTimeMillis() < deadline) {
            if ((runCatching { Repository.instanceCount() }.getOrNull() ?: 0) > 0) return true
            delay(300)
        }
        return false
    }

    private suspend fun awaitInstances(expected: Int) {
        val deadline = System.currentTimeMillis() + AWAIT_MS
        while (System.currentTimeMillis() < deadline) {
            if (runCatching { Repository.instanceCount() }.getOrNull() == expected) return
            delay(200)
        }
        error("instance count never reached $expected")
    }

    /**
     * Re-reads the overlay address every couple of seconds and re-establishes the tun
     * whenever it changes. Reconciling, not a one-shot: an address assignment tears the
     * kernel's nic context down, and on mobile nothing rebuilds it but us.
     */
    private fun startTunJob() {
        tunJob?.cancel()
        tunJob = scope.launch {
            var sent: TunParams? = null
            while (isActive) {
                val params = runCatching { readTunParams() }.getOrNull()
                if (params != null && params != sent) {
                    app.startForegroundService(PactMeshVpnService.startIntent(app, params))
                    sent = params
                }
                delay(RECONCILE_MS)
            }
        }
    }

    private fun stopTun() {
        tunJob?.cancel()
        tunJob = null
        app.startForegroundService(
            Intent(app, PactMeshVpnService::class.java).setAction(PactMeshVpnService.ACTION_STOP)
        )
    }

    /**
     * Null until the network administrator has assigned this device an address. Handing
     * the descriptor over before then gets it silently torn down by the assignment.
     */
    private suspend fun readTunParams(): TunParams? {
        val node = Repository.node() ?: return null
        if (node.ipv4Addr.isEmpty()) return null
        val cfg = Repository.config() ?: return null
        val instanceId = cfg.instanceId ?: return null

        // Peers' exported subnets only. This node's own proxy_cidrs are what it exports
        // to the mesh; routing them into the tun would swallow the phone's own LAN.
        val routes = Repository.routes()
            .filter { it.peerId != node.peerId }
            .flatMap { it.proxyCidrs }
            .map { it.substringBefore("->").trim() }
            .filter { it.isNotEmpty() }
            .distinct()

        return TunParams(
            instanceId = instanceId,
            ipv4 = node.ipv4Addr.substringBefore('/'),
            prefix = node.ipv4Addr.substringAfter('/', "24").toIntOrNull() ?: 24,
            mtu = cfg.mtu ?: DEFAULT_MTU,
            routes = routes,
        )
    }

    /** The user revoked the VPN, or another app took the slot. The core stays up. */
    fun onRevoked() {
        Log.w(TAG, "VPN slot revoked, falling back to co-existence")
        tunJob?.cancel()
        tunJob = null
        scope.launch {
            switch(RunMode.COEXIST)
            _error.value = "VPN 已被系统或其他 App 收回，已切回共存模式"
        }
    }

    fun onTunFailed(cause: Throwable) {
        Log.e(TAG, "tun setup failed", cause)
        tunJob?.cancel()
        tunJob = null
        scope.launch {
            switch(RunMode.COEXIST)
            _error.value = cause.message ?: cause.toString()
        }
    }
}
