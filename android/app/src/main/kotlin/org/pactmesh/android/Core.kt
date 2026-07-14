package org.pactmesh.android

import android.app.Application
import android.util.Log
import java.net.ServerSocket
import java.security.SecureRandom

/**
 * Owns the native core's lifetime and the loopback endpoints it exposes.
 *
 * Both ports are ephemeral rather than well-known. On Android every app can reach
 * `127.0.0.1`, and the daemon's RPC portal has no authentication at all — only an
 * address whitelist, which cannot tell one local app from another. A random port is
 * not a fix, it is a speed bump; the fix is to move console↔daemon off TCP entirely,
 * and that is tracked separately. The console itself is behind a bearer token.
 */
object Core {
    private const val TAG = "pactmesh"

    lateinit var token: String
        private set
    var webPort: Int = 0
        private set

    private var rpcPort: Int = 0
    private var started = false

    fun init(app: Application) {
        Native.nativeInit(app.filesDir.absolutePath, DeviceSecret.load(app), "info")
        token = ByteArray(24).also { SecureRandom().nextBytes(it) }
            .joinToString("") { "%02x".format(it) }
        rpcPort = ephemeralPort()
        webPort = ephemeralPort()
    }

    @Synchronized
    fun start() {
        if (started) return
        Native.nativeStart(rpcPort, webPort, token)
        started = true
        Log.i(TAG, "core up: console on 127.0.0.1:$webPort")
    }

    @Synchronized
    fun stop() {
        if (!started) return
        Native.nativeStop()
        started = false
    }

    /**
     * Racy by nature — the port is free when we look and could be taken before Rust
     * binds it. Nothing on the platform offers better, and a collision surfaces as a
     * loud bind failure from `nativeStart` rather than anything subtle.
     */
    private fun ephemeralPort(): Int = ServerSocket(0).use { it.localPort }
}
