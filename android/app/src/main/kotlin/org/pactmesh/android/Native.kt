package org.pactmesh.android

/**
 * The whole native surface. Everything else the app needs — join, peers, stats,
 * ACL — it gets over HTTP from the console this starts on loopback, which is the
 * same console the desktop uses. Only these four have no HTTP equivalent.
 *
 * Every one of them throws [RuntimeException] carrying the Rust-side message.
 */
object Native {
    init {
        System.loadLibrary("pactmesh_android")
    }

    /**
     * Once, from [PactMeshApp.onCreate]. [configDir] becomes the library's config
     * root; [deviceSecret] must be the same bytes on every launch or the sealed
     * device key stops opening — see [DeviceSecret].
     */
    external fun nativeInit(configDir: String, deviceSecret: String, logLevel: String)

    /** Starts the daemon and the console. Safe to call again; the second is a no-op. */
    external fun nativeStart(rpcPort: Int, webPort: Int, token: String): Boolean

    /**
     * Hands a `VpnService.establish()` descriptor to a running instance, or detaches
     * it with `fd <= 0`.
     *
     * The instance must already have its overlay IPv4 — poll `/api/node` until
     * `ipv4_addr` is set. Handing the fd over first gets it silently torn down by the
     * first address assignment.
     *
     * Pass `ParcelFileDescriptor.getFd()` and keep holding the descriptor. Never
     * `detachFd()`: Rust never closes this fd, so nobody would.
     */
    external fun nativeSetTunFd(instanceId: String, fd: Int): Boolean

    /** Stops the daemon and every instance. The process stays initialised. */
    external fun nativeStop()
}
