package org.pactmesh.android.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import org.pactmesh.android.MainActivity
import org.pactmesh.android.Native
import org.pactmesh.android.R

/**
 * Holds the tun descriptor for the whole time the phone is in VPN mode.
 *
 * Deliberately in the app's own process: the descriptor is handed to the core as a plain
 * integer, which only means anything to the process that opened it.
 */
class PactMeshVpnService : VpnService() {
    private var pfd: ParcelFileDescriptor? = null
    private var attachedTo: String? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, notification())
        if (intent == null || intent.action == ACTION_STOP) {
            detach()
            stopSelf()
            return START_NOT_STICKY
        }
        try {
            establish(intent)
        } catch (e: Throwable) {
            detach()
            stopSelf()
            VpnController.onTunFailed(e)
            return START_NOT_STICKY
        }
        // Not sticky: a restart would arrive with a null intent and no way to know which
        // instance to attach to. VpnController re-sends the parameters when it has them.
        return START_NOT_STICKY
    }

    /**
     * Detach before establishing, never the other way round: `establish()` invalidates
     * the previous descriptor, and the core would keep reading a dead fd.
     */
    private fun establish(intent: Intent) {
        val instanceId = requireNotNull(intent.getStringExtra(EXTRA_INSTANCE_ID)) { "no instance id" }
        val ipv4 = requireNotNull(intent.getStringExtra(EXTRA_IPV4)) { "no address" }
        val prefix = intent.getIntExtra(EXTRA_PREFIX, 24)
        val mtu = intent.getIntExtra(EXTRA_MTU, 1380)
        val routes = intent.getStringArrayListExtra(EXTRA_ROUTES).orEmpty()

        detach()

        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(mtu)
            .addAddress(ipv4, prefix)
            .addRoute(networkAddress(ipv4, prefix), prefix)
            // magic-dns lives at a single address inside the overlay; without an explicit
            // host route to it the resolver never reaches the core.
            .addRoute(MAGIC_DNS, 32)
            .addDnsServer(MAGIC_DNS)
            // Our own mesh sockets must not be routed into the tun we just built.
            .addDisallowedApplication(packageName)
            .setBlocking(false)

        routes.forEach { cidr ->
            val address = cidr.substringBefore('/')
            val length = cidr.substringAfter('/', "32").toIntOrNull() ?: 32
            runCatching { builder.addRoute(address, length) }
                .onFailure { Log.w(TAG, "skipping unusable route $cidr", it) }
        }

        val descriptor = requireNotNull(builder.establish()) { "VPN permission not granted" }
        pfd = descriptor
        // getFd(), not detachFd(): the core is told never to close this descriptor, so if
        // we let go of it nobody ever would.
        check(Native.nativeSetTunFd(instanceId, descriptor.fd)) { "set_tun_fd rejected" }
        attachedTo = instanceId
        Log.i(TAG, "tun up: $ipv4/$prefix mtu=$mtu routes=${routes.size}")
    }

    /** `fd = -1` unhooks the device cleanly and leaves the instance running. */
    private fun detach() {
        attachedTo?.let { runCatching { Native.nativeSetTunFd(it, -1) } }
        runCatching { pfd?.close() }
        attachedTo = null
        pfd = null
    }

    override fun onRevoke() {
        detach()
        stopSelf()
        VpnController.onRevoked()
    }

    override fun onDestroy() {
        detach()
        super.onDestroy()
    }

    private fun notification(): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL_ID) == null) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, getString(R.string.vpn_channel), NotificationManager.IMPORTANCE_LOW)
            )
        }
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.vpn_running))
            .setSmallIcon(R.drawable.ic_tunnel)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }

    private fun networkAddress(ipv4: String, prefix: Int): String {
        val bits = ipv4.split('.').fold(0L) { acc, octet -> (acc shl 8) or (octet.toLongOrNull() ?: 0) }
        val mask = if (prefix == 0) 0L else (0xffffffffL shl (32 - prefix)) and 0xffffffffL
        val network = bits and mask
        return (24 downTo 0 step 8).joinToString(".") { ((network shr it) and 0xff).toString() }
    }

    companion object {
        private const val TAG = "pactmesh"
        private const val CHANNEL_ID = "pactmesh-vpn"
        private const val NOTIFICATION_ID = 1
        private const val MAGIC_DNS = "100.100.100.101"

        const val ACTION_STOP = "org.pactmesh.android.STOP_VPN"
        private const val EXTRA_INSTANCE_ID = "instance_id"
        private const val EXTRA_IPV4 = "ipv4"
        private const val EXTRA_PREFIX = "prefix"
        private const val EXTRA_MTU = "mtu"
        private const val EXTRA_ROUTES = "routes"

        fun startIntent(context: Context, params: TunParams): Intent =
            Intent(context, PactMeshVpnService::class.java)
                .putExtra(EXTRA_INSTANCE_ID, params.instanceId)
                .putExtra(EXTRA_IPV4, params.ipv4)
                .putExtra(EXTRA_PREFIX, params.prefix)
                .putExtra(EXTRA_MTU, params.mtu)
                .putStringArrayListExtra(EXTRA_ROUTES, ArrayList(params.routes))
    }
}
