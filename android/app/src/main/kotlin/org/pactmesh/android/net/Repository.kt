package org.pactmesh.android.net

import kotlinx.serialization.encodeToString

object Repository {
    suspend fun previewInvite(inviteUrl: String): InvitePreview =
        ApiClient.json.decodeFromString(
            ApiClient.post(
                "/api/network/invite-preview",
                ApiClient.json.encodeToString(mapOf("invite_url" to inviteUrl.trim())),
            )
        )

    /**
     * Returns immediately with `pending`: approval can take an hour, so the console
     * drives the join on a task of its own. Progress shows up in [joinStatus].
     *
     * Always `no_tun` — joining must never raise the system's VPN consent dialog. The
     * proxy port rides along so the network comes up in co-existence mode, which is
     * also what [joinStatus] mounts it with once the certificate lands.
     */
    suspend fun join(inviteUrl: String, deviceLabel: String, socks5Port: Int) {
        ApiClient.post(
            "/api/network/join",
            ApiClient.json.encodeToString(
                JoinReq(
                    inviteUrl = inviteUrl.trim(),
                    deviceLabel = deviceLabel,
                    noTun = true,
                    socks5Port = socks5Port,
                )
            ),
        )
    }

    suspend fun joinStatus(): List<JoinItem> =
        ApiClient.json.decodeFromString<JoinStatus>(ApiClient.get("/api/network/join-status")).joins

    suspend fun node(): NodeInfo? =
        ApiClient.json.decodeFromString<NodeResponse>(ApiClient.get("/api/node")).nodeInfo

    suspend fun routes(): List<Route> =
        ApiClient.json.decodeFromString<RoutesResponse>(ApiClient.get("/api/routes")).routes

    suspend fun instanceCount(): Int =
        ApiClient.json.decodeFromString<InstancesResponse>(ApiClient.get("/api/instances"))
            .instIds.size

    suspend fun config(): NetworkConfig? =
        ApiClient.json.decodeFromString<ConfigResponse>(ApiClient.get("/api/config")).config

    suspend fun stats(): Map<String, Long> =
        ApiClient.json.decodeFromString<StatsResponse>(ApiClient.get("/api/stats"))
            .metrics.associate { it.name to it.value }

    suspend fun domains(): List<DomainInfo> =
        ApiClient.json.decodeFromString(ApiClient.get("/api/domains"))

    /**
     * Not idempotent: mounting a network that is already mounted starts a *second*
     * instance, and every instance-scoped endpoint then fails because the selector is
     * ambiguous. Always [leave] first and wait for [instanceCount] to reach zero.
     */
    suspend fun mount(td: String, nid: String, noTun: Boolean, socks5Port: Int?, peers: List<String>) {
        ApiClient.post(
            "/api/network/mount",
            ApiClient.json.encodeToString(
                MountReq(
                    trustDomainId = td,
                    networkLocalId = nid,
                    noTun = noTun,
                    socks5Port = socks5Port,
                    peers = peers,
                )
            ),
        )
    }

    /** Stops the instance and drops its persisted toml. Certificates stay on disk. */
    suspend fun leave(td: String, nid: String) {
        ApiClient.post(
            "/api/network/leave",
            ApiClient.json.encodeToString(NetworkRef(td, nid)),
        )
    }

    /** Leave, then delete this device's copy of the network — certificates included. */
    suspend fun purgeLocal(td: String, nid: String) {
        ApiClient.post(
            "/api/network/purge-local",
            ApiClient.json.encodeToString(NetworkRef(td, nid)),
        )
    }
}
