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
     * `no_tun` until S4 — this stage proves the governance path without touching the
     * kernel, so nothing here needs VpnService or its permission prompt.
     */
    suspend fun join(inviteUrl: String, deviceLabel: String) {
        ApiClient.post(
            "/api/network/join",
            ApiClient.json.encodeToString(
                JoinReq(inviteUrl = inviteUrl.trim(), deviceLabel = deviceLabel, noTun = true)
            ),
        )
    }

    suspend fun joinStatus(): List<JoinItem> =
        ApiClient.json.decodeFromString<JoinStatus>(ApiClient.get("/api/network/join-status")).joins

    suspend fun node(): NodeInfo? =
        ApiClient.json.decodeFromString<NodeResponse>(ApiClient.get("/api/node")).nodeInfo

    suspend fun routes(): List<Route> =
        ApiClient.json.decodeFromString<RoutesResponse>(ApiClient.get("/api/routes")).routes
}
