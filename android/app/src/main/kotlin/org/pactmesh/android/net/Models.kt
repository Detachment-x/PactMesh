package org.pactmesh.android.net

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class InvitePreview(
    @SerialName("trust_domain_id") val trustDomainId: String,
    @SerialName("network_local_id") val networkLocalId: String,
    @SerialName("domain_label") val domainLabel: String? = null,
    @SerialName("network_name") val networkName: String? = null,
    @SerialName("seed_count") val seedCount: Int = 0,
)

@Serializable
data class JoinReq(
    @SerialName("invite_url") val inviteUrl: String,
    @SerialName("device_label") val deviceLabel: String? = null,
    @SerialName("no_tun") val noTun: Boolean = true,
)

/**
 * `submitting` -> `pending` -> `online`, or `error` / `timeout`.
 *
 * Polling this is not passive: the handler is what mounts the network once the
 * network administrator has approved, so the status only reaches `online` because
 * somebody asked for it.
 */
@Serializable
data class JoinItem(
    @SerialName("trust_domain_id") val trustDomainId: String,
    @SerialName("network_local_id") val networkLocalId: String,
    @SerialName("domain_label") val domainLabel: String? = null,
    @SerialName("network_name") val networkName: String? = null,
    val status: String,
    @SerialName("inst_id") val instId: String? = null,
    val error: String? = null,
)

@Serializable
data class JoinStatus(val joins: List<JoinItem> = emptyList())

@Serializable
data class NodeInfo(
    @SerialName("peer_id") val peerId: Long = 0,
    @SerialName("ipv4_addr") val ipv4Addr: String = "",
    val hostname: String = "",
)

@Serializable
data class NodeResponse(@SerialName("node_info") val nodeInfo: NodeInfo? = null)

@Serializable
data class Route(
    @SerialName("peer_id") val peerId: Long = 0,
    val hostname: String = "",
    val cost: Int = 0,
)

@Serializable
data class RoutesResponse(val routes: List<Route> = emptyList())
