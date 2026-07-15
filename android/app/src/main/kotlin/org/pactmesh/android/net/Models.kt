package org.pactmesh.android.net

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

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
    @SerialName("socks5_port") val socks5Port: Int? = null,
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
data class NetworkRef(
    @SerialName("trust_domain_id") val trustDomainId: String,
    @SerialName("network_local_id") val networkLocalId: String,
)

@Serializable
data class MountReq(
    @SerialName("trust_domain_id") val trustDomainId: String,
    @SerialName("network_local_id") val networkLocalId: String,
    @SerialName("no_tun") val noTun: Boolean,
    @SerialName("socks5_port") val socks5Port: Int? = null,
    // Carried over from the live instance's connectors so the remount is not islanded.
    val peers: List<String> = emptyList(),
)

/** Instance ids arrive as uuid structs; nothing here needs more than the count. */
@Serializable
data class InstancesResponse(@SerialName("inst_ids") val instIds: List<JsonElement> = emptyList())

@Serializable
data class NodeInfo(
    @SerialName("peer_id") val peerId: Long = 0,
    /** `"10.243.0.7/24"`, empty until the network administrator assigns an address. */
    @SerialName("ipv4_addr") val ipv4Addr: String = "",
    val hostname: String = "",
)

@Serializable
data class NodeResponse(@SerialName("node_info") val nodeInfo: NodeInfo? = null)

/** Big-endian u32, high octet first — the wire form of every peer address. */
@Serializable
data class Ipv4Addr(val addr: Long = 0) {
    override fun toString(): String =
        (24 downTo 0 step 8).joinToString(".") { ((addr shr it) and 0xff).toString() }
}

@Serializable
data class Ipv4Inet(
    val address: Ipv4Addr = Ipv4Addr(),
    @SerialName("network_length") val networkLength: Int = 0,
) {
    /** Empty rather than a bogus `0.0.0.0` when the peer has no address yet. */
    fun render(): String = if (address.addr == 0L) "" else "$address/$networkLength"
}

@Serializable
data class Route(
    @SerialName("peer_id") val peerId: Long = 0,
    val hostname: String = "",
    val cost: Int = 0,
    @SerialName("path_latency") val pathLatency: Int = 0,
    @SerialName("ipv4_addr") val ipv4Addr: Ipv4Inet? = null,
    @SerialName("proxy_cidrs") val proxyCidrs: List<String> = emptyList(),
)

@Serializable
data class RoutesResponse(val routes: List<Route> = emptyList())

@Serializable
data class NetworkConfig(
    @SerialName("instance_id") val instanceId: String? = null,
    /** `"{trust_domain_id}/{network_local_id}"` — the network's identity, and the only
     *  place the phone has to look for it. */
    @SerialName("network_name") val networkName: String = "",
    @SerialName("network_length") val networkLength: Int = 24,
    @SerialName("peer_urls") val peerUrls: List<String> = emptyList(),
    @SerialName("proxy_cidrs") val proxyCidrs: List<String> = emptyList(),
    @SerialName("no_tun") val noTun: Boolean = false,
    @SerialName("enable_socks5") val enableSocks5: Boolean = false,
    @SerialName("socks5_port") val socks5Port: Int? = null,
    val mtu: Int? = null,
) {
    val trustDomainId: String get() = networkName.substringBefore('/')
    val networkLocalId: String get() = networkName.substringAfter('/')
}

@Serializable
data class ConfigResponse(val config: NetworkConfig? = null)

@Serializable
data class Metric(val name: String = "", val value: Long = 0)

/** Cumulative counters only. Rates are the caller's problem: sample twice, subtract. */
@Serializable
data class StatsResponse(val metrics: List<Metric> = emptyList())

@Serializable
data class DomainInfo(
    @SerialName("trust_domain_id") val trustDomainId: String,
    val label: String? = null,
    val networks: List<String> = emptyList(),
    @SerialName("base_network") val baseNetwork: String? = null,
)
