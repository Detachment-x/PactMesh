//! 选中行 Enter 后的多行 detail 文本生成（纯函数）。modal 渲染复用 help。

use crate::proto::api::instance::{Connector, ConnectorStatus, PeerRoutePair};
use crate::proto::common::StunInfo;
use crate::tui::derive::{PathType, path_type, relay_reason};
use crate::tui::state::JoinRow;

const KB: u64 = 1024;
const MB: u64 = KB * KB;
const GB: u64 = MB * KB;

fn human_bytes(b: u64) -> String {
    if b >= GB {
        format!("{:.1}G", b as f64 / GB as f64)
    } else if b >= MB {
        format!("{:.1}M", b as f64 / MB as f64)
    } else if b >= KB {
        format!("{:.1}K", b as f64 / KB as f64)
    } else {
        format!("{b}B")
    }
}

pub fn peer_detail(pair: &PeerRoutePair, my_stun: &StunInfo) -> String {
    let mut s = String::new();
    let route = pair.route.as_ref();
    let peer = pair.peer.as_ref();

    let hostname = route.map(|r| r.hostname.as_str()).unwrap_or("-");
    let ipv4 = route
        .and_then(|r| r.ipv4_addr.as_ref())
        .map(|i| i.address.as_ref().map(|a| a.addr).unwrap_or(0))
        .map(|n| {
            let o = n.to_be_bytes();
            format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
        })
        .unwrap_or_else(|| "-".into());
    let cost = route.map(|r| r.cost).unwrap_or(0);
    let next_hop = route.map(|r| r.next_hop_peer_id).unwrap_or(0);
    let path_lat_us = route.map(|r| r.path_latency).unwrap_or(0);
    let inst_id = route.map(|r| r.inst_id.as_str()).unwrap_or("-");
    let version = route.map(|r| r.version.as_str()).unwrap_or("-");
    let pid = peer.map(|p| p.peer_id).unwrap_or(0);

    s.push_str(&format!(" hostname  : {hostname}\n"));
    s.push_str(&format!(" peer_id   : {pid}\n"));
    s.push_str(&format!(" ipv4      : {ipv4}\n"));
    s.push_str(&format!(" cost      : {cost}\n"));
    s.push_str(&format!(" next_hop  : {next_hop}\n"));
    s.push_str(&format!(" latency   : {} ms\n", path_lat_us / 1000));
    s.push_str(&format!(" inst_id   : {inst_id}\n"));
    s.push_str(&format!(" version   : {version}\n"));
    let pt = path_type(pair);
    s.push_str(&format!(" path_type : {pt}\n"));
    if !matches!(pt, PathType::Direct) {
        s.push_str(&format!(" relay_why : {}\n", relay_reason(pair, my_stun)));
    }

    if let Some(p) = peer {
        s.push('\n');
        s.push_str(&format!(" conns ({}):\n", p.conns.len()));
        for (i, c) in p.conns.iter().enumerate() {
            let tunnel = c.tunnel.as_ref();
            let tunnel_type = tunnel.map(|t| t.tunnel_type.as_str()).unwrap_or("-");
            let local = tunnel
                .and_then(|t| t.local_addr.as_ref())
                .map(|u| u.url.as_str())
                .unwrap_or("-");
            let remote = tunnel
                .and_then(|t| t.remote_addr.as_ref())
                .map(|u| u.url.as_str())
                .unwrap_or("-");
            let lat_ms = c.stats.as_ref().map(|st| st.latency_us / 1000).unwrap_or(0);
            let rx = c.stats.as_ref().map(|st| st.rx_bytes).unwrap_or(0);
            let tx = c.stats.as_ref().map(|st| st.tx_bytes).unwrap_or(0);
            let closed_marker = if c.is_closed { " CLOSED" } else { "" };
            s.push_str(&format!(
                "  [{i}] {tunnel_type}{closed_marker} loss={:.2}\n      local  = {local}\n      remote = {remote}\n      lat={lat_ms}ms rx={} tx={}\n",
                c.loss_rate,
                human_bytes(rx),
                human_bytes(tx)
            ));
            if !c.features.is_empty() {
                s.push_str(&format!("      feat   = {}\n", c.features.join(",")));
            }
        }
    }

    s
}

pub fn connector_detail(c: &Connector) -> String {
    let url = c.url.as_ref().map(|u| u.url.as_str()).unwrap_or("(no url)");
    let status = match ConnectorStatus::try_from(c.status).unwrap_or(ConnectorStatus::Disconnected)
    {
        ConnectorStatus::Connected => "CONNECTED",
        ConnectorStatus::Connecting => "CONNECTING",
        ConnectorStatus::Disconnected => "DISCONNECTED",
    };
    format!(
        " url    : {url}\n status : {status}\n\n proto 暂无 retry/last_error 字段，详情请看 :!journalctl -u pactmesh-core",
    )
}

pub fn join_detail(row: &JoinRow) -> String {
    let pk_b64 = base64_url(&row.applicant_pk);
    let label = if row.device_label.is_empty() {
        "<no label>"
    } else {
        row.device_label.as_str()
    };
    let hint = if row.hint.is_empty() {
        "<no hint>"
    } else {
        row.hint.as_str()
    };
    format!(
        " applicant_pk : {pk_b64}\n short        : {}\n device_label : {label}\n hint         : {hint}\n trust_domain : {}\n network      : {}\n\n a=approve(passphrase)   d=reject  Esc=close",
        row.applicant_short, row.trust_domain_id_b64, row.network_local_id,
    )
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
