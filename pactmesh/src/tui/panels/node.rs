//! Node tab：本机视角 — PeerId、hostname、IPv4、listeners、NAT 类型、public_ip。

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::proto::common::NatType;
use crate::tui::state::Snapshot;

fn nat_label(t: i32) -> String {
    format!("{:?}", NatType::try_from(t).unwrap_or(NatType::Unknown))
}

pub fn render(frame: &mut Frame<'_>, snap: &Snapshot, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    let bold = Style::default().add_modifier(Modifier::BOLD);

    if let Some(n) = snap.node_info.as_ref() {
        lines.push(Line::from(vec![
            Span::styled("PeerId   : ", bold),
            Span::raw(format!("{:#x}", n.peer_id)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Hostname : ", bold),
            Span::raw(n.hostname.clone()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("IPv4     : ", bold),
            Span::raw(n.ipv4_addr.clone()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Version  : ", bold),
            Span::raw(n.version.clone()),
        ]));
        if !n.listeners.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("Listeners: ", bold),
                Span::raw(n.listeners.join(", ")),
            ]));
        }
    } else {
        lines.push(Line::from("(node info not loaded yet)"));
    }

    lines.push(Line::from(""));
    let s = &snap.stun;
    lines.push(Line::from(vec![
        Span::styled("UDP NAT  : ", bold),
        Span::raw(nat_label(s.udp_nat_type)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("TCP NAT  : ", bold),
        Span::raw(nat_label(s.tcp_nat_type)),
    ]));
    if !s.public_ip.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Public IP: ", bold),
            Span::raw(format!(
                "{}  (port {} - {})",
                s.public_ip.join(", "),
                s.min_port,
                s.max_port
            )),
        ]));
    }

    let block = Block::default().title(" Node ").borders(Borders::ALL);
    frame.render_widget(Paragraph::new(lines).block(block), area);
}
