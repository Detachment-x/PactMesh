//! Peers tab：peer 列表 + path_type / relay_reason 派生展示。

use std::net::Ipv4Addr;

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};

use crate::proto::api::instance::PeerRoutePair;
use crate::tui::derive::{PathType, path_type, relay_reason};
use crate::tui::state::Snapshot;

fn ipv4_str(pair: &PeerRoutePair) -> String {
    pair.route
        .as_ref()
        .and_then(|r| r.ipv4_addr.as_ref())
        .and_then(|inet| inet.address.as_ref())
        .map(|a| Ipv4Addr::from(a.addr).to_string())
        .unwrap_or_else(|| "-".into())
}

pub fn render(frame: &mut Frame<'_>, snap: &Snapshot, area: Rect, table_state: &mut TableState) {
    let header = Row::new(vec![
        Cell::from("Hostname"),
        Cell::from("IPv4"),
        Cell::from("Cost"),
        Cell::from("Path"),
        Cell::from("Latency"),
        Cell::from("Reason"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = snap
        .peers
        .iter()
        .map(|pair| {
            let route = pair.route.as_ref();
            let hostname = route
                .map(|r| r.hostname.clone())
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| "-".into());
            let ipv4 = ipv4_str(pair);
            let cost = route
                .map(|r| r.cost.to_string())
                .unwrap_or_else(|| "-".into());
            let pt = path_type(pair);
            let path = pt.to_string();
            let latency = route
                .map(|r| format!("{}ms", r.path_latency))
                .unwrap_or_else(|| "-".into());
            let reason = match pt {
                PathType::Direct => String::new(),
                _ => relay_reason(pair, &snap.stun).to_string(),
            };
            let style = match pt {
                PathType::Direct => Style::default().fg(Color::Green),
                PathType::Relay { .. } => Style::default().fg(Color::Yellow),
                PathType::Trying => Style::default().fg(Color::Cyan),
                PathType::Unknown => Style::default().fg(Color::DarkGray),
            };
            Row::new(vec![
                Cell::from(hostname),
                Cell::from(ipv4),
                Cell::from(cost),
                Cell::from(path).style(style),
                Cell::from(latency),
                Cell::from(reason),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(20),
        Constraint::Length(15),
        Constraint::Length(6),
        Constraint::Length(16),
        Constraint::Length(8),
        Constraint::Min(20),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(format!(" Peers ({}) ", snap.peers.len()))
                .borders(Borders::ALL),
        )
        .row_highlight_style(Style::default().bg(Color::DarkGray));
    frame.render_stateful_widget(table, area, table_state);
}
