//! Connectors tab：列出 daemon 已配置的 outbound connector + 状态。
//!
//! v0 PR-3 仅展示。proto 中 `ConnectorManageRpc` 当前只有 `ListConnector`，没有
//! Add/Remove/Reconnect；重连留给 PR-4 的 `:!systemctl restart pactmesh-core`。

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};

use crate::proto::api::instance::ConnectorStatus;
use crate::tui::state::Snapshot;

fn status_label(s: i32) -> (&'static str, Color) {
    match ConnectorStatus::try_from(s).unwrap_or(ConnectorStatus::Disconnected) {
        ConnectorStatus::Connected => ("CONNECTED", Color::Green),
        ConnectorStatus::Connecting => ("CONNECTING", Color::Yellow),
        ConnectorStatus::Disconnected => ("DISCONNECTED", Color::Red),
    }
}

pub fn render(frame: &mut Frame<'_>, snap: &Snapshot, area: Rect, table_state: &mut TableState) {
    let header = Row::new(vec![Cell::from("Status"), Cell::from("URL")])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = snap
        .connectors
        .iter()
        .map(|c| {
            let url = c
                .url
                .as_ref()
                .map(|u| u.url.clone())
                .unwrap_or_else(|| "(no url)".into());
            let (label, color) = status_label(c.status);
            Row::new(vec![
                Cell::from(label).style(Style::default().fg(color)),
                Cell::from(url),
            ])
        })
        .collect();

    let widths = [Constraint::Length(14), Constraint::Min(40)];
    let title = format!(" Connectors ({}) ", snap.connectors.len());
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().title(title).borders(Borders::ALL))
        .row_highlight_style(Style::default().bg(Color::DarkGray));
    frame.render_stateful_widget(table, area, table_state);
}
