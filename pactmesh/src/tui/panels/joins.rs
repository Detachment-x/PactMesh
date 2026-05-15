//! Joins tab：跨所有 trust-domain/network 列出 daemon 端 pending join request。
//!
//! v0 PR-3 仅支持 reject（无需根私钥签名）。Approve 需要解锁 sk_root.age 并本地签
//! MemberCert，留给 PR-4 的命令栏 `:approve <fp_prefix>` 配套 passphrase modal。

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};

use crate::tui::state::Snapshot;

pub fn render(frame: &mut Frame<'_>, snap: &Snapshot, area: Rect, table_state: &mut TableState) {
    let header = Row::new(vec![
        Cell::from("Applicant"),
        Cell::from("Device"),
        Cell::from("Network"),
        Cell::from("Trust Domain"),
        Cell::from("Hint"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = snap
        .pending_joins
        .iter()
        .map(|row| {
            let td_short: String = row.trust_domain_id_b64.chars().take(8).collect();
            let hint = if row.hint.is_empty() {
                "-".into()
            } else {
                row.hint.clone()
            };
            let label = if row.device_label.is_empty() {
                "-".into()
            } else {
                row.device_label.clone()
            };
            Row::new(vec![
                Cell::from(row.applicant_short.clone()).style(Style::default().fg(Color::Cyan)),
                Cell::from(label),
                Cell::from(row.network_local_id.clone()),
                Cell::from(td_short),
                Cell::from(hint),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(10),
        Constraint::Length(20),
        Constraint::Length(18),
        Constraint::Length(10),
        Constraint::Min(20),
    ];
    let title = format!(
        " Joins ({})  —  d=reject  a=approve(cmdbar PR-4) ",
        snap.pending_joins.len()
    );
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().title(title).borders(Borders::ALL))
        .row_highlight_style(Style::default().bg(Color::DarkGray));
    frame.render_stateful_widget(table, area, table_state);
}
