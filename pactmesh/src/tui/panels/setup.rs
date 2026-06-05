//! Setup tab: first-run state and concrete next commands.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::tui::state::Snapshot;

pub fn render(frame: &mut Frame<'_>, snap: &Snapshot, area: Rect) {
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let muted = Style::default().fg(Color::DarkGray);
    let ok = Style::default().fg(Color::Green);
    let warn = Style::default().fg(Color::Yellow);

    let setup = &snap.setup;
    let mut lines = vec![Line::from(vec![
        Span::styled("Config    : ", bold),
        Span::raw(
            setup
                .trust_domains_dir
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<not resolved>".to_string()),
        ),
    ])];
    lines.push(Line::from(vec![
        Span::styled("Domains   : ", bold),
        Span::raw(setup.trust_domain_count.to_string()),
        Span::raw("  roots="),
        Span::raw(setup.root_domain_count.to_string()),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Networks  : ", bold),
        Span::raw(setup.network_count.to_string()),
        Span::raw("  member-ready="),
        Span::raw(setup.member_network_count.to_string()),
    ]));
    lines.push(Line::from(""));

    if snap.node_info.is_some() {
        lines.push(Line::from(Span::styled("Daemon RPC: connected", ok)));
        lines.push(Line::from(
            "Use Node/Peers/Joins/Connectors/Logs tabs for live operation.",
        ));
    } else {
        lines.push(Line::from(Span::styled("Daemon RPC: not connected", warn)));
        lines.push(Line::from(
            "TUI is still usable for setup guidance, logs, and service control.",
        ));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("Root first run", bold)));
    lines.push(Line::from(
        "  :setup-root office-net root-a tcp://<public-ip>:11010 11010 15888 home",
    ));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("Joiner first run", bold)));
    lines.push(Line::from(
        "  :setup-join <invite-url> office-net node-b 15889",
    ));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("Daemon lifecycle", bold)));
    lines.push(Line::from(
        "  :daemon status | :daemon restart | :daemon start | :daemon stop",
    ));
    lines.push(Line::from(Span::styled(
        "Setup commands run the CLI steps and start pactmesh-core in the background.",
        muted,
    )));

    let block = Block::default().title(" Setup ").borders(Borders::ALL);
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}
