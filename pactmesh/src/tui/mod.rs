//! pactmesh TUI: ratatui-based interactive console.
//!
//! v0 scope: Node / Peers / Joins / Connectors tabs。Pure RPC pull (in-loop tick +
//! ArcSwap snapshot)。Joins 支持 d=reject（inline modal 输入理由）。
//! 后续 PR 加：Logs tab、`:`命令栏（含 :approve passphrase modal）、Ctrl-Z 挂起、
//! `:!shell`。

pub mod derive;
pub mod state;
pub mod panels;

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{Event, KeyCode, KeyEventKind, poll, read};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, TableState, Tabs, Wrap};
use tokio::sync::Mutex;

use crate::proto::api::instance::InstanceIdentifier;

use self::state::{
    AppState, JoinRow, RpcClient, new_state, record_error, refresh_all, reject_join_request,
};

#[derive(Copy, Clone, PartialEq, Eq)]
enum Tab {
    Node,
    Peers,
    Joins,
    Connectors,
}
const TABS: [Tab; 4] = [Tab::Node, Tab::Peers, Tab::Joins, Tab::Connectors];

fn tab_label(t: Tab) -> &'static str {
    match t {
        Tab::Node => "Node",
        Tab::Peers => "Peers",
        Tab::Joins => "Joins",
        Tab::Connectors => "Connectors",
    }
}

const REFRESH_INTERVAL: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const FLASH_TTL: Duration = Duration::from_secs(4);

/// Inline reject modal 输入状态。
struct RejectModal {
    row: JoinRow,
    reason: String,
}

/// TUI 入口。binary 端建好 RpcClient + InstanceIdentifier 后调进来。
pub async fn run(client: Arc<Mutex<RpcClient>>, instance: InstanceIdentifier) -> Result<()> {
    let state = new_state();
    if let Err(e) = refresh_all(&client, &instance, &state).await {
        record_error(&state, &e);
    }
    run_ui(state, client, instance).await
}

async fn run_ui(
    state: AppState,
    client: Arc<Mutex<RpcClient>>,
    instance: InstanceIdentifier,
) -> Result<()> {
    let mut stdout = io::stdout();
    enable_raw_mode()?;
    execute!(stdout, EnterAlternateScreen)?;

    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = event_loop(&mut terminal, &state, &client, &instance).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    res
}

#[derive(Default)]
struct UiState {
    tab_index: usize,
    table_states: [TableState; 4], // 每 tab 独立选择
    modal: Option<RejectModal>,
    flash: Option<(String, Instant, FlashKind)>,
}

#[derive(Copy, Clone)]
enum FlashKind {
    Info,
    Ok,
    Err,
}

impl UiState {
    fn flash_info(&mut self, msg: impl Into<String>) {
        self.flash = Some((msg.into(), Instant::now(), FlashKind::Info));
    }
    fn flash_ok(&mut self, msg: impl Into<String>) {
        self.flash = Some((msg.into(), Instant::now(), FlashKind::Ok));
    }
    fn flash_err(&mut self, msg: impl Into<String>) {
        self.flash = Some((msg.into(), Instant::now(), FlashKind::Err));
    }
    fn current_table_state(&mut self) -> &mut TableState {
        &mut self.table_states[self.tab_index]
    }
}

fn row_count(snap: &state::Snapshot, tab: Tab) -> usize {
    match tab {
        Tab::Node => 0,
        Tab::Peers => snap.peers.len(),
        Tab::Joins => snap.pending_joins.len(),
        Tab::Connectors => snap.connectors.len(),
    }
}

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &AppState,
    client: &Arc<Mutex<RpcClient>>,
    instance: &InstanceIdentifier,
) -> Result<()> {
    let mut ui = UiState::default();
    let mut last_refresh = Instant::now();

    loop {
        if last_refresh.elapsed() >= REFRESH_INTERVAL {
            if let Err(e) = refresh_all(client, instance, state).await {
                record_error(state, &e);
            }
            last_refresh = Instant::now();
        }

        // flash 自动过期
        if let Some((_, t, _)) = &ui.flash {
            if t.elapsed() >= FLASH_TTL {
                ui.flash = None;
            }
        }

        let snap = state.load_full();
        terminal.draw(|frame| draw(frame, &snap, &ui))?;

        if !poll(POLL_INTERVAL)? {
            continue;
        }
        let Event::Key(k) = read()? else { continue };
        if k.kind != KeyEventKind::Press {
            continue;
        }

        // 优先 modal 处理
        if let Some(modal) = ui.modal.as_mut() {
            match k.code {
                KeyCode::Esc => {
                    ui.flash_info("reject cancelled");
                    ui.modal = None;
                }
                KeyCode::Enter => {
                    let modal = ui.modal.take().expect("checked above");
                    let label = format!(
                        "{} ({}/{})",
                        modal.row.applicant_short,
                        modal.row.network_local_id,
                        &modal.row.trust_domain_id_b64.chars().take(8).collect::<String>()
                    );
                    match reject_join_request(client, &modal.row).await {
                        Ok(()) => {
                            ui.flash_ok(format!("rejected {label}"));
                            last_refresh = Instant::now() - REFRESH_INTERVAL;
                        }
                        Err(e) => ui.flash_err(format!("reject {label}: {e:#}")),
                    }
                }
                KeyCode::Backspace => {
                    modal.reason.pop();
                }
                KeyCode::Char(c) => {
                    modal.reason.push(c);
                }
                _ => {}
            }
            continue;
        }

        match k.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => break,
            KeyCode::Tab => ui.tab_index = (ui.tab_index + 1) % TABS.len(),
            KeyCode::BackTab => {
                ui.tab_index = if ui.tab_index == 0 {
                    TABS.len() - 1
                } else {
                    ui.tab_index - 1
                };
            }
            KeyCode::Char('r') => {
                last_refresh = Instant::now() - REFRESH_INTERVAL;
                ui.flash_info("refresh queued");
            }
            KeyCode::Char('j') | KeyCode::Down => {
                let len = row_count(&snap, TABS[ui.tab_index]);
                if len > 0 {
                    let cur = ui.current_table_state().selected().unwrap_or(0);
                    ui.current_table_state().select(Some((cur + 1).min(len - 1)));
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                let cur = ui.current_table_state().selected().unwrap_or(0);
                ui.current_table_state().select(Some(cur.saturating_sub(1)));
            }
            KeyCode::Char('a') if TABS[ui.tab_index] == Tab::Joins => {
                ui.flash_info("approve via cmdbar (:approve) — coming in PR-4");
            }
            KeyCode::Char('d') if TABS[ui.tab_index] == Tab::Joins => {
                let sel = ui.current_table_state().selected();
                if let Some(idx) = sel {
                    if let Some(row) = snap.pending_joins.get(idx) {
                        ui.modal = Some(RejectModal {
                            row: row.clone(),
                            reason: String::new(),
                        });
                    } else {
                        ui.flash_err("no join request at this row");
                    }
                } else {
                    ui.flash_err("select a row with j/k first");
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn draw(frame: &mut ratatui::Frame<'_>, snap: &state::Snapshot, ui: &UiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let titles: Vec<Line<'_>> = TABS.iter().map(|t| Line::from(tab_label(*t))).collect();
    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title(" PactMesh "))
        .select(ui.tab_index)
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, chunks[0]);

    // 借用一个本地 mutable 副本给 stateful widget；不影响 ui.table_states 本身
    let mut ts = ui.table_states[ui.tab_index].clone();
    match TABS[ui.tab_index] {
        Tab::Node => panels::node::render(frame, snap, chunks[1]),
        Tab::Peers => panels::peers::render(frame, snap, chunks[1], &mut ts),
        Tab::Joins => panels::joins::render(frame, snap, chunks[1], &mut ts),
        Tab::Connectors => panels::connectors::render(frame, snap, chunks[1], &mut ts),
    }

    let status = build_status_line(snap, ui);
    frame.render_widget(
        Paragraph::new(status).style(Style::default().bg(Color::DarkGray)),
        chunks[2],
    );

    if let Some(modal) = ui.modal.as_ref() {
        draw_reject_modal(frame, modal);
    }
}

fn build_status_line<'a>(snap: &'a state::Snapshot, ui: &'a UiState) -> Line<'a> {
    if let Some((msg, _, kind)) = ui.flash.as_ref() {
        let color = match kind {
            FlashKind::Info => Color::Cyan,
            FlashKind::Ok => Color::Green,
            FlashKind::Err => Color::Red,
        };
        return Line::from(vec![
            Span::styled(format!(" {msg} "), Style::default().fg(color)),
            Span::raw(" | Tab tabs | q quit "),
        ]);
    }
    if let Some(err) = snap.last_error.as_ref() {
        return Line::from(vec![
            Span::styled(
                format!(" ERROR: {err} "),
                Style::default().fg(Color::Red),
            ),
            Span::raw(" | Tab tabs | r refresh | q quit "),
        ]);
    }
    Line::from(format!(
        " peers={} joins={} connectors={} | last={} | Tab/S-Tab tabs | j/k select | r refresh | d=reject(Joins) a=approve(PR-4) | q quit ",
        snap.peers.len(),
        snap.pending_joins.len(),
        snap.connectors.len(),
        snap.last_refresh_at.map(|_| "ok").unwrap_or("waiting"),
    ))
}

fn draw_reject_modal(frame: &mut ratatui::Frame<'_>, modal: &RejectModal) {
    let area = centered_rect(60, 30, frame.area());
    frame.render_widget(Clear, area);

    let td_short: String = modal.row.trust_domain_id_b64.chars().take(8).collect();
    let mut body: Vec<Line> = Vec::new();
    body.push(Line::from(vec![
        Span::styled("Reject join request", Style::default().add_modifier(Modifier::BOLD)),
    ]));
    body.push(Line::from(""));
    body.push(Line::from(format!(
        "Applicant : {}  ({})",
        modal.row.applicant_short,
        if modal.row.device_label.is_empty() {
            "<no label>"
        } else {
            modal.row.device_label.as_str()
        }
    )));
    body.push(Line::from(format!(
        "Network   : {} / {td_short}…",
        modal.row.network_local_id
    )));
    body.push(Line::from(""));
    body.push(Line::from(vec![
        Span::raw("Reason (optional, not sent — local record only): "),
    ]));
    body.push(Line::from(vec![
        Span::styled(modal.reason.clone(), Style::default().fg(Color::Yellow)),
        Span::styled("█", Style::default().fg(Color::Yellow)),
    ]));
    body.push(Line::from(""));
    body.push(Line::from(vec![Span::styled(
        "[Enter] confirm   [Esc] cancel",
        Style::default().fg(Color::Cyan),
    )]));

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Reject Join Request ")
        .title_alignment(Alignment::Center)
        .style(Style::default().bg(Color::Black));
    frame.render_widget(Paragraph::new(body).block(block).wrap(Wrap { trim: false }), area);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}
