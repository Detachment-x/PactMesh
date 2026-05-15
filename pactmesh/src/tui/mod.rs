//! pactmesh TUI: ratatui-based interactive console.
//!
//! v0 scope: Node + Peers tabs。Pure RPC pull (in-loop tick + ArcSwap snapshot)。
//! 后续 PR 加：Joins / Connectors / Logs tab、命令栏、Ctrl-Z 挂起、cmdbar。

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
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, TableState, Tabs};
use tokio::sync::Mutex;

use crate::proto::api::instance::InstanceIdentifier;

use self::state::{
    AppState, RpcClient, new_state, record_error, refresh_node_and_peers,
};

#[derive(Copy, Clone, PartialEq, Eq)]
enum Tab {
    Node,
    Peers,
}
const TABS: [Tab; 2] = [Tab::Node, Tab::Peers];

fn tab_label(t: Tab) -> &'static str {
    match t {
        Tab::Node => "Node",
        Tab::Peers => "Peers",
    }
}

const REFRESH_INTERVAL: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// TUI 入口。binary 端建好 RpcClient + InstanceIdentifier 后调进来。
pub async fn run(client: Arc<Mutex<RpcClient>>, instance: InstanceIdentifier) -> Result<()> {
    let state = new_state();
    // 立刻触发首次刷新（避免开屏空白）
    if let Err(e) = refresh_node_and_peers(&client, &instance, &state).await {
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

    // panic hook：还原终端再 panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut tab_index: usize = 0;
    let mut table_state = TableState::default();

    let res = event_loop(
        &mut terminal,
        &state,
        &client,
        &instance,
        &mut tab_index,
        &mut table_state,
    )
    .await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    res
}

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &AppState,
    client: &Arc<Mutex<RpcClient>>,
    instance: &InstanceIdentifier,
    tab_index: &mut usize,
    table_state: &mut TableState,
) -> Result<()> {
    let mut last_refresh = Instant::now();
    loop {
        // 到时间就 in-loop 刷一次（不开 spawn，避免 Send 约束）
        if last_refresh.elapsed() >= REFRESH_INTERVAL {
            if let Err(e) = refresh_node_and_peers(client, instance, state).await {
                record_error(state, &e);
            }
            last_refresh = Instant::now();
        }

        let snap = state.load_full();
        terminal.draw(|frame| {
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
                .select(*tab_index)
                .highlight_style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                );
            frame.render_widget(tabs, chunks[0]);

            match TABS[*tab_index] {
                Tab::Node => panels::node::render(frame, &snap, chunks[1]),
                Tab::Peers => panels::peers::render(frame, &snap, chunks[1], table_state),
            }

            let status = match &snap.last_error {
                Some(e) => Line::from(format!(" ERROR: {e}  | Tab tabs | q quit ")),
                None => Line::from(format!(
                    " peers={} | last refresh={} | Tab/S-Tab tabs | j/k select | q quit ",
                    snap.peers.len(),
                    snap.last_refresh_at.map(|_| "ok").unwrap_or("waiting"),
                )),
            };
            frame.render_widget(
                Paragraph::new(status).style(Style::default().bg(Color::DarkGray)),
                chunks[2],
            );
        })?;

        if poll(POLL_INTERVAL)? {
            if let Event::Key(k) = read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match k.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => break,
                    KeyCode::Tab => *tab_index = (*tab_index + 1) % TABS.len(),
                    KeyCode::BackTab => {
                        *tab_index = if *tab_index == 0 {
                            TABS.len() - 1
                        } else {
                            *tab_index - 1
                        };
                    }
                    KeyCode::Char('r') | KeyCode::Char('R') => {
                        // 强制刷新
                        last_refresh = Instant::now() - REFRESH_INTERVAL;
                    }
                    KeyCode::Char('j') | KeyCode::Down => {
                        let len = state.load().peers.len();
                        if len > 0 {
                            let cur = table_state.selected().unwrap_or(0);
                            table_state.select(Some((cur + 1).min(len - 1)));
                        }
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        let cur = table_state.selected().unwrap_or(0);
                        table_state.select(Some(cur.saturating_sub(1)));
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}
