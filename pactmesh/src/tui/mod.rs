//! pactmesh TUI: ratatui-based interactive console.
//!
//! v0 PR-4: 5 tabs (Node/Peers/Joins/Connectors/Logs) + `:` 命令栏 + passphrase
//! modal + `:!shell` + Ctrl-Z 挂起（unix）+ log file tail（polling）。
//! reject 走独立 reason modal，approve 走 passphrase modal。

pub mod actions;
pub mod cmd;
pub mod derive;
pub mod log_tail;
pub mod panels;
pub mod state;

use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers, poll, read};
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
use tokio::sync::{Mutex, mpsc};

use crate::proto::api::instance::InstanceIdentifier;
use crate::tui::panels::logs::{GrepTemplate, LevelFilter, LogsView};

use self::cmd::Cmd;
use self::log_tail::LogTail;
use self::state::{
    AppState, JoinRow, RpcClient, new_state, record_error, refresh_all, reject_join_request,
};

#[derive(Copy, Clone, PartialEq, Eq)]
enum Tab {
    Node,
    Peers,
    Joins,
    Connectors,
    Logs,
}
const TABS: [Tab; 5] = [
    Tab::Node,
    Tab::Peers,
    Tab::Joins,
    Tab::Connectors,
    Tab::Logs,
];

fn tab_label(t: Tab) -> &'static str {
    match t {
        Tab::Node => "Node",
        Tab::Peers => "Peers",
        Tab::Joins => "Joins",
        Tab::Connectors => "Connectors",
        Tab::Logs => "Logs",
    }
}

const REFRESH_INTERVAL: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const FLASH_TTL: Duration = Duration::from_secs(4);
const LOG_CAP: usize = 5000;

enum InputMode {
    Normal,
    Command(String),
    Filter(String),
    Passphrase {
        buf: String,
        action: PendingAction,
    },
    RejectReason {
        row: JoinRow,
        reason: String,
    },
    Help(&'static str),
    Detail(String),
}

enum PendingAction {
    Approve(JoinRow),
}

#[derive(Copy, Clone)]
enum FlashKind {
    Info,
    Ok,
    Err,
}

enum ActionResult {
    ApproveOk { short_fp: String, label: String, version: u64 },
    ApproveErr(String),
    RejectOk(String),
    RejectErr(String),
}

struct UiState {
    tab_index: usize,
    table_states: [TableState; 5],
    mode: InputMode,
    flash: Option<(String, Instant, FlashKind)>,
    log_buffer: VecDeque<String>,
    log_substring: Option<String>,
    log_level: LevelFilter,
    log_grep: GrepTemplate,
    log_path: Option<PathBuf>,
    env_overrides: HashMap<String, String>,
    should_quit: bool,
    force_refresh: bool,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            tab_index: 0,
            table_states: Default::default(),
            mode: InputMode::Normal,
            flash: None,
            log_buffer: VecDeque::with_capacity(LOG_CAP),
            log_substring: None,
            log_level: LevelFilter::default(),
            log_grep: GrepTemplate::default(),
            log_path: None,
            env_overrides: HashMap::new(),
            should_quit: false,
            force_refresh: false,
        }
    }
}

impl UiState {
    fn flash_info(&mut self, m: impl Into<String>) {
        self.flash = Some((m.into(), Instant::now(), FlashKind::Info));
    }
    fn flash_ok(&mut self, m: impl Into<String>) {
        self.flash = Some((m.into(), Instant::now(), FlashKind::Ok));
    }
    fn flash_err(&mut self, m: impl Into<String>) {
        self.flash = Some((m.into(), Instant::now(), FlashKind::Err));
    }
    fn cur_table_state(&mut self) -> &mut TableState {
        &mut self.table_states[self.tab_index]
    }
    fn push_log(&mut self, line: String) {
        if self.log_buffer.len() == LOG_CAP {
            self.log_buffer.pop_front();
        }
        self.log_buffer.push_back(line);
    }
}

fn row_count(snap: &state::Snapshot, tab: Tab) -> usize {
    match tab {
        Tab::Node | Tab::Logs => 0,
        Tab::Peers => snap.peers.len(),
        Tab::Joins => snap.pending_joins.len(),
        Tab::Connectors => snap.connectors.len(),
    }
}

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

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &AppState,
    client: &Arc<Mutex<RpcClient>>,
    instance: &InstanceIdentifier,
) -> Result<()> {
    let mut ui = UiState::default();
    let initial_log = log_tail::detect_initial_path();
    ui.log_path = initial_log.clone();
    let LogTail {
        mut rx,
        path_tx,
        handle: _log_handle,
    } = log_tail::spawn(initial_log);
    let (action_tx, mut action_rx) = mpsc::unbounded_channel::<ActionResult>();

    let mut last_refresh = Instant::now() - REFRESH_INTERVAL;

    loop {
        if ui.should_quit {
            break;
        }
        if ui.force_refresh {
            last_refresh = Instant::now() - REFRESH_INTERVAL;
            ui.force_refresh = false;
        }
        if last_refresh.elapsed() >= REFRESH_INTERVAL {
            if let Err(e) = refresh_all(client, instance, state).await {
                record_error(state, &e);
            }
            last_refresh = Instant::now();
        }

        // 收 log tail
        for _ in 0..512 {
            match rx.try_recv() {
                Ok(line) => ui.push_log(line),
                Err(_) => break,
            }
        }
        // 收异步动作结果
        while let Ok(r) = action_rx.try_recv() {
            match r {
                ActionResult::ApproveOk {
                    short_fp,
                    label,
                    version,
                } => {
                    ui.flash_ok(format!(
                        "approved {short_fp}  label='{label}'  net version={version}"
                    ));
                    last_refresh = Instant::now() - REFRESH_INTERVAL;
                }
                ActionResult::ApproveErr(e) => ui.flash_err(format!("approve failed: {e}")),
                ActionResult::RejectOk(s) => {
                    ui.flash_ok(format!("rejected {s}"));
                    last_refresh = Instant::now() - REFRESH_INTERVAL;
                }
                ActionResult::RejectErr(e) => ui.flash_err(format!("reject failed: {e}")),
            }
        }

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

        if matches!(&ui.mode, InputMode::Normal)
            && k.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(k.code, KeyCode::Char('c'))
        {
            break;
        }
        if matches!(&ui.mode, InputMode::Normal)
            && k.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(k.code, KeyCode::Char('z'))
        {
            #[cfg(unix)]
            {
                if let Err(e) = suspend(terminal) {
                    ui.flash_err(format!("suspend failed: {e:#}"));
                } else {
                    ui.flash_info("resumed");
                }
            }
            #[cfg(not(unix))]
            {
                ui.flash_info("Ctrl-Z 在 Win 不可用：用 :!cmd 或开第二个 tab");
            }
            continue;
        }

        // mode 路由
        match std::mem::replace(&mut ui.mode, InputMode::Normal) {
            InputMode::Normal => {
                handle_normal_key(
                    &mut ui,
                    k.code,
                    &snap,
                    client.clone(),
                    instance.clone(),
                    action_tx.clone(),
                );
            }
            InputMode::Command(mut buf) => match k.code {
                KeyCode::Esc => {}
                KeyCode::Enter => dispatch_cmd(
                    &buf,
                    &mut ui,
                    &snap,
                    client.clone(),
                    instance.clone(),
                    action_tx.clone(),
                    terminal,
                    &path_tx,
                ),
                KeyCode::Backspace => {
                    buf.pop();
                    ui.mode = InputMode::Command(buf);
                }
                KeyCode::Char(c) => {
                    buf.push(c);
                    ui.mode = InputMode::Command(buf);
                }
                _ => ui.mode = InputMode::Command(buf),
            },
            InputMode::Filter(mut buf) => match k.code {
                KeyCode::Esc => {
                    ui.log_substring = None;
                }
                KeyCode::Enter => {
                    ui.log_substring = if buf.is_empty() { None } else { Some(buf) };
                }
                KeyCode::Backspace => {
                    buf.pop();
                    ui.mode = InputMode::Filter(buf);
                }
                KeyCode::Char(c) => {
                    buf.push(c);
                    ui.mode = InputMode::Filter(buf);
                }
                _ => ui.mode = InputMode::Filter(buf),
            },
            InputMode::Passphrase { mut buf, action } => match k.code {
                KeyCode::Esc => {
                    ui.flash_info("approve cancelled");
                }
                KeyCode::Enter => {
                    spawn_action(action, std::mem::take(&mut buf), client.clone(), instance.clone(), action_tx.clone());
                    ui.flash_info("approving…");
                }
                KeyCode::Backspace => {
                    buf.pop();
                    ui.mode = InputMode::Passphrase { buf, action };
                }
                KeyCode::Char(c) => {
                    buf.push(c);
                    ui.mode = InputMode::Passphrase { buf, action };
                }
                _ => ui.mode = InputMode::Passphrase { buf, action },
            },
            InputMode::RejectReason { row, mut reason } => match k.code {
                KeyCode::Esc => {
                    ui.flash_info("reject cancelled");
                }
                KeyCode::Enter => {
                    let label = format!(
                        "{} ({}/{})",
                        row.applicant_short,
                        row.network_local_id,
                        &row.trust_domain_id_b64.chars().take(8).collect::<String>()
                    );
                    let client_c = client.clone();
                    let row_c = row.clone();
                    let tx = action_tx.clone();
                    let reason_taken = std::mem::take(&mut reason);
                    tokio::spawn(async move {
                        let r = reject_join_request(&client_c, &row_c).await;
                        let label_with_reason = if reason_taken.is_empty() {
                            label
                        } else {
                            format!("{label} reason='{reason_taken}'")
                        };
                        let _ = tx.send(match r {
                            Ok(()) => ActionResult::RejectOk(label_with_reason),
                            Err(e) => ActionResult::RejectErr(format!("{label_with_reason}: {e:#}")),
                        });
                    });
                }
                KeyCode::Backspace => {
                    reason.pop();
                    ui.mode = InputMode::RejectReason { row, reason };
                }
                KeyCode::Char(c) => {
                    reason.push(c);
                    ui.mode = InputMode::RejectReason { row, reason };
                }
                _ => ui.mode = InputMode::RejectReason { row, reason },
            },
            InputMode::Help(_) | InputMode::Detail(_) => {} // 任意键关闭
        }
    }
    Ok(())
}

fn handle_normal_key(
    ui: &mut UiState,
    code: KeyCode,
    snap: &state::Snapshot,
    client: Arc<Mutex<RpcClient>>,
    instance: InstanceIdentifier,
    action_tx: mpsc::UnboundedSender<ActionResult>,
) {
    let cur_tab = TABS[ui.tab_index];
    match code {
        KeyCode::Char('q') | KeyCode::Char('Q') => ui.should_quit = true,
        KeyCode::Tab => ui.tab_index = (ui.tab_index + 1) % TABS.len(),
        KeyCode::BackTab => {
            ui.tab_index = if ui.tab_index == 0 {
                TABS.len() - 1
            } else {
                ui.tab_index - 1
            };
        }
        KeyCode::Char('r') => {
            ui.force_refresh = true;
            ui.flash_info("refresh queued");
        }
        KeyCode::Char(':') => ui.mode = InputMode::Command(String::new()),
        KeyCode::Char('?') => ui.mode = InputMode::Help(cmd::help_text(None)),
        KeyCode::Char('/') if cur_tab == Tab::Logs => {
            ui.mode = InputMode::Filter(ui.log_substring.clone().unwrap_or_default());
        }
        KeyCode::Char('l') if cur_tab == Tab::Logs => {
            ui.log_level = ui.log_level.cycle();
        }
        KeyCode::Char('g') if cur_tab == Tab::Logs => {
            ui.log_grep = ui.log_grep.cycle();
        }
        KeyCode::Char('j') | KeyCode::Down => {
            let len = row_count(snap, cur_tab);
            if len > 0 {
                let cur = ui.cur_table_state().selected().unwrap_or(0);
                ui.cur_table_state().select(Some((cur + 1).min(len - 1)));
            }
        }
        KeyCode::Char('k') | KeyCode::Up => {
            let cur = ui.cur_table_state().selected().unwrap_or(0);
            ui.cur_table_state().select(Some(cur.saturating_sub(1)));
        }
        KeyCode::Enter => {
            if let Some(text) = build_detail(ui, snap) {
                ui.mode = InputMode::Detail(text);
            } else {
                ui.flash_info("nothing to expand here");
            }
        }
        KeyCode::Char('a') if cur_tab == Tab::Joins => {
            if let Some(row) = selected_join(ui, snap) {
                ui.mode = InputMode::Passphrase {
                    buf: String::new(),
                    action: PendingAction::Approve(row),
                };
            } else {
                ui.flash_err("select a join row first");
            }
        }
        KeyCode::Char('d') if cur_tab == Tab::Joins => {
            if let Some(row) = selected_join(ui, snap) {
                ui.mode = InputMode::RejectReason {
                    row,
                    reason: String::new(),
                };
            } else {
                ui.flash_err("select a join row first");
            }
        }
        _ => {}
    }
    let _ = (client, instance, action_tx); // silence in some branches
}

fn selected_join(ui: &mut UiState, snap: &state::Snapshot) -> Option<JoinRow> {
    let idx = ui.cur_table_state().selected()?;
    snap.pending_joins.get(idx).cloned()
}

fn build_detail(ui: &mut UiState, snap: &state::Snapshot) -> Option<String> {
    let cur_tab = TABS[ui.tab_index];
    let idx = ui.cur_table_state().selected()?;
    match cur_tab {
        Tab::Peers => snap
            .peers
            .get(idx)
            .map(|p| panels::detail::peer_detail(p, &snap.stun)),
        Tab::Connectors => snap.connectors.get(idx).map(panels::detail::connector_detail),
        Tab::Joins => snap.pending_joins.get(idx).map(panels::detail::join_detail),
        _ => None,
    }
}

fn dispatch_cmd(
    buf: &str,
    ui: &mut UiState,
    snap: &state::Snapshot,
    client: Arc<Mutex<RpcClient>>,
    instance: InstanceIdentifier,
    action_tx: mpsc::UnboundedSender<ActionResult>,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    path_tx: &tokio::sync::watch::Sender<Option<PathBuf>>,
) {
    let parsed = match cmd::parse(buf) {
        Ok(c) => c,
        Err(e) => {
            ui.flash_err(e);
            return;
        }
    };
    match parsed {
        Cmd::Quit => ui.should_quit = true,
        Cmd::Help(t) => ui.mode = InputMode::Help(cmd::help_text(t.as_deref())),
        Cmd::SetEnv { key, value } => {
            ui.env_overrides.insert(key.clone(), value);
            ui.flash_ok(format!("env set: {key} (only for :! children)"));
        }
        Cmd::SetLogFile(path) => {
            let _ = path_tx.send_replace(Some(path.clone()));
            ui.log_path = Some(path);
            ui.flash_ok("log file updated");
        }
        Cmd::Approve(prefix) => match find_pending(snap, &prefix) {
            Ok(row) => {
                ui.mode = InputMode::Passphrase {
                    buf: String::new(),
                    action: PendingAction::Approve(row),
                };
            }
            Err(e) => ui.flash_err(e),
        },
        Cmd::Reject { fp, reason } => match find_pending(snap, &fp) {
            Ok(row) => {
                ui.mode = InputMode::RejectReason {
                    row,
                    reason: reason.unwrap_or_default(),
                };
            }
            Err(e) => ui.flash_err(e),
        },
        Cmd::Revoke(_) => {
            ui.flash_info("not in TUI v0 — use: pactmesh trust revoke <td> <net> <fp>");
        }
        Cmd::Reconnect(_) | Cmd::RestartConnector(_) => {
            ui.flash_info(
                "no daemon RPC for reconnect — try :!systemctl restart pactmesh-core",
            );
        }
        Cmd::ExportBundle(_) => {
            ui.flash_info(
                "not in TUI v0 — use: pactmesh trust bootstrap export <td> --network <net>",
            );
        }
        Cmd::Shell(s) => {
            if let Err(e) = run_shell(&s, &ui.env_overrides, terminal) {
                ui.flash_err(format!("shell failed: {e:#}"));
            } else {
                ui.flash_info("shell exited");
            }
        }
    }
    let _ = (client, instance, action_tx);
}

fn find_pending(snap: &state::Snapshot, prefix: &str) -> Result<JoinRow, String> {
    let lower = prefix.to_ascii_lowercase();
    let matches: Vec<&JoinRow> = snap
        .pending_joins
        .iter()
        .filter(|r| r.applicant_short.to_ascii_lowercase().starts_with(&lower))
        .collect();
    match matches.len() {
        0 => Err(format!("no pending join with applicant prefix '{prefix}'")),
        1 => Ok(matches[0].clone()),
        n => Err(format!("ambiguous prefix '{prefix}' matches {n} requests")),
    }
}

fn spawn_action(
    action: PendingAction,
    passphrase: String,
    client: Arc<Mutex<RpcClient>>,
    instance: InstanceIdentifier,
    tx: mpsc::UnboundedSender<ActionResult>,
) {
    match action {
        PendingAction::Approve(row) => {
            tokio::spawn(async move {
                let pp = passphrase;
                let r = actions::approve_join(&client, &instance, &row, &pp).await;
                drop(pp);
                let _ = tx.send(match r {
                    Ok(o) => ActionResult::ApproveOk {
                        short_fp: o.short_fp,
                        label: o.device_label,
                        version: o.network_state_version,
                    },
                    Err(e) => ActionResult::ApproveErr(format!("{e:#}")),
                });
            });
        }
    }
}

fn run_shell(
    cmdline: &str,
    env_overrides: &HashMap<String, String>,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;

    #[cfg(unix)]
    let mut cmd = {
        let mut c = Command::new("sh");
        c.arg("-c").arg(cmdline);
        c
    };
    #[cfg(not(unix))]
    let mut cmd = {
        let mut c = Command::new("cmd");
        c.arg("/c").arg(cmdline);
        c
    };
    for (k, v) in env_overrides {
        cmd.env(k, v);
    }
    let status = cmd.status();

    eprintln!("\n[pactmesh tui] press Enter to return…");
    let mut sink = String::new();
    let _ = io::stdin().read_line(&mut sink);

    enable_raw_mode()?;
    execute!(terminal.backend_mut(), EnterAlternateScreen)?;
    terminal.clear()?;
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(anyhow::anyhow!("shell exited {s}")),
        Err(e) => Err(anyhow::anyhow!(e)),
    }
}

#[cfg(unix)]
fn suspend(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    use nix::sys::signal::{Signal, raise};
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    raise(Signal::SIGTSTP).map_err(|e| anyhow::anyhow!(e))?;
    enable_raw_mode()?;
    execute!(terminal.backend_mut(), EnterAlternateScreen)?;
    terminal.clear()?;
    Ok(())
}

fn draw(frame: &mut ratatui::Frame<'_>, snap: &state::Snapshot, ui: &UiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
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

    let mut ts = ui.table_states[ui.tab_index].clone();
    match TABS[ui.tab_index] {
        Tab::Node => panels::node::render(frame, snap, chunks[1]),
        Tab::Peers => panels::peers::render(frame, snap, chunks[1], &mut ts),
        Tab::Joins => panels::joins::render(frame, snap, chunks[1], &mut ts),
        Tab::Connectors => panels::connectors::render(frame, snap, chunks[1], &mut ts),
        Tab::Logs => panels::logs::render(
            frame,
            LogsView {
                buffer: &ui.log_buffer,
                substring: ui.log_substring.as_deref(),
                level: ui.log_level,
                grep: ui.log_grep,
                path_hint: ui.log_path.as_ref().and_then(|p| p.to_str()),
            },
            chunks[1],
        ),
    }

    frame.render_widget(Paragraph::new(cmd_bar_line(ui)), chunks[2]);
    frame.render_widget(
        Paragraph::new(status_line(snap, ui)).style(Style::default().bg(Color::DarkGray)),
        chunks[3],
    );

    match &ui.mode {
        InputMode::Passphrase { buf, action } => draw_passphrase_modal(frame, buf, action),
        InputMode::RejectReason { row, reason } => draw_reject_modal(frame, row, reason),
        InputMode::Help(text) => draw_text_modal(frame, " Help — any key to close ", text, 70, 60),
        InputMode::Detail(text) => draw_text_modal(frame, " Detail — any key to close ", text, 75, 70),
        _ => {}
    }
}

fn cmd_bar_line(ui: &UiState) -> Line<'_> {
    match &ui.mode {
        InputMode::Command(buf) => Line::from(vec![
            Span::styled(":", Style::default().fg(Color::Yellow)),
            Span::raw(buf.clone()),
            Span::styled("█", Style::default().fg(Color::Yellow)),
        ]),
        InputMode::Filter(buf) => Line::from(vec![
            Span::styled("/", Style::default().fg(Color::Cyan)),
            Span::raw(buf.clone()),
            Span::styled("█", Style::default().fg(Color::Cyan)),
        ]),
        _ => Line::from(Span::styled(
            " : command   ? help   /=filter(Logs)   l=level   g=grep   Ctrl-Z suspend ",
            Style::default().fg(Color::DarkGray),
        )),
    }
}

fn status_line<'a>(snap: &'a state::Snapshot, ui: &'a UiState) -> Line<'a> {
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
            Span::raw(" | r refresh | q quit "),
        ]);
    }
    Line::from(format!(
        " peers={} joins={} connectors={} logs={} | last={} | Tab tabs | j/k select | r refresh | a/d (Joins) | q quit ",
        snap.peers.len(),
        snap.pending_joins.len(),
        snap.connectors.len(),
        ui.log_buffer.len(),
        snap.last_refresh_at.map(|_| "ok").unwrap_or("waiting"),
    ))
}

fn draw_passphrase_modal(
    frame: &mut ratatui::Frame<'_>,
    buf: &str,
    action: &PendingAction,
) {
    let area = centered_rect(60, 30, frame.area());
    frame.render_widget(Clear, area);
    let title = match action {
        PendingAction::Approve(row) => format!(
            " Unlock sk_root.age — approve {} ({}) ",
            row.applicant_short, row.network_local_id
        ),
    };
    let mask = "•".repeat(buf.chars().count());
    let body = vec![
        Line::from(""),
        Line::from(Span::styled(
            "Management password (root key passphrase):",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(mask, Style::default().fg(Color::Yellow)),
            Span::styled("█", Style::default().fg(Color::Yellow)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "[Enter] confirm   [Esc] cancel",
            Style::default().fg(Color::Cyan),
        )),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .title_alignment(Alignment::Center)
        .style(Style::default().bg(Color::Black));
    frame.render_widget(
        Paragraph::new(body).block(block).wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_reject_modal(frame: &mut ratatui::Frame<'_>, row: &JoinRow, reason: &str) {
    let area = centered_rect(60, 30, frame.area());
    frame.render_widget(Clear, area);
    let td_short: String = row.trust_domain_id_b64.chars().take(8).collect();
    let body = vec![
        Line::from(Span::styled(
            "Reject join request",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!(
            "Applicant : {} ({})",
            row.applicant_short,
            if row.device_label.is_empty() {
                "<no label>"
            } else {
                row.device_label.as_str()
            }
        )),
        Line::from(format!(
            "Network   : {} / {td_short}…",
            row.network_local_id
        )),
        Line::from(""),
        Line::from(Span::raw(
            "Reason (optional, local flash only — not sent):",
        )),
        Line::from(vec![
            Span::styled(reason.to_string(), Style::default().fg(Color::Yellow)),
            Span::styled("█", Style::default().fg(Color::Yellow)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "[Enter] confirm   [Esc] cancel",
            Style::default().fg(Color::Cyan),
        )),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Reject Join Request ")
        .title_alignment(Alignment::Center)
        .style(Style::default().bg(Color::Black));
    frame.render_widget(
        Paragraph::new(body).block(block).wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_text_modal(
    frame: &mut ratatui::Frame<'_>,
    title: &str,
    text: &str,
    pct_x: u16,
    pct_y: u16,
) {
    let area = centered_rect(pct_x, pct_y, frame.area());
    frame.render_widget(Clear, area);
    let body: Vec<Line> = text.lines().map(|l| Line::from(l.to_string())).collect();
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title.to_string())
        .title_alignment(Alignment::Center)
        .style(Style::default().bg(Color::Black));
    frame.render_widget(
        Paragraph::new(body).block(block).wrap(Wrap { trim: false }),
        area,
    );
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
