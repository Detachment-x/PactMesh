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

use self::cmd::{Cmd, DaemonAction};
use self::log_tail::LogTail;
use self::state::{
    AppState, JoinRow, RpcClient, new_state, record_error, refresh_all, reject_join_request,
};

#[derive(Copy, Clone, PartialEq, Eq)]
enum Tab {
    Setup,
    Node,
    Peers,
    Joins,
    Connectors,
    Logs,
}
const TABS: [Tab; 6] = [
    Tab::Setup,
    Tab::Node,
    Tab::Peers,
    Tab::Joins,
    Tab::Connectors,
    Tab::Logs,
];

fn tab_label(t: Tab) -> &'static str {
    match t {
        Tab::Node => "Node",
        Tab::Setup => "Setup",
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
    SetupWizard(SetupWizard),
    Filter(String),
    Passphrase { buf: String, action: PendingAction },
    RejectReason { row: JoinRow, reason: String },
    Help(&'static str),
    Detail(String),
}

enum SetupWizard {
    Root {
        fields: SetupRootFields,
        step: RootSetupStep,
        input: String,
    },
    Join {
        fields: SetupJoinFields,
        step: JoinSetupStep,
        input: String,
    },
}

#[derive(Default)]
struct SetupRootFields {
    network: String,
    label: String,
    seed: String,
    listen_port: String,
    rpc_port: String,
    domain_label: String,
}

#[derive(Default)]
struct SetupJoinFields {
    invite: String,
    network: String,
    label: String,
    rpc_port: String,
}

#[derive(Copy, Clone)]
enum RootSetupStep {
    Network,
    Label,
    Seed,
    ListenPort,
    RpcPort,
    DomainLabel,
    Confirm,
}

#[derive(Copy, Clone)]
enum JoinSetupStep {
    Invite,
    Network,
    Label,
    RpcPort,
    Confirm,
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
    ApproveOk {
        short_fp: String,
        label: String,
        version: u64,
    },
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
        Tab::Setup | Tab::Node | Tab::Logs => 0,
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
            InputMode::SetupWizard(wizard) => {
                handle_setup_wizard_key(&mut ui, wizard, k.code, terminal);
            }
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
                    spawn_action(
                        action,
                        std::mem::take(&mut buf),
                        client.clone(),
                        instance.clone(),
                        action_tx.clone(),
                    );
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
                            Err(e) => {
                                ActionResult::RejectErr(format!("{label_with_reason}: {e:#}"))
                            }
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
        Tab::Connectors => snap
            .connectors
            .get(idx)
            .map(panels::detail::connector_detail),
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
            ui.flash_info("connector-level reconnect is not exposed yet — use :daemon restart");
        }
        Cmd::Daemon { action, service } => {
            if let Err(e) = run_daemon_service_action(action, service.as_deref(), terminal) {
                ui.flash_err(format!("daemon command failed: {e:#}"));
            } else {
                ui.flash_ok("daemon command finished");
                ui.force_refresh = true;
            }
        }
        Cmd::SetupRootWizard => {
            ui.mode = InputMode::SetupWizard(SetupWizard::Root {
                fields: SetupRootFields {
                    network: "office-net".to_string(),
                    label: "root-a".to_string(),
                    seed: "tcp://<public-ip>:11010".to_string(),
                    listen_port: "11010".to_string(),
                    rpc_port: "15888".to_string(),
                    domain_label: "home".to_string(),
                },
                step: RootSetupStep::Network,
                input: "office-net".to_string(),
            });
        }
        Cmd::SetupRoot {
            network,
            label,
            seed,
            listen_port,
            rpc_port,
            domain_label,
        } => {
            if let Err(e) = run_setup_root(
                &network,
                &label,
                &seed,
                &listen_port,
                &rpc_port,
                domain_label.as_deref(),
                terminal,
            ) {
                ui.flash_err(format!("setup-root failed: {e:#}"));
            } else {
                ui.flash_ok("setup-root finished");
                ui.force_refresh = true;
            }
        }
        Cmd::SetupJoinWizard => {
            ui.mode = InputMode::SetupWizard(SetupWizard::Join {
                fields: SetupJoinFields {
                    invite: "privatenetwork://join?...".to_string(),
                    network: "office-net".to_string(),
                    label: "node-b".to_string(),
                    rpc_port: "15889".to_string(),
                },
                step: JoinSetupStep::Invite,
                input: "privatenetwork://join?...".to_string(),
            });
        }
        Cmd::SetupJoin {
            invite,
            network,
            label,
            rpc_port,
        } => {
            if let Err(e) = run_setup_join(&invite, &network, &label, &rpc_port, terminal) {
                ui.flash_err(format!("setup-join failed: {e:#}"));
            } else {
                ui.flash_ok("setup-join finished");
                ui.force_refresh = true;
            }
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

fn handle_setup_wizard_key(
    ui: &mut UiState,
    wizard: SetupWizard,
    code: KeyCode,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) {
    match code {
        KeyCode::Esc => ui.flash_info("setup cancelled"),
        KeyCode::Backspace => match wizard {
            SetupWizard::Root {
                fields,
                step,
                mut input,
            } => {
                input.pop();
                ui.mode = InputMode::SetupWizard(SetupWizard::Root {
                    fields,
                    step,
                    input,
                });
            }
            SetupWizard::Join {
                fields,
                step,
                mut input,
            } => {
                input.pop();
                ui.mode = InputMode::SetupWizard(SetupWizard::Join {
                    fields,
                    step,
                    input,
                });
            }
        },
        KeyCode::Char(c) => match wizard {
            SetupWizard::Root {
                fields,
                step,
                mut input,
            } => {
                input.push(c);
                ui.mode = InputMode::SetupWizard(SetupWizard::Root {
                    fields,
                    step,
                    input,
                });
            }
            SetupWizard::Join {
                fields,
                step,
                mut input,
            } => {
                input.push(c);
                ui.mode = InputMode::SetupWizard(SetupWizard::Join {
                    fields,
                    step,
                    input,
                });
            }
        },
        KeyCode::Enter => match wizard {
            SetupWizard::Root {
                mut fields,
                step,
                input,
            } => handle_root_setup_enter(ui, &mut fields, step, input, terminal),
            SetupWizard::Join {
                mut fields,
                step,
                input,
            } => handle_join_setup_enter(ui, &mut fields, step, input, terminal),
        },
        _ => ui.mode = InputMode::SetupWizard(wizard),
    }
}

fn handle_root_setup_enter(
    ui: &mut UiState,
    fields: &mut SetupRootFields,
    step: RootSetupStep,
    input: String,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) {
    let value = input.trim().to_string();
    match step {
        RootSetupStep::Network => {
            fields.network = value;
            ui.mode = root_setup_mode(std::mem::take(fields), RootSetupStep::Label);
        }
        RootSetupStep::Label => {
            fields.label = value;
            ui.mode = root_setup_mode(std::mem::take(fields), RootSetupStep::Seed);
        }
        RootSetupStep::Seed => {
            fields.seed = value;
            ui.mode = root_setup_mode(std::mem::take(fields), RootSetupStep::ListenPort);
        }
        RootSetupStep::ListenPort => {
            fields.listen_port = value;
            ui.mode = root_setup_mode(std::mem::take(fields), RootSetupStep::RpcPort);
        }
        RootSetupStep::RpcPort => {
            fields.rpc_port = value;
            ui.mode = root_setup_mode(std::mem::take(fields), RootSetupStep::DomainLabel);
        }
        RootSetupStep::DomainLabel => {
            fields.domain_label = value;
            ui.mode = root_setup_mode(std::mem::take(fields), RootSetupStep::Confirm);
        }
        RootSetupStep::Confirm => {
            if value.eq_ignore_ascii_case("y") || value.eq_ignore_ascii_case("yes") {
                let fields = std::mem::take(fields);
                if let Err(e) = run_setup_root(
                    &fields.network,
                    &fields.label,
                    &fields.seed,
                    &fields.listen_port,
                    &fields.rpc_port,
                    Some(&fields.domain_label),
                    terminal,
                ) {
                    ui.flash_err(format!("setup-root failed: {e:#}"));
                } else {
                    ui.flash_ok("setup-root finished");
                    ui.force_refresh = true;
                }
            } else {
                ui.flash_info("setup-root cancelled");
            }
        }
    }
}

fn handle_join_setup_enter(
    ui: &mut UiState,
    fields: &mut SetupJoinFields,
    step: JoinSetupStep,
    input: String,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) {
    let value = input.trim().to_string();
    match step {
        JoinSetupStep::Invite => {
            fields.invite = value;
            ui.mode = join_setup_mode(std::mem::take(fields), JoinSetupStep::Network);
        }
        JoinSetupStep::Network => {
            fields.network = value;
            ui.mode = join_setup_mode(std::mem::take(fields), JoinSetupStep::Label);
        }
        JoinSetupStep::Label => {
            fields.label = value;
            ui.mode = join_setup_mode(std::mem::take(fields), JoinSetupStep::RpcPort);
        }
        JoinSetupStep::RpcPort => {
            fields.rpc_port = value;
            ui.mode = join_setup_mode(std::mem::take(fields), JoinSetupStep::Confirm);
        }
        JoinSetupStep::Confirm => {
            if value.eq_ignore_ascii_case("y") || value.eq_ignore_ascii_case("yes") {
                let fields = std::mem::take(fields);
                if let Err(e) = run_setup_join(
                    &fields.invite,
                    &fields.network,
                    &fields.label,
                    &fields.rpc_port,
                    terminal,
                ) {
                    ui.flash_err(format!("setup-join failed: {e:#}"));
                } else {
                    ui.flash_ok("setup-join finished");
                    ui.force_refresh = true;
                }
            } else {
                ui.flash_info("setup-join cancelled");
            }
        }
    }
}

fn root_setup_mode(fields: SetupRootFields, step: RootSetupStep) -> InputMode {
    let input = match step {
        RootSetupStep::Network => fields.network.clone(),
        RootSetupStep::Label => fields.label.clone(),
        RootSetupStep::Seed => fields.seed.clone(),
        RootSetupStep::ListenPort => fields.listen_port.clone(),
        RootSetupStep::RpcPort => fields.rpc_port.clone(),
        RootSetupStep::DomainLabel => fields.domain_label.clone(),
        RootSetupStep::Confirm => "yes".to_string(),
    };
    InputMode::SetupWizard(SetupWizard::Root {
        fields,
        step,
        input,
    })
}

fn join_setup_mode(fields: SetupJoinFields, step: JoinSetupStep) -> InputMode {
    let input = match step {
        JoinSetupStep::Invite => fields.invite.clone(),
        JoinSetupStep::Network => fields.network.clone(),
        JoinSetupStep::Label => fields.label.clone(),
        JoinSetupStep::RpcPort => fields.rpc_port.clone(),
        JoinSetupStep::Confirm => "yes".to_string(),
    };
    InputMode::SetupWizard(SetupWizard::Join {
        fields,
        step,
        input,
    })
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

fn run_daemon_service_action(
    action: DaemonAction,
    service: Option<&str>,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> Result<()> {
    let exe = std::env::current_exe()?;
    let action_arg = match action {
        DaemonAction::Start => "start",
        DaemonAction::Stop => "stop",
        DaemonAction::Restart => "restart",
        DaemonAction::Status => "status",
    };
    let service = service.unwrap_or(env!("CARGO_PKG_NAME"));
    run_shell(
        &format!(
            "{} service --name {} {}",
            shell_quote(&exe.to_string_lossy()),
            shell_quote(service),
            action_arg
        ),
        &HashMap::new(),
        terminal,
    )
}

fn run_setup_root(
    network: &str,
    label: &str,
    seed: &str,
    listen_port: &str,
    rpc_port: &str,
    domain_label: Option<&str>,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> Result<()> {
    let exe = std::env::current_exe()?;
    let exe = shell_quote(&exe.to_string_lossy());
    let domain_label = domain_label.unwrap_or("home");
    let script = format!(
        "set -eu\n\
exe={exe}\n\
core=$(dirname -- \"$exe\")/pactmesh-core\n\
if [ ! -x \"$core\" ]; then echo \"pactmesh-core not found next to $exe: $core\" >&2; exit 1; fi\n\
td_json=$(\"$exe\" trust create-domain --label {domain_label} --json)\n\
printf '%s\\n' \"$td_json\"\n\
td=$(printf '%s' \"$td_json\" | sed -n 's/.*\"trust_domain_id\":\"\\([^\"]*\\)\".*/\\1/p')\n\
if [ -z \"$td\" ]; then echo \"failed to parse trust_domain_id\" >&2; exit 1; fi\n\
\"$exe\" trust create-network \"$td\" {network} --json\n\
\"$exe\" trust bootstrap-self \"$td\" {network} --device-label {label} --json\n\
invite=$(\"$exe\" trust invite \"$td\" {network} --seed {seed} --format url)\n\
printf '%s\\n' \"$invite\"\n\
config_base=${{XDG_CONFIG_HOME:-$HOME/.config}}/privateNetwork\n\
log_dir=${{PNW_TEST_HOME:-.}}\n\
mkdir -p \"$log_dir\"\n\
nohup \"$core\" --network-name {network} --trust-domain-dir \"$config_base/trust-domains/$td\" --network-local-id {network} --rpc-portal 127.0.0.1:{rpc_port} --listeners {listen_port} --no-tun true --disable-ipv6 true --instance-name {label} --console-log-level debug --daemon > \"$log_dir/{label}.log\" 2>&1 &\n\
printf 'started root daemon pid=%s log=%s\\n' \"$!\" \"$log_dir/{label}.log\"\n",
        exe = exe,
        domain_label = shell_quote(domain_label),
        network = shell_quote(network),
        label = shell_quote(label),
        seed = shell_quote(seed),
        listen_port = shell_quote(listen_port),
        rpc_port = shell_quote(rpc_port),
    );
    run_shell(&script, &HashMap::new(), terminal)
}

fn run_setup_join(
    invite: &str,
    network: &str,
    label: &str,
    rpc_port: &str,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> Result<()> {
    let exe = std::env::current_exe()?;
    let exe = shell_quote(&exe.to_string_lossy());
    let script = format!(
        "set -eu\n\
exe={exe}\n\
core=$(dirname -- \"$exe\")/pactmesh-core\n\
if [ ! -x \"$core\" ]; then echo \"pactmesh-core not found next to $exe: $core\" >&2; exit 1; fi\n\
\"$exe\" --rpc-portal 127.0.0.1:{rpc_port} trust accept-invite {invite} --device-label {label} --online --wait-secs 600 --poll-secs 2\n\
log_dir=${{PNW_TEST_HOME:-.}}\n\
mkdir -p \"$log_dir\"\n\
nohup \"$core\" --network-name {network} --network-local-id {network} --rpc-portal 127.0.0.1:{rpc_port} --listeners 11010 --no-tun true --disable-ipv6 true --instance-name {label} --console-log-level debug --daemon > \"$log_dir/{label}.log\" 2>&1 &\n\
printf 'started joiner daemon pid=%s log=%s\\n' \"$!\" \"$log_dir/{label}.log\"\n",
        exe = exe,
        invite = shell_quote(invite),
        network = shell_quote(network),
        label = shell_quote(label),
        rpc_port = shell_quote(rpc_port),
    );
    run_shell(&script, &HashMap::new(), terminal)
}

fn shell_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | ':' | '\\'))
    {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
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
        Tab::Setup => panels::setup::render(frame, snap, chunks[1]),
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
        InputMode::SetupWizard(wizard) => draw_setup_wizard_modal(frame, wizard),
        InputMode::Passphrase { buf, action } => draw_passphrase_modal(frame, buf, action),
        InputMode::RejectReason { row, reason } => draw_reject_modal(frame, row, reason),
        InputMode::Help(text) => draw_text_modal(frame, " Help — any key to close ", text, 70, 60),
        InputMode::Detail(text) => {
            draw_text_modal(frame, " Detail — any key to close ", text, 75, 70)
        }
        _ => {}
    }
}

fn draw_setup_wizard_modal(frame: &mut ratatui::Frame<'_>, wizard: &SetupWizard) {
    let area = centered_rect(72, 55, frame.area());
    frame.render_widget(Clear, area);
    let (title, body) = match wizard {
        SetupWizard::Root {
            fields,
            step,
            input,
        } => (
            " Root Setup ",
            root_setup_lines(fields, *step, input.as_str()),
        ),
        SetupWizard::Join {
            fields,
            step,
            input,
        } => (
            " Joiner Setup ",
            join_setup_lines(fields, *step, input.as_str()),
        ),
    };
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

fn field_line<'a>(name: &'a str, value: String, active: bool) -> Line<'a> {
    let style = if active {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Line::from(vec![
        Span::styled(
            format!("{name:13}: "),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(value, style),
    ])
}

fn root_setup_lines<'a>(
    fields: &'a SetupRootFields,
    step: RootSetupStep,
    input: &'a str,
) -> Vec<Line<'a>> {
    let mut lines = vec![Line::from("Fill fields. Enter accepts, Esc cancels.")];
    lines.push(Line::from(""));
    lines.push(field_line(
        "network",
        field_value(
            &fields.network,
            input,
            matches!(step, RootSetupStep::Network),
        ),
        matches!(step, RootSetupStep::Network),
    ));
    lines.push(field_line(
        "label",
        field_value(&fields.label, input, matches!(step, RootSetupStep::Label)),
        matches!(step, RootSetupStep::Label),
    ));
    lines.push(field_line(
        "seed",
        field_value(&fields.seed, input, matches!(step, RootSetupStep::Seed)),
        matches!(step, RootSetupStep::Seed),
    ));
    lines.push(field_line(
        "listen_port",
        field_value(
            &fields.listen_port,
            input,
            matches!(step, RootSetupStep::ListenPort),
        ),
        matches!(step, RootSetupStep::ListenPort),
    ));
    lines.push(field_line(
        "rpc_port",
        field_value(
            &fields.rpc_port,
            input,
            matches!(step, RootSetupStep::RpcPort),
        ),
        matches!(step, RootSetupStep::RpcPort),
    ));
    lines.push(field_line(
        "domain_label",
        field_value(
            &fields.domain_label,
            input,
            matches!(step, RootSetupStep::DomainLabel),
        ),
        matches!(step, RootSetupStep::DomainLabel),
    ));
    if matches!(step, RootSetupStep::Confirm) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Type yes and Enter to run setup-root.",
            Style::default().fg(Color::Cyan),
        )));
        lines.push(Line::from(format!("confirm: {input}")));
    }
    lines
}

fn join_setup_lines<'a>(
    fields: &'a SetupJoinFields,
    step: JoinSetupStep,
    input: &'a str,
) -> Vec<Line<'a>> {
    let mut lines = vec![Line::from("Fill fields. Enter accepts, Esc cancels.")];
    lines.push(Line::from(""));
    lines.push(field_line(
        "invite",
        field_value(&fields.invite, input, matches!(step, JoinSetupStep::Invite)),
        matches!(step, JoinSetupStep::Invite),
    ));
    lines.push(field_line(
        "network",
        field_value(
            &fields.network,
            input,
            matches!(step, JoinSetupStep::Network),
        ),
        matches!(step, JoinSetupStep::Network),
    ));
    lines.push(field_line(
        "label",
        field_value(&fields.label, input, matches!(step, JoinSetupStep::Label)),
        matches!(step, JoinSetupStep::Label),
    ));
    lines.push(field_line(
        "rpc_port",
        field_value(
            &fields.rpc_port,
            input,
            matches!(step, JoinSetupStep::RpcPort),
        ),
        matches!(step, JoinSetupStep::RpcPort),
    ));
    if matches!(step, JoinSetupStep::Confirm) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Type yes and Enter to run setup-join.",
            Style::default().fg(Color::Cyan),
        )));
        lines.push(Line::from(format!("confirm: {input}")));
    }
    lines
}

fn field_value(committed: &str, input: &str, active: bool) -> String {
    if active {
        format!("{input}█")
    } else {
        committed.to_string()
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
            Span::styled(format!(" ERROR: {err} "), Style::default().fg(Color::Red)),
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

fn draw_passphrase_modal(frame: &mut ratatui::Frame<'_>, buf: &str, action: &PendingAction) {
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
        Line::from(Span::raw("Reason (optional, local flash only — not sent):")),
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
