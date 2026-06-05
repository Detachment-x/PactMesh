//! Logs tab：tail daemon 日志，按级别染色 + 子串/level/grep 过滤。

use std::collections::VecDeque;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum LevelFilter {
    #[default]
    All,
    InfoUp,
    WarnUp,
    ErrOnly,
}

impl LevelFilter {
    pub fn cycle(self) -> Self {
        match self {
            Self::All => Self::InfoUp,
            Self::InfoUp => Self::WarnUp,
            Self::WarnUp => Self::ErrOnly,
            Self::ErrOnly => Self::All,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "ALL",
            Self::InfoUp => "INFO+",
            Self::WarnUp => "WARN+",
            Self::ErrOnly => "ERR",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum GrepTemplate {
    #[default]
    None,
    HolePunch,
    Stun,
    Relay,
    Error,
}

impl GrepTemplate {
    pub fn cycle(self) -> Self {
        match self {
            Self::None => Self::HolePunch,
            Self::HolePunch => Self::Stun,
            Self::Stun => Self::Relay,
            Self::Relay => Self::Error,
            Self::Error => Self::None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "-",
            Self::HolePunch => "hole-punch",
            Self::Stun => "stun",
            Self::Relay => "relay",
            Self::Error => "error",
        }
    }
    fn matches(self, line: &str) -> bool {
        let l = line.to_ascii_lowercase();
        match self {
            Self::None => true,
            Self::HolePunch => l.contains("hole") || l.contains("punch"),
            Self::Stun => l.contains("stun"),
            Self::Relay => l.contains("relay"),
            Self::Error => l.contains("error") || l.contains("err ") || l.contains("warn"),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

fn classify(line: &str) -> Option<Level> {
    // 命中第一个 token 之后的 INFO/WARN/ERROR/DEBUG/TRACE
    let upper = line.to_ascii_uppercase();
    if upper.contains(" ERROR ") || upper.starts_with("ERROR ") || upper.contains("[ERROR]") {
        Some(Level::Error)
    } else if upper.contains(" WARN ") || upper.starts_with("WARN ") || upper.contains("[WARN]") {
        Some(Level::Warn)
    } else if upper.contains(" INFO ") || upper.starts_with("INFO ") || upper.contains("[INFO]") {
        Some(Level::Info)
    } else if upper.contains(" DEBUG ") || upper.starts_with("DEBUG ") || upper.contains("[DEBUG]")
    {
        Some(Level::Debug)
    } else if upper.contains(" TRACE ") || upper.starts_with("TRACE ") || upper.contains("[TRACE]")
    {
        Some(Level::Trace)
    } else {
        None
    }
}

fn level_passes(level: Option<Level>, f: LevelFilter) -> bool {
    let l = level.unwrap_or(Level::Info);
    match f {
        LevelFilter::All => true,
        LevelFilter::InfoUp => matches!(l, Level::Info | Level::Warn | Level::Error),
        LevelFilter::WarnUp => matches!(l, Level::Warn | Level::Error),
        LevelFilter::ErrOnly => l == Level::Error,
    }
}

fn level_color(level: Option<Level>) -> Color {
    match level {
        Some(Level::Error) => Color::Red,
        Some(Level::Warn) => Color::Yellow,
        Some(Level::Info) => Color::White,
        Some(Level::Debug) => Color::DarkGray,
        Some(Level::Trace) => Color::DarkGray,
        None => Color::Gray,
    }
}

pub struct LogsView<'a> {
    pub buffer: &'a VecDeque<String>,
    pub substring: Option<&'a str>,
    pub level: LevelFilter,
    pub grep: GrepTemplate,
    pub path_hint: Option<&'a str>,
}

pub fn render(frame: &mut Frame<'_>, view: LogsView<'_>, area: Rect) {
    let total = view.buffer.len();
    let mut visible_lines: Vec<Line<'_>> = Vec::new();
    let needle = view.substring.map(|s| s.to_ascii_lowercase());
    for raw in view.buffer.iter() {
        let level = classify(raw);
        if !level_passes(level, view.level) {
            continue;
        }
        if !view.grep.matches(raw) {
            continue;
        }
        if let Some(n) = needle.as_deref()
            && !raw.to_ascii_lowercase().contains(n)
        {
            continue;
        }
        let color = level_color(level);
        visible_lines.push(Line::from(Span::styled(
            raw.clone(),
            Style::default().fg(color),
        )));
    }
    let visible_count = visible_lines.len();
    let path_label = view
        .path_hint
        .unwrap_or("(no log file — :set-log-file <path>)");
    let title = format!(
        " Logs ({visible_count}/{total})  l={}  g={}  /={}  src={path_label} ",
        view.level.label(),
        view.grep.label(),
        view.substring.unwrap_or("-"),
    );
    let para = Paragraph::new(visible_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .style(Style::default().add_modifier(Modifier::DIM)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}
