//! Logs tab 的文件 tailer：每 1s 读 path 末尾增量，按行 push 到 mpsc。
//!
//! v0 PR-4：polling 实现，单线程友好。`notify` watcher 留给后续优化。
//! 路径优先级（在 mod.rs 里解析，这里只接 Option<PathBuf>）：
//!   `PNW_TUI_LOG_FILE` env > 启动参数 > `:set-log-file <path>` 现场指定。

use std::io::SeekFrom;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, BufReader};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::watch;
use tokio::task::JoinHandle;

const POLL: Duration = Duration::from_millis(1000);
const STARTUP_TAIL_BYTES: u64 = 64 * 1024; // 启动时回看 64KB，避免一次性灌满

pub struct LogTail {
    pub rx: UnboundedReceiver<String>,
    pub path_tx: watch::Sender<Option<PathBuf>>,
    pub handle: JoinHandle<()>,
}

pub fn spawn(initial: Option<PathBuf>) -> LogTail {
    let (tx, rx) = mpsc::unbounded_channel::<String>();
    let (path_tx, path_rx) = watch::channel(initial);
    let handle = tokio::spawn(run_loop(tx, path_rx));
    LogTail {
        rx,
        path_tx,
        handle,
    }
}

async fn run_loop(tx: UnboundedSender<String>, mut path_rx: watch::Receiver<Option<PathBuf>>) {
    let mut tracker: Option<Tracker> = None;
    loop {
        // 先消费路径切换信号
        let cur_path = path_rx.borrow().clone();
        if tracker.as_ref().map(|t| &t.path) != cur_path.as_ref() {
            tracker = match cur_path {
                Some(p) => match Tracker::open(p, &tx).await {
                    Ok(t) => Some(t),
                    Err(e) => {
                        let _ = tx.send(format!("[log_tail] open failed: {e:#}"));
                        None
                    }
                },
                None => None,
            };
        }
        if let Some(t) = tracker.as_mut() {
            if let Err(e) = t.tick(&tx).await {
                let _ = tx.send(format!("[log_tail] read err: {e:#}"));
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(POLL) => {}
            changed = path_rx.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
    }
}

struct Tracker {
    path: PathBuf,
    file: BufReader<File>,
    pos: u64,
    inode_hint: Option<u64>, // 简陋的 rotation 检测
}

impl Tracker {
    async fn open(path: PathBuf, tx: &UnboundedSender<String>) -> Result<Self> {
        let mut file = File::open(&path)
            .await
            .with_context(|| format!("open {}", path.display()))?;
        let len = file.metadata().await?.len();
        let start = len.saturating_sub(STARTUP_TAIL_BYTES);
        file.seek(SeekFrom::Start(start)).await?;
        // 读完启动 tail 一次性发完
        let mut reader = BufReader::new(file);
        let mut leftover = String::new();
        reader.read_to_string(&mut leftover).await.ok();
        for line in leftover.split_inclusive('\n') {
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if !trimmed.is_empty() {
                let _ = tx.send(trimmed.to_string());
            }
        }
        let pos = start + leftover.len() as u64;
        let inode_hint = inode_of(&path);
        Ok(Self {
            path,
            file: reader,
            pos,
            inode_hint,
        })
    }

    async fn tick(&mut self, tx: &UnboundedSender<String>) -> Result<()> {
        // rotation 探测：当前 inode 与初始不同 → 重开
        if inode_of(&self.path) != self.inode_hint {
            let reopened = Tracker::open(self.path.clone(), tx).await?;
            *self = reopened;
            return Ok(());
        }
        let meta = tokio::fs::metadata(&self.path).await?;
        if meta.len() < self.pos {
            // truncated → seek 0 重读最近 1 page
            let mut f = File::open(&self.path).await?;
            f.seek(SeekFrom::Start(0)).await?;
            self.file = BufReader::new(f);
            self.pos = 0;
        }
        let mut buf = String::new();
        loop {
            buf.clear();
            let n = self.file.read_line(&mut buf).await?;
            if n == 0 {
                break;
            }
            self.pos += n as u64;
            let trimmed = buf.trim_end_matches(['\r', '\n']);
            if !trimmed.is_empty() {
                let _ = tx.send(trimmed.to_string());
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn inode_of(path: &std::path::Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| m.ino())
}

#[cfg(not(unix))]
fn inode_of(_: &std::path::Path) -> Option<u64> {
    None
}

/// 启动时按优先级解析 log file 路径。
pub fn detect_initial_path() -> Option<PathBuf> {
    if let Ok(v) = std::env::var("PNW_TUI_LOG_FILE") {
        if !v.is_empty() {
            return Some(PathBuf::from(v));
        }
    }
    None
}
