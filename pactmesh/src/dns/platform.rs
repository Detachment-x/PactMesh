use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use super::hosts_writer::HostsError;

pub trait HostsBackend {
    fn read(&self) -> Result<String, HostsError>;
    fn atomic_write(&self, content: &str) -> Result<(), HostsError>;
    fn path(&self) -> &Path;
}

#[derive(Debug, Clone)]
pub struct SystemHostsBackend {
    path: PathBuf,
}

impl Default for SystemHostsBackend {
    fn default() -> Self {
        #[cfg(windows)]
        let path = PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts");
        #[cfg(not(windows))]
        let path = PathBuf::from("/etc/hosts");
        Self { path }
    }
}

impl SystemHostsBackend {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl HostsBackend for SystemHostsBackend {
    fn read(&self) -> Result<String, HostsError> {
        fs::read_to_string(&self.path).map_err(HostsError::Io)
    }

    fn atomic_write(&self, content: &str) -> Result<(), HostsError> {
        let tmp_path = self.path.with_extension("pnw.tmp");
        fs::write(&tmp_path, content).map_err(HostsError::Io)?;
        fs::rename(tmp_path, &self.path).map_err(HostsError::Io)
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug)]
pub struct MockHostsBackend {
    path: PathBuf,
    content: Mutex<String>,
    write_count: Mutex<usize>,
}

impl MockHostsBackend {
    pub fn new(content: impl Into<String>) -> Self {
        Self {
            path: PathBuf::from("/mock/hosts"),
            content: Mutex::new(content.into()),
            write_count: Mutex::new(0),
        }
    }

    pub fn content(&self) -> String {
        self.content.lock().unwrap().clone()
    }

    pub fn write_count(&self) -> usize {
        *self.write_count.lock().unwrap()
    }
}

impl HostsBackend for MockHostsBackend {
    fn read(&self) -> Result<String, HostsError> {
        Ok(self.content())
    }

    fn atomic_write(&self, content: &str) -> Result<(), HostsError> {
        *self.content.lock().unwrap() = content.to_owned();
        *self.write_count.lock().unwrap() += 1;
        Ok(())
    }

    fn path(&self) -> &Path {
        &self.path
    }
}
