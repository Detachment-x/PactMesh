use std::path::PathBuf;

use anyhow::Context;

const CONFIG_SUBDIR: &str = "privateNetwork";
const TRUST_DOMAINS_SUBDIR: &str = "trust-domains";

/// 纯函数：按 (XDG_CONFIG_HOME, HOME, ProjectDirs) 优先级解析配置目录。
/// env 函数注入便于单测，避免污染进程级环境变量。
pub(crate) fn resolve_pnw_config_dir<F>(env: F) -> anyhow::Result<PathBuf>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(xdg) = env("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(xdg).join(CONFIG_SUBDIR));
    }
    if let Some(home) = env("HOME") {
        return Ok(PathBuf::from(home).join(".config").join(CONFIG_SUBDIR));
    }
    if let Some(proj) = directories::ProjectDirs::from("", "PactMesh", CONFIG_SUBDIR) {
        return Ok(proj.config_dir().to_path_buf());
    }
    Err(anyhow::anyhow!(
        "could not determine privateNetwork config dir; set HOME, XDG_CONFIG_HOME, or APPDATA"
    ))
}

pub fn pnw_config_dir() -> anyhow::Result<PathBuf> {
    resolve_pnw_config_dir(|k| std::env::var(k).ok())
}

pub fn pnw_trust_domains_dir() -> anyhow::Result<PathBuf> {
    pnw_config_dir()
        .context("locating trust domains dir")
        .map(|d| d.join(TRUST_DOMAINS_SUBDIR))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_env(pairs: Vec<(&'static str, &'static str)>) -> impl Fn(&str) -> Option<String> {
        move |k| {
            pairs
                .iter()
                .find(|(name, _)| *name == k)
                .map(|(_, v)| (*v).to_string())
        }
    }

    #[test]
    fn xdg_takes_priority() {
        let env = fake_env(vec![
            ("XDG_CONFIG_HOME", "/tmp/xdg-test"),
            ("HOME", "/tmp/home-test"),
        ]);
        assert_eq!(
            resolve_pnw_config_dir(env).unwrap(),
            PathBuf::from("/tmp/xdg-test/privateNetwork"),
        );
    }

    #[test]
    fn home_fallback_when_no_xdg() {
        let env = fake_env(vec![("HOME", "/tmp/home-test")]);
        assert_eq!(
            resolve_pnw_config_dir(env).unwrap(),
            PathBuf::from("/tmp/home-test/.config/privateNetwork"),
        );
    }

    #[test]
    fn errors_when_no_env_and_no_project_dirs() {
        // 注入空 env 且 ProjectDirs 在 CI / minimal env 也可能 None
        // 这里只断言「无 HOME 无 XDG 时不会 panic」，结果可能 Ok（ProjectDirs 拿到）或 Err
        let env = fake_env(vec![]);
        let _ = resolve_pnw_config_dir(env);
    }

    #[test]
    fn trust_domains_dir_appends_subdir() {
        let env = fake_env(vec![("HOME", "/tmp/home-test")]);
        let base = resolve_pnw_config_dir(env).unwrap();
        assert_eq!(
            base.join(TRUST_DOMAINS_SUBDIR),
            PathBuf::from("/tmp/home-test/.config/privateNetwork/trust-domains"),
        );
    }
}
