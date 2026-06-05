//! `:` 命令栏的解析器（纯函数 + 单测）。Dispatch 留给 mod.rs/actions.rs。
//!
//! v0 PR-4 范围：approve/reject/revoke/reconnect/restart-connector/export-bundle/
//! set-env/set-log-file/!shell/help/quit。`reason` 仅本地展示（proto 无字段）。

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cmd {
    /// `:approve <fp_prefix>` — 模糊匹配 pending join 的 applicant_short
    Approve(String),
    /// `:reject <fp_prefix> [reason]` — reason 仅本地 flash，daemon proto 无字段
    Reject {
        fp: String,
        reason: Option<String>,
    },
    /// `:revoke <fp_prefix>` — TODO，daemon 侧需 sk_root 签新 network_state
    Revoke(String),
    /// `:accept-root-upgrade [ttl_secs]` — 本机预授权一次性 root 升级（弹口令 modal，默认 120s）
    AcceptRootUpgrade {
        ttl_secs: Option<u32>,
    },
    /// `:relay-grant <foreign_td_hex> [data=true] [holepunch=true] [ttl=<secs>] [remove]`
    /// 运行时增删跨信任域中继授权（写 config relay_serving + 热重载授权表）。
    RelayGrant {
        foreign_td_hex: String,
        remove: bool,
        can_relay_data: bool,
        can_assist_holepunch: bool,
        ttl_secs: u64,
    },
    /// `:reconnect <peer_hostname>` — 当前回退到 :!systemctl restart pactmesh-core
    Reconnect(String),
    /// `:restart-connector <id>` — 同上回退
    RestartConnector(String),
    /// `:daemon <start|stop|restart|status> [service_name]` — manage pactmesh-core service
    Daemon {
        action: DaemonAction,
        service: Option<String>,
    },
    SetupRoot {
        network: String,
        label: String,
        seed: String,
        listen_port: String,
        rpc_port: String,
        domain_label: Option<String>,
    },
    SetupRootWizard,
    SetupJoin {
        invite: String,
        network: String,
        label: String,
        rpc_port: String,
    },
    SetupJoinWizard,
    /// `:export-bundle <td_b64>` — 复制 NetworkBootstrap 到剪贴板
    ExportBundle(String),
    /// `:set-env KEY=VAL` — 仅注入到 :! 子进程，不污染当前
    SetEnv {
        key: String,
        value: String,
    },
    /// `:set-log-file <path>` — 切换 Logs tab 跟踪的文件
    SetLogFile(PathBuf),
    /// `:!cmd` — 临时离开 alt-screen 跑外壳
    Shell(String),
    /// `:q` / `:quit`
    Quit,
    /// `:help [cmd]`
    Help(Option<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonAction {
    Start,
    Stop,
    Restart,
    Status,
}

pub fn parse(line: &str) -> Result<Cmd, String> {
    let line = line.trim();
    if line.is_empty() {
        return Err("empty command".into());
    }
    // `:!shell` 走单独路径，cmd 字符串原样传出（含空格、引号）
    if let Some(rest) = line.strip_prefix('!') {
        let rest = rest.trim_start();
        if rest.is_empty() {
            return Err("usage: :!<shell command>".into());
        }
        return Ok(Cmd::Shell(rest.to_string()));
    }
    let mut iter = line.splitn(2, char::is_whitespace);
    let verb = iter.next().unwrap_or("");
    let rest = iter.next().unwrap_or("").trim();
    match verb {
        "approve" | "a" => {
            let fp = require_arg(rest, "usage: :approve <fp_prefix>")?;
            Ok(Cmd::Approve(fp.to_string()))
        }
        "reject" | "r" => {
            let (fp, reason) = split_first_word(rest);
            let fp = require_arg(fp, "usage: :reject <fp_prefix> [reason]")?;
            Ok(Cmd::Reject {
                fp: fp.to_string(),
                reason: reason.map(str::to_string),
            })
        }
        "revoke" => {
            let fp = require_arg(rest, "usage: :revoke <fp_prefix>")?;
            Ok(Cmd::Revoke(fp.to_string()))
        }
        "accept-root-upgrade" => {
            let ttl_secs = if rest.is_empty() {
                None
            } else {
                Some(
                    rest.parse::<u32>()
                        .map_err(|_| "usage: :accept-root-upgrade [ttl_secs]".to_string())?,
                )
            };
            Ok(Cmd::AcceptRootUpgrade { ttl_secs })
        }
        "relay-grant" => {
            const USAGE: &str = "usage: :relay-grant <foreign_td_hex> [data=true] [holepunch=true] [ttl=<secs>] [remove]";
            let args = words(rest);
            let foreign_td_hex = args.first().ok_or_else(|| USAGE.to_string())?.clone();
            let mut remove = false;
            let mut can_relay_data = false;
            let mut can_assist_holepunch = false;
            let mut ttl_secs = 86_400u64;
            for tok in &args[1..] {
                if tok == "remove" {
                    remove = true;
                    continue;
                }
                let (k, v) = tok
                    .split_once('=')
                    .ok_or_else(|| format!("invalid flag '{tok}' (use key=value or 'remove')"))?;
                match k {
                    "data" | "can_relay_data" => can_relay_data = parse_flag_bool(v)?,
                    "holepunch" | "can_assist_holepunch" => {
                        can_assist_holepunch = parse_flag_bool(v)?
                    }
                    "ttl" | "ttl_secs" => {
                        ttl_secs = v.parse().map_err(|_| format!("invalid ttl '{v}'"))?
                    }
                    _ => return Err(format!("unknown flag '{k}'")),
                }
            }
            Ok(Cmd::RelayGrant {
                foreign_td_hex,
                remove,
                can_relay_data,
                can_assist_holepunch,
                ttl_secs,
            })
        }
        "reconnect" => {
            let peer = require_arg(rest, "usage: :reconnect <peer_hostname>")?;
            Ok(Cmd::Reconnect(peer.to_string()))
        }
        "restart-connector" => {
            let id = require_arg(rest, "usage: :restart-connector <id>")?;
            Ok(Cmd::RestartConnector(id.to_string()))
        }
        "daemon" => {
            let (action, service) = split_first_word(rest);
            let action = match require_arg(
                action,
                "usage: :daemon <start|stop|restart|status> [service_name]",
            )? {
                "start" => DaemonAction::Start,
                "stop" => DaemonAction::Stop,
                "restart" => DaemonAction::Restart,
                "status" => DaemonAction::Status,
                other => return Err(format!("unknown daemon action '{other}'")),
            };
            Ok(Cmd::Daemon {
                action,
                service: service.map(str::to_string),
            })
        }
        "setup-root" => {
            let args = words(rest);
            if args.is_empty() {
                return Ok(Cmd::SetupRootWizard);
            }
            if args.len() < 5 || args.len() > 6 {
                return Err("usage: :setup-root <network> <label> <seed-url> <listen_port> <rpc_port> [domain_label]".into());
            }
            Ok(Cmd::SetupRoot {
                network: args[0].to_string(),
                label: args[1].to_string(),
                seed: args[2].to_string(),
                listen_port: args[3].to_string(),
                rpc_port: args[4].to_string(),
                domain_label: args.get(5).map(|s| s.to_string()),
            })
        }
        "setup-join" => {
            let args = words(rest);
            if args.is_empty() {
                return Ok(Cmd::SetupJoinWizard);
            }
            if args.len() != 4 {
                return Err("usage: :setup-join <invite-url> <network> <label> <rpc_port>".into());
            }
            Ok(Cmd::SetupJoin {
                invite: args[0].to_string(),
                network: args[1].to_string(),
                label: args[2].to_string(),
                rpc_port: args[3].to_string(),
            })
        }
        "export-bundle" => {
            let td = require_arg(rest, "usage: :export-bundle <td_b64>")?;
            Ok(Cmd::ExportBundle(td.to_string()))
        }
        "set-env" => {
            let (k, v) = rest
                .split_once('=')
                .ok_or_else(|| "usage: :set-env KEY=VALUE".to_string())?;
            let k = k.trim();
            if k.is_empty() {
                return Err("set-env: empty key".into());
            }
            Ok(Cmd::SetEnv {
                key: k.to_string(),
                value: v.trim().to_string(),
            })
        }
        "set-log-file" => {
            let path = require_arg(rest, "usage: :set-log-file <path>")?;
            Ok(Cmd::SetLogFile(PathBuf::from(path)))
        }
        "q" | "quit" => Ok(Cmd::Quit),
        "help" | "?" => {
            let topic = if rest.is_empty() {
                None
            } else {
                Some(rest.to_string())
            };
            Ok(Cmd::Help(topic))
        }
        other => Err(format!("unknown command :{other} (try :help)")),
    }
}

fn require_arg<'a>(s: &'a str, err: &str) -> Result<&'a str, String> {
    if s.is_empty() {
        Err(err.to_string())
    } else {
        Ok(s)
    }
}

fn split_first_word(s: &str) -> (&str, Option<&str>) {
    let s = s.trim();
    if s.is_empty() {
        return (s, None);
    }
    match s.split_once(char::is_whitespace) {
        Some((a, b)) => (a, Some(b.trim())),
        None => (s, None),
    }
}

/// 按空白切分，但 `"..."` / `'...'` 内的空白保留为单 token（引号被剥离）。
/// 用于 setup-root/setup-join：含空格的 invite/seed URL 可整体加引号传入。
fn parse_flag_bool(v: &str) -> Result<bool, String> {
    match v {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        other => Err(format!("invalid bool '{other}' (use true/false)")),
    }
}

fn words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut has_token = false;
    for c in s.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None if c == '"' || c == '\'' => {
                quote = Some(c);
                has_token = true;
            }
            None if c.is_whitespace() => {
                if has_token {
                    out.push(std::mem::take(&mut cur));
                    has_token = false;
                }
            }
            None => {
                cur.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        out.push(cur);
    }
    out
}

/// 内嵌 help 文案；mod.rs 显示在 modal 里。
pub fn help_text(topic: Option<&str>) -> &'static str {
    match topic {
        None => HELP_OVERVIEW,
        Some("approve") | Some("a") => {
            "approve <fp>: passphrase modal → 解锁 sk_root → 本地签 cert → daemon RPC → 写 member_certs/<fp>.pem + 更新 network_state"
        }
        Some("reject") | Some("r") => {
            "reject <fp> [reason]: daemon RPC，reason 仅本地 flash（proto 无字段）"
        }
        Some("!") | Some("shell") => {
            ":!cmd → 离开 alt-screen，sh -c (unix) / cmd /c (win)，含 set-env 注入；按任意键回 TUI"
        }
        Some(other) => {
            // 注意：返回的是静态字符串，不能含动态部分；这里保守提示
            let _ = other;
            "no help for that topic"
        }
    }
}

const HELP_OVERVIEW: &str = "\
:approve <fp>          passphrase 后审批
:reject  <fp> [why]    立即拒绝
:revoke  <fp>          TODO（用 CLI: pactmesh trust revoke）
:reconnect <peer>      TODO（用 :!systemctl restart pactmesh-core）
:restart-connector <id> TODO
:daemon <action> [svc] start/stop/restart/status pactmesh-core service
:setup-root             interactive root setup wizard
:setup-root <net> <label> <seed> <listen> <rpc> [domain-label]
:setup-join             interactive joiner setup wizard
:setup-join <invite> <net> <label> <rpc>
:export-bundle <td>    NetworkBootstrap → 剪贴板
:set-env KEY=VAL       注入 :! 子进程
:set-log-file <path>   切换 Logs tab 跟踪
:!<shell>              临时回 shell
:q  /  :quit           退出";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_error() {
        assert!(parse("").is_err());
        assert!(parse("   ").is_err());
    }

    #[test]
    fn unknown_verb() {
        let e = parse("nope").unwrap_err();
        assert!(e.contains("unknown"));
    }

    #[test]
    fn approve_short_and_long() {
        assert_eq!(parse("approve abcd").unwrap(), Cmd::Approve("abcd".into()));
        assert_eq!(parse("a abcd").unwrap(), Cmd::Approve("abcd".into()));
        assert!(parse("approve").is_err());
    }

    #[test]
    fn relay_grant_parses_flags_and_remove() {
        assert_eq!(
            parse("relay-grant abcd123 data=true holepunch=true ttl=600").unwrap(),
            Cmd::RelayGrant {
                foreign_td_hex: "abcd123".into(),
                remove: false,
                can_relay_data: true,
                can_assist_holepunch: true,
                ttl_secs: 600,
            }
        );
        assert_eq!(
            parse("relay-grant abcd123 remove").unwrap(),
            Cmd::RelayGrant {
                foreign_td_hex: "abcd123".into(),
                remove: true,
                can_relay_data: false,
                can_assist_holepunch: false,
                ttl_secs: 86_400,
            }
        );
        assert!(parse("relay-grant").is_err());
        assert!(parse("relay-grant x bogus").is_err());
    }

    #[test]
    fn accept_root_upgrade_parses_optional_ttl() {
        assert_eq!(
            parse("accept-root-upgrade").unwrap(),
            Cmd::AcceptRootUpgrade { ttl_secs: None }
        );
        assert_eq!(
            parse("accept-root-upgrade 300").unwrap(),
            Cmd::AcceptRootUpgrade {
                ttl_secs: Some(300)
            }
        );
        assert!(parse("accept-root-upgrade nope").is_err());
    }

    #[test]
    fn reject_with_and_without_reason() {
        assert_eq!(
            parse("reject abcd").unwrap(),
            Cmd::Reject {
                fp: "abcd".into(),
                reason: None
            }
        );
        assert_eq!(
            parse("reject abcd  bad device  ").unwrap(),
            Cmd::Reject {
                fp: "abcd".into(),
                reason: Some("bad device".into())
            }
        );
    }

    #[test]
    fn shell_passes_through_quotes_and_spaces() {
        assert_eq!(
            parse("!sudo tcpdump -i eth0 -c 50").unwrap(),
            Cmd::Shell("sudo tcpdump -i eth0 -c 50".into())
        );
        assert_eq!(
            parse("! echo \"hello world\"").unwrap(),
            Cmd::Shell("echo \"hello world\"".into())
        );
        assert!(parse("!").is_err());
    }

    #[test]
    fn set_env_split() {
        assert_eq!(
            parse("set-env PNW_LOG=trace").unwrap(),
            Cmd::SetEnv {
                key: "PNW_LOG".into(),
                value: "trace".into()
            }
        );
        assert!(parse("set-env BAD").is_err());
        assert!(parse("set-env =val").is_err());
    }

    #[test]
    fn set_log_file_takes_path() {
        assert_eq!(
            parse("set-log-file /var/log/pactmesh.log").unwrap(),
            Cmd::SetLogFile(PathBuf::from("/var/log/pactmesh.log"))
        );
        assert!(parse("set-log-file").is_err());
    }

    #[test]
    fn daemon_command_parses_action_and_optional_service() {
        assert_eq!(
            parse("daemon restart").unwrap(),
            Cmd::Daemon {
                action: DaemonAction::Restart,
                service: None,
            }
        );
        assert_eq!(
            parse("daemon status pactmesh-core-test").unwrap(),
            Cmd::Daemon {
                action: DaemonAction::Status,
                service: Some("pactmesh-core-test".into()),
            }
        );
        assert!(parse("daemon reload").is_err());
        assert!(parse("daemon").is_err());
    }

    #[test]
    fn setup_commands_parse_required_args() {
        assert_eq!(parse("setup-root").unwrap(), Cmd::SetupRootWizard);
        assert_eq!(parse("setup-join").unwrap(), Cmd::SetupJoinWizard);
        assert_eq!(
            parse("setup-root office-net root-a tcp://1.2.3.4:11010 11010 15888 home").unwrap(),
            Cmd::SetupRoot {
                network: "office-net".into(),
                label: "root-a".into(),
                seed: "tcp://1.2.3.4:11010".into(),
                listen_port: "11010".into(),
                rpc_port: "15888".into(),
                domain_label: Some("home".into()),
            }
        );
        assert_eq!(
            parse("setup-join privatenetwork://join?x office-net node-b 15889").unwrap(),
            Cmd::SetupJoin {
                invite: "privatenetwork://join?x".into(),
                network: "office-net".into(),
                label: "node-b".into(),
                rpc_port: "15889".into(),
            }
        );
        assert!(parse("setup-root office-net root-a").is_err());
        assert!(parse("setup-join invite office-net").is_err());
    }

    #[test]
    fn setup_join_accepts_quoted_url_with_spaces() {
        assert_eq!(
            parse("setup-join \"privatenetwork://join?x=a b\" office-net node-b 15889").unwrap(),
            Cmd::SetupJoin {
                invite: "privatenetwork://join?x=a b".into(),
                network: "office-net".into(),
                label: "node-b".into(),
                rpc_port: "15889".into(),
            }
        );
    }

    #[test]
    fn setup_root_accepts_quoted_seed_with_spaces() {
        assert_eq!(
            parse("setup-root office-net root-a 'tcp://1.2.3.4:11010 x' 11010 15888").unwrap(),
            Cmd::SetupRoot {
                network: "office-net".into(),
                label: "root-a".into(),
                seed: "tcp://1.2.3.4:11010 x".into(),
                listen_port: "11010".into(),
                rpc_port: "15888".into(),
                domain_label: None,
            }
        );
    }

    #[test]
    fn help_topic() {
        assert_eq!(parse("help").unwrap(), Cmd::Help(None));
        assert_eq!(
            parse("help approve").unwrap(),
            Cmd::Help(Some("approve".into()))
        );
        assert_eq!(parse("?").unwrap(), Cmd::Help(None));
    }

    #[test]
    fn quit_aliases() {
        assert_eq!(parse("q").unwrap(), Cmd::Quit);
        assert_eq!(parse("quit").unwrap(), Cmd::Quit);
    }
}
