# 部署指南 — PactMesh

本文档说明 PactMesh 的构建、安装与运维。PactMesh 是一个 EasyTier fork，在 EasyTier 数据面之上加了签名信任域、成员证书、ACL、MagicDNS、跨信任域中继借用等能力。

部署模型假设由一个人类运维者（信任域所有者）管理少量节点（通常 2-20 台）。本项目不是控制面 / 多租户产品蓝图。

## 目录

- 先决条件
- 从源码构建
- 文件布局与环境变量
- 两节点 happy path
- TUI 快速搭建
- 配置文件参考
- 作为 systemd 服务运行
- 防火墙与可达性
- 多信任域部署
- 跨信任域中继借用（含运行时授权与强制校验）
- 运维任务（吊销 / 禁用 / 设 hostname / 升级为根 / peer hints）
- Windows 部署（CI 制品 + 真机清单）
- 故障排查

## 先决条件

| 组件 | 要求 | 说明 |
|---|---|---|
| 操作系统 | Linux（Ubuntu 20.04+ / Debian 11+ / Arch 等）、macOS 12+、Windows 10+ | TUN/TAP 支持：Linux 需要内核模块；macOS 用系统 TUN；Windows 用 WinTun 驱动 |
| Rust 工具链 | 1.95 | 由 `rust-toolchain.toml` 锁定 |
| 构建工具 | `protoc 25.5`、`libclang-dev`、C 链接器（`gold` 或 `lld`） | `protoc` ≥ 25 是必须的，因为 build 用到了 `--experimental_allow_proto3_optional` |
| 磁盘 | release `target/` 树约 2.5 GB；产物二进制 `pactmesh-core` ~28 MB + `pactmesh` ~13 MB（release + LTO + strip，默认 features） | |
| 网络端口 | 每节点 1 个 TCP/UDP 监听端口（默认 `11010`） | 端口可配置 |

Ubuntu 20.04 系统包没有 `mold`，需要用 `gold`（`binutils-gold`）并在 `.cargo/config.toml` 里设 `-fuse-ld=gold`。新一些的发行版可直接用 `lld` 或 `mold`。

## 从源码构建

```bash
git clone <your-fork-url> PactMesh
cd PactMesh
# 如果只拿到了源码 tarball：
#   tar xf privatenetwork-src.tgz && cd privatenetwork

# 确认 cargo 和 protoc 在 PATH 上。
export PROTOC=$(command -v protoc)

cargo build --release -p pactmesh
```

`target/release/` 下会产出两个二进制：

- `pactmesh-core` —— 守护进程（长驻，跑数据面 + trust 服务）
- `pactmesh` —— 运维 CLI（签证书、管成员、操作本地 trust 状态）

安装到系统路径：

```bash
sudo install -m 0755 target/release/pactmesh-core /usr/local/bin/
sudo install -m 0755 target/release/pactmesh /usr/local/bin/
```

校验：

```bash
pactmesh --version
pactmesh-core --version
```

## 文件布局与环境变量

`pactmesh` 默认把信任域状态写在 `$HOME/.config/privateNetwork/` 下，布局如下：

```
~/.config/privateNetwork/
├── trust-domains/
│   └── <trust_domain_id>/                       # 每个本机持有的信任域一个目录
│       ├── pk_root.pem                          # PEM 格式（PNW-PK-ROOT label），32 字节 Ed25519 根公钥
│       ├── sk_root.age                          # age 加密（Argon2id）的根私钥
│       └── networks/
│           └── <network_local_id>/
│               ├── network_state.cbor.pem       # 签名后的 NetworkState payload
│               ├── network_state.v1.cbor.pem    # 历史版本快照
│               ├── member_cert.pem              # 本节点的成员证书（仅成员设备上有）
│               ├── device_id                    # 设备密钥索引
│               └── sk_self.raw                  # 默认未加密设备签名密钥副本
└── devices/
    └── default/
        ├── pk_self.pem                          # 默认设备公钥
        └── sk_self.raw                          # 默认未加密设备签名密钥
```

管理密码由需要 `SK_root` 签名的 CLI 子命令使用（`create-domain`、`create-network`、`bootstrap-self`、`approve`、`revoke`、`disable`、`enable`、`set-hostname`、`unset-hostname`）。可以交互输入，也可以通过 `PNW_ROOT_PASSPHRASE` 或 `--passphrase-file` 提供。daemon 不应常驻持有管理密码。

设备密钥默认写成 `sk_self.raw`，依赖本机文件权限保护，因此 daemon 重启不需要设备密钥密码。如果你显式设置 `PNW_DEVICE_PASSPHRASE` 或设备 `--passphrase-file`，PactMesh 会写 `sk_self.age`；此时 daemon 需要通过 `trust_domain.sk_self_password_env` 指定对应环境变量，例如 `PNW_DEVICE_PASSPHRASE`。

## 两节点 happy path

下面这个例子搭一个两节点的家庭网络。节点 A 是运维者（持 `SK_root`）；节点 B 是新加入设备。

### 在节点 A 上 —— 创建信任域和网络

```bash
# 生成根密钥对。根私钥用 PNW_ROOT_PASSPHRASE 封装。
PNW_ROOT_PASSPHRASE='long-passphrase-please' \
  pactmesh trust create-domain \
    --label home \
    --out-dir "$HOME/.config/privateNetwork/trust-domains"
# 输出中包含 trust_domain_id（PK_root 的 SHA-256），记下来。

# 在信任域内创建一个网络。默认 ACL 动作是 'accept'（默认放行；
# 后续可改 network_state 重新签名收紧规则）。
PNW_ROOT_PASSPHRASE='long-passphrase-please' \
  pactmesh trust create-network <trust_domain_id> home \
    --default-action accept

# 导出 invite bundle 给节点 B 使用。--seed URL 指向新设备能直连的节点。
pactmesh trust invite <trust_domain_id> home \
  --seed tcp://nodea.example.com:11010 \
  --format url \
  --out /tmp/invite.txt
# /tmp/invite.txt 内是 `privatenetwork://join?...` URL。
```

### 传输 invite

通过任意"基本可信"的渠道把 `/tmp/invite.txt` 转给节点 B。invite 只携带公开信息（出借方 `PK_root`、网络 local id、seed 节点地址），不嵌入任何私钥。

### 在节点 B 上 —— 接受 invite

```bash
# 默认（在线）路径：CLI 在 B 本地生成设备密钥，构造 join request，直接连到
# invite 中 seed 节点的「加入受理端口」（= seed 端口 + 1）提交，并原地轮询审批结果。
# 节点 A 审批通过后，CLI 自动拉回签好的 member_cert，写入
# ~/.config/privateNetwork/trust-domains/<td_id>/networks/home/。全程无需人工搬运文件。
pactmesh trust accept-invite "$(cat /tmp/invite.txt)" \
    --device-label nodeb-laptop \
    --hint 'Alice 的 nodeb laptop'
```

> 设备私钥只在 B 本地生成、从不离开 B；invite 只含公开信息；member_cert 经受理端口自动回传。
>
> **隔离网络兜底**：加 `--offline` 时命令只写出 `pending_join_request.cbor.pem` 即止，
> 不联系任何节点——需人工把该文件交给运维者审批，再把回签的 member_cert 拷回 B。
> 仅在 B 无法直连 seed 受理端口时才用。

### 审批 join（在节点 A 上）

在线路径下，invite seed 指向的节点 A 守护进程必须在运行——它会在监听端口 +1 上自动暴露
加入受理端口。运维者在 A 上审批待处理 join：TUI 的 Joins 标签（`:approve <指纹前缀>` /
`:reject`），或 CLI `pactmesh trust list-members --include pending` 配合 approve/reject。
审批用根私钥签发 member_cert，B 端轮询自动取回。

### 拉起数据面

两个节点都需要一份指向信任域的 daemon 配置。最小节点配置：

```toml
# ~/.config/privateNetwork/networks/<td_id>_home.toml
network_name = "home"
hostname = "nodea"          # 另一节点写 "nodeb"
ipv4 = "10.244.0.1"         # 或网络已分配范围内的其他 IP
listeners = ["tcp://0.0.0.0:11010"]
peers = ["tcp://nodea.example.com:11010"]  # 仅 nodeb 需要；nodea 不写

[trust_domain]
domain_dir = "/home/alice/.config/privateNetwork/trust-domains/<td_id>"
network_local_id = "home"
sk_self_password_env = "PNW_DEVICE_PASSPHRASE"
```

启动守护进程：

```bash
pactmesh-core --config-file ~/.config/privateNetwork/networks/<td_id>_home.toml
```

两个守护进程会自动汇合：trust-aware 握手验证对方的成员证书，ACL 从签名 NetworkState 加载，流量经 TUN 接口（默认 `et0`）转发。

## TUI 快速搭建（CLI happy path 的替代）

`pactmesh tui` 是一个终端 UI，驱动与 CLI 相同的守护进程 RPC，外加一次性搭建向导和
服务管理器。它免去手改 TOML，是新节点上最快的路径。

```bash
pactmesh tui                      # 若本地已有守护进程则自动连接
```

在 `:` 提示符下输入命令：

| 命令 | 作用 |
|---|---|
| `:setup-root` | 向导：创建信任域 + 网络并写出节点 TOML，随后拉起本地守护进程。带参形式：`:setup-root <network> <label> <seed-url> <listen_port> <rpc_port> [domain_label]`。 |
| `:setup-join <invite-url> <network> <label> <rpc_port>` | 向导：消费 invite URL，生成设备密钥 + join request，写出成员 TOML。裸 `:setup-join` 打开交互表单。invite URL 加引号后可含空格。 |
| `:daemon <start\|stop\|restart\|status> [service]` | 管理本地 `pactmesh-core` 守护进程。 |
| `:reconnect <peer_hostname>` | 强制重新拨号某 peer（见"peer hints 与 LAN 恢复"）。 |
| `:accept-root-upgrade [ttl_secs]` | 武装本节点以接受远端推送的根密钥（见"将成员升级为根设备"）。 |
| `:relay-grant <foreign_td_hex> [data=true] [holepunch=true] [ttl=<secs>] [remove]` | 运行时增删跨信任域中继授权（见"跨信任域中继借用"）。 |

向导写出的磁盘布局与上文一致，因此 TUI 搭建的节点之后可完全用 CLI 操作，反之亦然。

## 配置文件参考

守护进程 TOML 是标准 EasyTier 配置，外加一个 `[trust_domain]` 段。PactMesh 特有的字段如下：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `trust_domain.domain_dir` | path | 是 | 信任域目录绝对路径（`.../trust-domains/<td_id>/`） |
| `trust_domain.network_local_id` | string | 是 | 信任域内的网络 id；必须能匹配到 `<domain_dir>/networks/<network_local_id>/` 目录 |
| `trust_domain.sk_self_password_env` | string | 是 | 用于解密设备密钥的环境变量名 |
| `trust_domain.relay_serving[]` | table 数组 | 否 | 表示本节点为外部信任域提供中继服务；详见下文"跨信任域中继借用" |

配置优先级：**CLI flag > 环境变量 > TOML 配置**。`pactmesh-core` 上的 trust 域相关 flag：

- `--trust-domain-dir <PATH>` / `ET_TRUST_DOMAIN_DIR`
- `--network-local-id <ID>` / `ET_NETWORK_LOCAL_ID`
- `--sk-self-password-env <VAR>` / `ET_SK_SELF_PASSWORD_ENV`

用 `pactmesh-core --check-config -c <PATH>` 在不启动数据面的情况下校验配置文件。

## 作为 systemd 服务运行

最小化的 unit 文件（按用户级安装方式）：

```ini
# /etc/systemd/system/privatenetwork@.service
[Unit]
Description=PactMesh node (instance %i)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=privatenetwork
Group=privatenetwork
EnvironmentFile=/etc/privatenetwork/%i.env
ExecStart=/usr/local/bin/pactmesh-core --config-file /etc/privatenetwork/%i.toml
Restart=on-failure
RestartSec=5s
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/privatenetwork
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

`/etc/privatenetwork/home.toml`：照上面的配置文件示例，`domain_dir` 指向 `/var/lib/privatenetwork/...` 之内。

启用并启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now privatenetwork@home.service
sudo systemctl status privatenetwork@home.service
journalctl -u privatenetwork@home.service -f
```

如果使用加密设备密钥，env 文件会持有设备密钥密码，权限应收紧到 `0600` 且 root 拥有（`chmod 600 /etc/privatenetwork/home.env; chown root:root /etc/privatenetwork/home.env`）。默认 `sk_self.raw` 路径下，daemon 不需要设备密钥密码。守护进程只需要 `CAP_NET_ADMIN` 来创建 TUN 设备，不需要 root。

## 防火墙与可达性

入站：开放监听端口（默认 `11010/tcp` 与 `11010/udp`；通常两者都声明，EasyTier 任一传输都用得上）。如果配置了多个 listener，逐一开放。

**加入受理端口（根节点必开）**：守护进程在每个 TCP 监听端口 **+1** 上自动暴露加入受理 RPC
（默认 `11011/tcp`）。新设备的在线 `accept-invite` 直接连这个端口提交申请并取回证书。作为
invite seed 的根节点必须从公网放行该端口，否则在线加入会卡在 "Connecting to join admission
endpoint"。不接收加入的纯成员节点可不开。

```bash
# ufw
sudo ufw allow 11010/tcp
sudo ufw allow 11010/udp
sudo ufw allow 11011/tcp   # 加入受理端口（监听端口 + 1）；根节点需要

# firewalld
sudo firewall-cmd --add-port=11010/tcp --permanent
sudo firewall-cmd --add-port=11010/udp --permanent
sudo firewall-cmd --add-port=11011/tcp --permanent   # 加入受理端口
sudo firewall-cmd --reload
```

出站：大多数 NAT 都能被自动穿透（EasyTier 处理 STUN、hole-punching、relay fallback）。如果你有稳定公网地址的中继节点，对应监听端口必须从公网可达。如果所有节点都没有公网地址，可以在朋友的信任域上配置 `trust_domain.relay_serving`，借用他们的中继（见下一节）。

ICMP / IPv4：确保两边的主机防火墙没有过滤 TUN 子网（默认在 10.244.0.0/16 范围内；每网络可配置）。

## 多信任域部署

同一台设备可以以独立成员身份加入多个信任域，每个信任域映射到独立的守护进程实例和独立的配置文件：

```
~/.config/privateNetwork/
├── trust-domains/
│   ├── <td_alice>/
│   │   └── networks/home/    （在 Alice 网络中作为 nodea-laptop 成员）
│   └── <td_bob>/
│       └── networks/team/    （在 Bob 网络中作为 alice-laptop 成员）
└── networks/
    ├── <td_alice>_home.toml
    └── <td_bob>_team.toml
```

跑两个守护进程：

```bash
# Alice 的 home 网络
pactmesh-core --config-file ~/.config/privateNetwork/networks/<td_alice>_home.toml &

# Bob 的 team 网络
pactmesh-core --config-file ~/.config/privateNetwork/networks/<td_bob>_team.toml &
```

如果使用加密设备密钥，在两个配置文件里设不同的 `sk_self_password_env`，让两个守护进程各自解锁自己的设备密钥。systemd 下用模板实例（`privatenetwork@home` 和 `privatenetwork@team`）。

两个网络互不共享密钥也互不共享 ACL 策略。两边流量只能通过主机正常 IP 栈互通（即两个 TUN 接口相互独立）。

## 跨信任域中继借用

借用机制允许信任域 A 的节点使用信任域 B 的中继，而无需合并两个信任域。

### 出借方（信任域 B，运维者 Bob）

1. 把中继节点加进 `TrustDomainMeta.active_relays`（Bob 创建网络或刷新 meta 时签名）。
2. 给信任域 A 签发一条 `OutboundGrant`：

```bash
# 概念示意——实际命令通过守护进程 RPC 和 CLI trust 子命令暴露。
# 授权携带 (foreign_root_pk, foreign_td_id, capabilities, expires_at)，
# 包含在下一个 TrustDomainMeta 修订中。
```

3. 把更新后的 `TrustDomainMeta` 分发给 A（文件复制或 QR 编码的 `NetworkBootstrap` 都行；签名可自验证）。

4. 在 Bob 的中继节点上，配置 `relay_serving` 让守护进程接受来自 A 的中继请求：

```toml
[[trust_domain.relay_serving]]
foreign_root_pk_hex = "abcdef0123...64-hex-chars"
foreign_trust_domain_meta_pem = "/etc/privatenetwork/foreign/td_alice_meta.pem"
can_relay_data = true
can_assist_holepunch = true
expires_at = 1782345600     # unix 秒；应与授权过期时间一致
```

### 借用方（信任域 A）

1. 把 Bob 签好的 `TrustDomainMeta` 放到 A 节点能读到的路径（守护进程从这份 meta 派生 `BorrowedRelayProof`，在与 Bob 的中继握手时附带）。

2. 把 Bob 的中继节点像任何 seed 一样写进 `peers`：

```toml
peers = [
    "tcp://relay.bob.example.com:11010",
]
```

借用证明和能力位由 Bob 的中继节点本地验证，无需中央协调。

### 运行时授权与强制校验

中继授权是端到端**强制校验**的。外域 peer 拨号 Bob 的中继时，中继在转发前先用借用
证明比对授权表：

- `can_relay_data = true` 的授权允许该 peer 中继数据流量。
- `can_assist_holepunch = true` 的授权只允许其借中继协调打洞（控制 / RPC），数据包仍被丢弃。
- 借用证明对应的授权**两项能力都没有**时，连接在握手阶段即被拒绝——没有隐式兜底。

Bob 可在 TUI 中**不重启守护进程**增删授权：

```text
:relay-grant <foreign_td_hex> data=true holepunch=true ttl=86400
:relay-grant <foreign_td_hex> remove
```

这会就地修改运行配置的 `relay_serving` 列表并热重载授权表（省略 `ttl` 时默认 86400 秒）。
改动不落盘 TOML——要在重启后仍生效，需补回 `[[trust_domain.relay_serving]]` 块。

## 运维任务

### 吊销成员（永久）

```bash
PNW_ROOT_PASSPHRASE='...' \
  pactmesh trust revoke <trust_domain_id> home <member_cert_fingerprint> \
    --reason key-compromise \
    --note '2026-05-10 笔记本丢失'
```

吊销不可逆：条目写入 `NetworkState.revoked_certs`，下次签名配置刷新时扩散全网。其他节点会拒绝被吊销指纹的所有流量。

节点应用包含吊销（或禁用）某成员的签名状态时，会**立即作废该 peer 的在用数据面会话**——
现有流量密钥即刻失效、连接被拆。吊销不等待密钥轮换周期：被攻陷的成员在吊销状态到达各节点
的瞬间即被切断。

### 禁用成员（可恢复）

```bash
PNW_ROOT_PASSPHRASE='...' \
  pactmesh trust disable <trust_domain_id> home <member_cert_fingerprint> \
    --until 2026-06-01T00:00:00Z \
    --note '出差禁用'

# 在过期之前主动恢复：
PNW_ROOT_PASSPHRASE='...' \
  pactmesh trust enable <trust_domain_id> home <member_cert_fingerprint>
```

### 设置 hostname（MagicDNS）

```bash
PNW_ROOT_PASSPHRASE='...' \
  pactmesh trust set-hostname <trust_domain_id> home <member_cert_fingerprint> alice-laptop
```

hostname 被签进新的 `MemberCert`（超越上一版）。其他节点会在 hosts 文件中维护一个 `# privateNetwork` 块，每个 active 成员一行。

### 列出成员

```bash
pactmesh trust list-members <trust_domain_id> home --include active
pactmesh trust list-members <trust_domain_id> home --include all --json
```

`--include` 可取 `active | revoked | disabled | pending | all`。

### 列出本地信任域

```bash
pactmesh trust list-domains
```

### 将成员升级为根设备

一个信任域可以有多个持有 `SK_root` 的设备。要把现有成员节点提升为根设备，当前根
通过认证后的 mesh 把（重新封装的）根密钥推给目标。目标**永不**从环境变量读口令——它必须
先显式**武装一次性接受令牌**：

1. 在**目标**节点的 TUI 上武装接受，并输入用于封装即将到来的 `sk_root.age` 的口令：

   ```text
   :accept-root-upgrade            # 默认 TTL；或 ":accept-root-upgrade 300" 给 5 分钟
   ```

   随即弹出口令 modal；令牌一次性，TTL 到期即失效。

2. 从**当前根**触发推送（守护进程 RPC `UpgradePeerToRoot`，经运维 CLI/TUI 暴露）。目标
   消费已武装的令牌，校验 `SK_root` 能派生出预期的 `PK_root`（`pk_root.pem`），然后写出
   `sk_root.age`。此步不签发任何成员证书。

令牌缺失、已用或过期时，目标以 "no armed root-upgrade acceptance" 拒绝推送。重新武装再试。

### peer hints 与 LAN 恢复

每个节点记住最近见过的 peer 地址（"hints"），以便在传输抖动或 IP 变更后无需完整 seed
重握手即可重建直连。要强制立即重拨某个 peer（例如笔记本在网络间迁移后）：

```text
:reconnect <peer_hostname>
```

在同一 LAN 上，节点还通过本地广播互相再发现，因此失去公网 seed 的网络只要成员同段就能持续收敛。

## Windows 部署

PactMesh 的 Windows 二进制由 `windows-x86_64` GitHub Actions 工作流产出（权威 MSVC 构建）。
不支持从 Linux 跨编译到 Windows（`ring` 加密 crate 需要 MSVC 工具链），因此用 CI 制品而非本地跨编译。

### 获取制品

1. 推送到 `main`（命中 `pactmesh/**`、`Cargo.*` 或工作流文件路径），或手动运行工作流
   （`Actions → Windows x86_64 Build → Run workflow`）。
2. run 变绿后下载 `pactmesh-windows-x86_64` 制品。内含 `pactmesh.exe`、`pactmesh-core.exe`、
   随附的 `wintun.dll` / `Packet.dll` 和 `WinDivert64.sys`。
3. 解压到工作目录，如 `C:\PactMesh\`。保持 `.dll`/`.sys` 与可执行文件同目录。

### 在 Windows 上运行

- 以**管理员身份打开 PowerShell 或命令提示符**——TUN 配置和写 hosts 文件都需要提权。
- WinTun 驱动从随附的 `wintun.dll` 加载，无需单独安装。首次使用时 Windows 可能提示信任
  `WinDivert64.sys`。
- MagicDNS 把 `# privateNetwork` 块写入 `C:\Windows\System32\drivers\etc\hosts`，仅在提权进程下成功。

```powershell
cd C:\PactMesh
.\pactmesh.exe tui              # 搭建向导 + 管理器，与 Linux 一致
# 或直接跑守护进程：
.\pactmesh-core.exe --config-file C:\PactMesh\home.toml
```

在 TUI 用 `:setup-join` 消费 invite 并写出节点配置，再 `:daemon start` 拉起 `pactmesh-core`。
配置与信任域状态存于 `%USERPROFILE%\.config\privateNetwork\`，与 Linux 布局一致。

> A/B/C 混合真机清单（Linux A + Linux B + Windows C）：
> (1) 在 A 上建域/建网；(2) 在 B、C 上 invite + `accept-invite`；(3) 在 A 上审批两个 join；
> (4) 启动三个守护进程；(5) 确认 C 经 TUN 子网可达 A 与 B，且 MagicDNS hostname 在 C 上能解析。

## 故障排查

| 现象 | 首选排查点 |
|---|---|
| 守护进程退出："trust_domain.domain_dir is required" | TOML 缺 `[trust_domain]` 段或缺三个必填字段之一。跑 `pactmesh-core --check-config -c <file>`。 |
| 守护进程退出："trust_domain member_cert.pem not found" | `<domain_dir>/networks/<network_local_id>/member_cert.pem` 不存在。要么 `accept-invite` 没完成，要么 network_local_id 与目录名不匹配。 |
| 在线 `accept-invite` 卡在 "Connecting to join admission endpoint" | 连不上 seed 节点的加入受理端口（监听端口 + 1，默认 `11011`）。确认作为 seed 的根节点已从公网放行该端口且守护进程在运行；隔离网络下改用 `--offline` 走手动审批。 |
| 守护进程退出："failed to read sk_self password from env var" | 设备密钥是加密的 `sk_self.age`，但 `sk_self_password_env` 指向的环境变量在守护进程环境里没设。systemd 下检查 `EnvironmentFile=`。默认 `sk_self.raw` 路径不需要这个变量。 |
| 守护进程跑起来了但没 peer | (1) 监听端口是否被防火墙挡住？(2) `peers` URL 能否通？(3) 看日志有没有 `member_cert verify failed` / `handshake rejected`。 |
| 日志里 `member_cert verify failed` | 对端提供的成员证书无法通过本机信任域根的验证。可能是不同信任域、不同网络，或已被吊销/取代的旧证书。 |
| `trust_domain_id mismatch` | TOML 的 `domain_dir` 指向的目录，其 `pk_root.pem` 哈希出的 `trust_domain_id` 与加载的成员证书不一致。通常是跨信任域剪切目录或备份错位导致。 |
| 流量通了但 ACL drop 一切 | 要么网络是用 `--default-action drop` 创建的，要么信任 ACL 策略缺失/无法解码。信任网络**fail-closed**：无可用 ACL 策略时成员间*数据*被丢弃（控制/RPC/握手通道仍豁免）。签发并下发有效 ACL 策略，或用 `--default-action accept` 重建网络。 |
| peer 宣告的子网路由被忽略 | proxy CIDR 会按宣告方成员证书的 `can_proxy_subnet` 裁剪。peer（或本节点）只能宣告其证书授权的子网，超出部分被丢弃。重新签发带所需 `can_proxy_subnet` 的成员证书。 |
| 外域中继 peer 在连接时被拒 | 借用证明没有匹配的授权。在中继上用 `:relay-grant <foreign_td_hex> data=true`（和/或 `holepunch=true`）补授权，或恢复 `[[trust_domain.relay_serving]]` 块。 |
| hostname 不解析 | (1) 成员证书可能没设 hostname，用 `trust set-hostname` 设上。(2) 主机 `/etc/hosts`（或 Windows 等价位置）可能还没写入 `# privateNetwork` 块——等下一轮同步周期或重启守护进程。 |
| `cargo build` 报 "experimental_allow_proto3_optional" | 装 protoc 25.5 或更新。Ubuntu 20.04 自带 3.6.1 不接受该 flag。 |

需要更细的排查信息时打开 trace 日志：

```bash
RUST_LOG=pactmesh::trust=debug,pactmesh::peers=debug \
  pactmesh-core --config-file <file>
```

关键日志 target：

- `pactmesh::trust::*` —— trust pool 验证、成员证书生命周期、ACL 判决
- `pactmesh::peers::peer_conn` —— 握手状态（noise / plain / routing）
- `pactmesh::peers::peer_manager` —— peer 上下线

如果在构建主机上怀疑 `cargo test --test trust` 回归，连带跑：

```bash
cargo test --workspace --no-run                # 确认全编译通过
cargo test --test trust                        # trust 单测 umbrella
cargo test --test acl_e2e --test magicdns_e2e  # e2e 场景
```

## 延伸阅读

- `README.md` / `README_CN.md` —— 功能概述与快速开始
- `trust-and-config-design.md` —— 信任模型、NetworkState、TrustDomainMeta、签名流程
- `acl-schema-draft.md` —— ACL schema 与校验规则
- `THIRD_PARTY_NOTICES.md` —— 许可证声明与依赖来源
