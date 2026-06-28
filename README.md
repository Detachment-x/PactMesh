# PactMesh

[English](README_EN.md) | **中文**

PactMesh 是当前项目的产品名。它是一个基于 EasyTier 的 fork：保留 EasyTier 的去中心化数据面，并在其上增加签名信任层与签名配置层，面向私人和小团队内网穿透场景。

本仓库基于 EasyTier commit `5a1668c`（2026-04-25）。EasyTier 提供 P2P 传输、NAT 穿透、路由、隧道与 RPC 基础设施；PactMesh 增加自治信任域、成员证书、签名网络配置、ACL、MagicDNS hosts 渲染，以及跨信任域中继借用。

当前用户可见 CLI 和 daemon 二进制已经命名为 `pactmesh` 与 `pactmesh-core`。本地配置目录暂时仍使用 `~/.config/privateNetwork`，用于兼容现有 Alpha 数据布局。

一句话定位：**数据面（EasyTier）负责无论 NAT 多恶劣都尽力把设备直连起来、连不上就中继兜底；治理面（PactMesh）负责由你本人的密钥决定谁能进、能干什么、借谁的中继，全部本地签名验证、不依赖任何中央服务器。**

## 状态

PactMesh 当前处于 Alpha 阶段，面向私人和小团队使用。公网 VPS + NAT 设备 + 在线准入 + TUN 路径已经验证可跑通，但还不是完整打磨后的最终用户产品，也不是企业 IAM 产品、托管控制面或多租户 SaaS 系统。

当前核心实现聚焦于：

- 以 Ed25519 `PK_root` / `SK_root` 为根的信任域。
- 通过不可信渠道分发但可本地验签的 `NetworkState` 与 `TrustDomainMeta`。
- 用于设备准入、吊销、临时禁用/恢复、hostname 分配的成员证书。
- 接入 EasyTier 握手路径和数据包路径的 trust-aware 验证与 ACL。
- 用于离线/在线分发公开信任域信息的 bootstrap invite/import 流程。

## 功能总览

数据面继承自 EasyTier，信任治理面为 PactMesh 增量。两层正交：**角色 ≠ 能力，永久吊销 ≠ 临时禁用，配置传播渠道无需可信**。下表为完整能力清单；信任模型与中继借用的概念说明见后续章节。

### 组网数据面

无论 NAT 多恶劣都尽力直连，连不上则中继兜底。

**连接与隧道**

| 功能 | 说明 / 设计原因 |
| --- | --- |
| 虚拟网卡（TUN） | 设备间用虚拟内网 IP 直连，体验等同真局域网 |
| 无网卡模式（`no_tun`） | 不建虚拟网卡，只做端口转发/代理。供路由器、受限容器、无 TUN 权限环境加入网络只当转发 |
| 多协议传输（`default_protocol`） | 同一连接可走 TCP / UDP / WebSocket（ws、wss）/ QUIC。仅放行 443 的网络可用 wss 伪装成 HTTPS 穿过 |
| 用户态 TCP 栈（`use_smoltcp`） | 不依赖系统协议栈，适配受限/嵌入式环境 |
| MTU 配置（`mtu`） | 适配链路，避免分片 |

**NAT 穿透（打洞）**

| 功能 | 说明 / 设计原因 |
| --- | --- |
| UDP / TCP / 对称型 NAT 打洞 | 三类分项开关（`disable_udp/tcp/sym_hole_punching`），便于按 NAT 类型隔离排查 |
| UPnP 自动端口映射 | 路由器支持即主动开端口（`disable_upnp` 可关） |
| 打洞协助（`can_assist_holepunch`） | 有公网的节点帮两台被挡节点牵线 |
| 绑定物理网卡 | `bind_device` / `bind_device_public` / `bind_device_name`，强制走指定网卡；当系统存在抢占默认路由的代理 TUN 时，避免打洞被污染 |

**中继（兜底）**

| 功能 | 说明 / 设计原因 |
| --- | --- |
| 中继转发 | 直连失败自动经公网节点转发，链路不断 |
| 中继白名单（`relay_network_whitelist`） | 限定为哪些网络提供中继 |
| 转发所有 peer RPC（`relay_all_peer_rpc`） | 控制信令转发范围 |
| 外域中继限速（`foreign_relay_bps_limit`） | 把中继借给别人时单独限速，避免外域转发占满本机带宽 |

**传输优化与安全**

| 功能 | 说明 |
| --- | --- |
| 加密（`enable_encryption` / `encryption_algorithm`） | 开关 + 算法选择（AES-GCM、ChaCha20 等） |
| 数据压缩（`data_compress_algo`） | 如 zstd，弱网省流量 |
| KCP 代理加速（`enable_kcp_proxy`） | TCP 套入 KCP 抗丢包；配 `disable_kcp_input` / `disable_relay_kcp` 细调 |
| QUIC 代理（`enable_quic_proxy`） | 配 `disable_quic_input` / `disable_relay_quic` 细调 |
| 外域中继 KCP/QUIC | `enable_relay_foreign_network_kcp` / `_quic` 控制借出的中继是否承载加速协议 |
| 延迟优先路由（`latency_first`） | 多路可选时取最低延迟 |
| 收发限速（`instance_recv_bps_limit`） | 实例级带宽上限 |
| 多线程（`multi_thread` / `multi_thread_count`） | 压满多核吞吐 |
| 私有模式（`private_mode`） | 限制节点随意中继/暴露 |

**网络服务能力**

| 功能 | 说明 / 场景 |
| --- | --- |
| 出口节点（`enable_exit_node`） | 让某台设备当全流量出口；在外把流量从家中出口出去，等于回家上网 |
| 子网代理 / 路由共享 | 把某设备背后的整个局域网段（如 NAS 子网）暴露给成员，无需每台设备装客户端 |
| WireGuard 入口（VpnPortal） | 给装不了 PactMesh 的设备（老手机、电视盒子）开标准 WireGuard 入口接入 |
| MagicDNS（`accept_dns` / `tld_dns_zone`） | 用主机名（如 `nas.home`）代替记 IP |

### 守护进程管理（命令行）

| 命令 | 功能 |
| --- | --- |
| `peer list` / `list-foreign` / `list-global-foreign` | 本域 / 指定外域 / 所有跨域对等节点 |
| `route list` / `route dump` | 查看 / 导出路由表 |
| `connector add` / `remove` / `list` | 增删连接入口 URL |
| `mapped-listener add` / `remove` / `list` | 管理映射监听地址 |
| `stun` | 测本机 NAT 类型（排查打洞） |
| `vpn-portal` | 查看 WireGuard 入口信息 |
| `node info` / `node config` | 自身核心状态与配置 |
| `proxy` | TCP/KCP 代理状态 |
| `acl stats` | ACL 规则命中统计 |
| `port-forward add` / `remove` / `list` | 端口转发（远端服务映射到本地端口） |
| `whitelist set-tcp` / `set-udp` / `clear-tcp` / `clear-udp` / `show` | TCP/UDP 端口白名单 |
| `stats show` / `stats prometheus` | 运行统计；可导出 Prometheus 格式接 Grafana |
| `logger get` / `set` | 运行时调日志级别，免重启 |
| `service install` / `uninstall` / `status` / `start` / `stop` / `restart` | 注册系统服务、开机自启 |
| `tui` | 交互式终端控制台（ratatui，含 Node / Peers / Joins 审批） |
| `gen-autocomplete` | 生成 shell 补全脚本 |

### 信任与治理（`trust`）

每个用户拥有自己的信任域，由根密钥（Ed25519 `SK_root`）签发证书与配置，无中央机构。概念说明见 [信任模型](#信任模型)。

| 命令 | 功能 / 设计原因 |
| --- | --- |
| `create-domain` / `list-domains` | 创建信任域（生成根密钥并设管理密码，根私钥加密存为 `sk_root.age`）/ 列出本机信任域 |
| `create-network` | 在域内创建具体网络 |
| `bootstrap-self` | 给根设备自己签发成员证书 |
| `invite` / `accept-invite` | 签发 / 接受邀请，载体支持 URL、文件、二维码；配置带签名，任何渠道传播都安全 |
| `approve` / `reject` / `list-pending` | 在线准入审批 |
| `revoke` | 永久吊销，要求填原因（密钥泄露 / 设备丢失 / 主动移除 / 被替换 / 未指定），原因签进证书供审计 |
| `disable` / `enable` | 临时禁用 / 恢复设备，区别于永久 `revoke`，恢复后无需重新签证 |
| `upgrade-peer-to-root` | 把成员设备提升为根设备；经加密 peer 通道传根私钥，目标机解锁密码仅本地输入。用于管理权迁移 / 多根设备 |
| `list-members` / `list-external` | 成员设备 / 外部引用设备列表 |
| `show-device` / `rename-device` | 查看 / 重命名设备 |
| `set-hostname` / `unset-hostname` | 分配主机名，配合 MagicDNS 用名字访问 |
| `capability set` | 设置能力位（`can_relay_data` 能否中继、`can_assist_holepunch` 能否协助打洞）；角色与能力分离，成员机也可被授权当中继 |
| `tag list` / `add` / `remove` | 人工分组标签（如 home / work） |
| `peer-hint list` / `add` / `remove` | 手动提供节点地址提示，辅助连接 / 打洞 |
| `acl explain` | 解释当前 ACL 流量规则（谁能访问谁） |

### 凭证与引导分发

| 命令 | 功能 / 场景 |
| --- | --- |
| `credential generate` / `revoke` / `list` | 签发 / 吊销 / 列出临时凭证；可发短期自动失效的入网凭据给临时协作者 |
| `bootstrap export` / `import` | 导出 / 导入信任域引导包，离线传播公开信任域信息 |

### 本地 Web 控制台（`controller`）

对标 ZeroTier / Tailscale 的产品级浏览器管理台，明亮简洁、青绿连接感的视觉。前端用 Preact + Vite 构建为**单文件**后经 `include_str!` 内嵌进二进制——运行期零 Node、零外部依赖、单二进制不破。挂在 CLI 侧，连接本机已运行的 daemon RPC：

```bash
pactmesh --rpc-portal 127.0.0.1:<rpc> controller --listen 127.0.0.1:15810
# 启动打印带一次性 token 的本地 URL；仅 loopback 可访问
```

**界面预览**

<table>
  <tr>
    <td><img src="pactmesh/docs/screenshots/01-overview.png" width="430" alt="概览"><br><sub>概览 · 健康指标 + 邀请设备 CTA</sub></td>
    <td><img src="pactmesh/docs/screenshots/03-devices.png" width="430" alt="设备"><br><sub>设备 · 身份与运行时融合表</sub></td>
  </tr>
  <tr>
    <td><img src="pactmesh/docs/screenshots/11-assign-ip.png" width="430" alt="指派 IP"><br><sub>设备抽屉 · 主控指派固定虚拟 IP</sub></td>
    <td><img src="pactmesh/docs/screenshots/02-network.png" width="430" alt="网络"><br><sub>网络 · 成员 IP / 托管路由 / DNS 概览</sub></td>
  </tr>
  <tr>
    <td><img src="pactmesh/docs/screenshots/05-policy.png" width="430" alt="访问策略"><br><sub>访问策略 · 可视化 ACL 编辑器</sub></td>
    <td><img src="pactmesh/docs/screenshots/12-invite-modal.png" width="430" alt="邀请设备"><br><sub>邀请设备 · 二维码 + 用法说明</sub></td>
  </tr>
</table>

信息架构按"用户想完成的事"组织为顶栏（网络选择器 + 会话锁 TTL 倒计时）+ 四组侧边导航：

- **概览**：本机节点卡 + 健康指标（设备 / 在线节点 / 待批，可点击跳转）+ 邀请设备主 CTA；daemon 未连接时优雅降级而非崩溃。
- **网络** — *设备*（**身份与运行时融合一表**：成员名册按主机名左连 routes / peers，一行看齐 在线状态 · 虚拟 IPv4/IPv6 · 直连 / 中继 + 隧道类型 · 延迟；管理抽屉含改名 / 主机名 / 能力开关 + 代理 CIDR / 禁用 / 吊销，并展开本机物理 IP（`ip_list` 公网 / 内网 v4·v6）、逐连接远端地址、MagicDNS 只读 FQDN，证书指纹收进底部「高级 / 审计」折叠；行内表单非弹窗，在线临时设备凭徽标区分）、*待批*（卡片审批 / 拒绝）。
- **访问控制** — *访问策略*（可视化 ACL 链 / 规则编辑器，枚举走人话下拉）、*分组*（tags 成员管理）。
- **设置** — *本机配置*（连接器 / 映射监听 / 端口转发 / 路由 / 子网代理 / 出口节点 / 中继授权 / 主机名 / IPv4 / 白名单声明式表单，并含 **MagicDNS 启用状态 + 网络域名 + 本机 FQDN 只读卡**）、*诊断*（指标 / ACL 统计 / 连接跟踪）、*高级*（**危险区**：建域 / 建网 / 升根 / 武装升级，折叠保护 + 模态二次确认；**临时设备密钥**签发 / 吊销）。

产品化体验：**首启引导**（无网络时两步建好第一个网络）· **邀请一等公民**（二维码 + 复制 + 对方用法说明）· **JIT 解锁**（任意写操作就地弹解锁，无需先去顶栏）· toast 反馈 + 加载骨架 + 空状态 CTA · 基础键盘可达与语义标签。

- **写操作鉴权**：成员治理 / tags / 升根等 root 签名操作须先解锁（会话内 `zeroize` 缓存 root 口令、TTL 到期自动清除，绝不落盘 / 日志）；配置下发与 ACL 编辑走 daemon RPC 热重载、无需 root 口令；建域 / 建网用内联口令即用即清。设备自举（`bootstrap-self`）仍是一次性 CLI 步骤。
- **安全**：仅绑定 loopback；每次请求校验 token（Cookie `SameSite=Strict` / Bearer）；高危操作强制二次确认。

> 前端源码在 `pactmesh/webui/`（Preact + Vite）；改动后 `npm run build` 产出单文件 `src/controller/assets/dist/index.html` 随源码提交，`cargo build` 时内嵌。

### 测试与运维脚手架（`lab`）

主要供开发与回归测试，非最终用户日常功能：`doctor`（环境体检）、`status`（汇总本地文件/RPC/peers/日志）、`run`、`approve`、`peers explain/root/joiner`、`remote-check`、`remote-run` / `remote-fresh-run`（SSH 驱动的三节点回归，后者从全新信任域跑通）、`commands`、`disable` / `enable`。`wizard` 及旧的 no-TTY fallback 已弃用，推荐 `tui`。

## 信任模型

每个用户拥有自己的信任域。信任域由 `trust_domain_id = SHA-256(PK_root)` 标识，持有 `SK_root` 的根设备负责签发该信任域内的成员证书和网络配置。

用户可见的“管理密码”就是本地 `sk_root.age` 的 root key passphrase。它不是账号密码、不是登录密码，也不是助记词。恢复管理权需要同时拥有 `sk_root.age` 备份和管理密码；只有其中任意一个都无法恢复或解锁根密钥。

### 备份与恢复管理权

创建信任域后，立即备份该信任域目录下的 `sk_root.age`，并把管理密码保存在你能长期记住或安全托管的位置。`sk_root.age` 是加密后的根私钥文件，管理密码只是解锁该文件的 passphrase；只有管理密码没有文件，无法重新生成 root key；只有 `sk_root.age` 但忘记管理密码，也无法解锁 root key。

恢复或迁移管理权时，把备份的 `sk_root.age` 放回目标机器的信任域目录，并使用同一个管理密码执行 `trust create-network`、`trust approve`、`trust revoke` 等管理命令。普通 daemon 运行和数据面重连不需要管理密码，只有需要 `SK_root` 签名的管理操作才会按需解锁。

配置分发渠道不需要可信。节点在接受 `NetworkState`、`TrustDomainMeta`、成员证书或 join 相关 payload 前，会在本地验证签名。这样配置可以通过普通 EasyTier 路径、中继、文件、QR/bootstrap payload 或后续同步通道传播，但这些传播通道本身不拥有授权能力。

设备角色只表达治理身份，不表达具体网络功能：Root device 是能解锁本信任域 `SK_root` 的管理设备，Member device 是持有本域 `member_cert.pem` 的成员设备，External device 是被本域引用但不是本域成员的外部设备或服务资源。relay、打洞协助、子网代理属于 capability；tag 是人工分组；ACL 只负责判断数据面流量是否允许通过。

把另一台已入网 Member device 提升为 Root device 时，先在目标设备 daemon 启动环境中临时设置本机 `PNW_ROOT_UPGRADE_PASSPHRASE`，再在已有 Root device 上执行 `pactmesh trust upgrade-peer-to-root <trust_domain_id> <network_local_id> <peer_id>`。已有 Root device 只解锁自己的 `sk_root.age`，通过已建立的 peer RPC/Noise 路径发送原始 `SK_root` 字节；目标设备收到后用它派生 `PK_root`，与本机缓存的 `pk_root.pem` 比对一致才写入自己的加密 `sk_root.age`。目标设备用于保存 `sk_root.age` 的密码只在目标本机提供，不会从已有 Root device 传过去。

## 跨信任域中继借用

小团队信任域往往只有少量节点，且通常没有稳定的公网地址。PactMesh 允许一个信任域显式地把自己的中继借给另一个信任域使用——既不合并两个信任域，也不共享私钥。

该机制以 `TrustDomainMeta` 为载体：

- 由 `SK_root` 签名的 `TrustDomainMeta.active_relays` 列出本信任域名下的中继节点。
- `TrustDomainMeta.outbound_grants` 显式列出对外信任域的借用授权（含 `foreign_root_pk` + `foreign_trust_domain_id` + 能力位 + 过期时间）。
- 借用方节点在握手时附带 `BorrowedRelayProof`（从出借方签名后的 `TrustDomainMeta` 切片构造）；中继节点用本地 resolver 验证证明，过程不涉及任何中央协调机构。
- 能力位（`can_relay_data`、`can_assist_holepunch`）和过期时间随授权一并签名，借用容量、生命周期和范围都由出借方的根设备掌控。

这让非对称拓扑变得可行：一个网络条件好的朋友可以借给你几个月的中继容量，借期签进证书内，无共享密钥，也不需要联合运维。

## 一键安装

预编译版本通过 GitHub Releases 发布（打 `v*` tag 触发，覆盖 **Windows x86_64** 与 **Linux x86_64**）。安装脚本会下载二进制、放进 PATH，并在 Linux 上为 `pactmesh-core` 赋 `cap_net_admin,cap_net_raw`（无需 sudo 即可裸跑 daemon）。

```bash
# Linux x86_64（需 root；--gh-proxy 走国内代理可选）
curl -fsSL https://github.com/Detachment-x/PactMesh/releases/latest/download/install.sh | sudo bash
```

```powershell
# Windows x86_64（管理员 PowerShell）
irm https://github.com/Detachment-x/PactMesh/releases/latest/download/install.ps1 | iex
```

装好后用 **一条命令** 完成首次初始化（建信任域 → 建网络 → 自举本机 → 拉起 daemon → 打开本地 Web 控制台）：

```bash
pactmesh quickstart
# 终端会打印 http://127.0.0.1:15810/?token=... ，浏览器打开即用
```

`quickstart` 在 TTY 下交互询问管理密码与设备密钥密码；自动化/非 TTY 用 `--passphrase-file` / `--device-passphrase-file` 或环境变量 `PNW_ROOT_PASSPHRASE` / `PNW_DEVICE_PASSPHRASE`。需要时可调端口与命名：`pactmesh quickstart --network-id home --listen 127.0.0.1:15810`。

> 想从源码构建、或手动分步初始化（理解每一步在做什么），见下面《快速开始》与《构建与测试》。

## 快速开始

> 下面是 `pactmesh quickstart` 背后的等价手工步骤，便于理解信任模型；日常首次初始化直接用上面的 `pactmesh quickstart` 即可。

具体二进制名称和服务封装取决于你的构建/打包方式。首次初始化建议按下面的向导顺序执行：先创建信任域并设置管理密码，再创建网络，给根设备自己签发成员证书，最后生成给其他设备使用的 invite。

```bash
# 1. 创建信任域。交互式输入并确认管理密码；根私钥会加密保存为 sk_root.age。
pactmesh trust create-domain --label home --out-dir ~/.config/privateNetwork/trust-domains

# 保存输出中的 trust_domain_id，后续命令都需要它。
export TRUST_DOMAIN_ID='<trust_domain_id>'
export NETWORK_LOCAL_ID='home'

# 2. 在该信任域下创建网络。
pactmesh trust create-network "$TRUST_DOMAIN_ID" "$NETWORK_LOCAL_ID" --default-action accept

# 3. 给当前根设备自己签发成员证书，否则 daemon 无法作为网络成员启动。
pactmesh trust bootstrap-self "$TRUST_DOMAIN_ID" "$NETWORK_LOCAL_ID" --device-label root-a

# 4. 为新设备导出 invite/bootstrap。
pactmesh trust invite "$TRUST_DOMAIN_ID" "$NETWORK_LOCAL_ID" \
  --seed tcp://<reachable-node>:11010 \
  --format url

# 5. 在新设备上接受 invite，并生成 join request。
pactmesh trust accept-invite '<privatenetwork://join?...>' \
  --device-label laptop \
  --hint 'Alice laptop'
```

自动化脚本或非 TTY 环境不能交互输入管理密码，应使用 `PNW_ROOT_PASSPHRASE` 或 `--passphrase-file`。管理密码只在 `create-domain`、`create-network`、`bootstrap-self`、`approve`、`revoke` 等需要 `SK_root` 签名的管理 CLI 命令中按需使用；正常 daemon 运行不要常驻携带管理密码。

在线审批是默认行为（需根节点侧运行启用了 trust services 的 daemon/instance）：`trust accept-invite` 会从 invite 中的 `tcp://<reachable-node>:11010` seed 自动推导 join-admission 准入端口 `tcp://<reachable-node>:11011`，因此公网/防火墙需要放行 `11010/TCP` 与 `11011/TCP`；管理 RPC `15888` 只应绑定本机，不应暴露给新设备或公网。设备私钥默认以 `sk_self.raw` 存储并依赖本机文件权限保护，因此 daemon 可无交互重启；如果显式设置 `PNW_DEVICE_PASSPHRASE` 或 `--passphrase-file`，PactMesh 会改用 `sk_self.age`，daemon 会默认从 `PNW_DEVICE_PASSPHRASE` 读取密码；只有使用其他环境变量名时才需要 `--sk-self-password-env`。不要把管理密码放进 daemon 环境；审批和配置修改由管理 CLI 命令按需解锁 `SK_root` 后签名。air-gapped 或手工审批场景请加 `--offline`：该命令只会准备本地设备密钥和待提交的 join request artifact，不联网，后续再人工提交。

`pactmesh-core --daemon` 的含义是“按 daemon/instance 模式运行网络实例”；它不会自动 fork 到后台。人工测试建议使用 `nohup ... &`、`systemd`、`screen` 或 `tmux` 管理进程，并显式重定向日志。

## 构建与测试

项目基线是 Rust 1.95。

```bash
cargo build -p pactmesh
cargo test --test trust
cargo clippy -- -D warnings
```

部分集成测试和 e2e 测试会触发 EasyTier 隧道行为，具体运行权限取决于测试目标和操作系统网络能力。

## Release 二进制

PactMesh release 构建会生成两个二进制：daemon 使用的 `pactmesh-core` 和管理 CLI 使用的 `pactmesh`。

在 workspace 内构建 release 产物：

```bash
cd workspace/pactmesh
cargo build --release --bin pactmesh-core --bin pactmesh
```

产物写在 workspace 级 target 目录，不在 crate 目录：

```text
workspace/target/release/pactmesh-core
workspace/target/release/pactmesh
```

当前 Linux x86-64 构建机生成的是动态链接 ELF x86-64 二进制。实测大小约为：`pactmesh-core` 28M，`pactmesh` 14M。x86-64 产物不能直接在 ARM 主机运行；ARM 机器要么在 ARM 主机本机构建，要么补齐 Rust target、交叉链接器和对应系统库后交叉编译。

复制到测试服务器示例：

```bash
scp workspace/target/release/pactmesh-core workspace/target/release/pactmesh user@server:/opt/pactmesh/
ssh user@server 'chmod +x /opt/pactmesh/pactmesh-core /opt/pactmesh/pactmesh'
```

## 设计文档

- [部署指南](deploy_CN.md)（英文版 [deploy.md](deploy.md)）
- [临时凭据（Credential）系统实现计划](pactmesh/docs/credential_peer.md)
- [PeerConn Secure Mode（乱序隧道友好）](pactmesh/docs/peer_conn_secure_mode_v3.md)
- [Relay Peer 管理模块设计](pactmesh/docs/relay_peer_manager_design.md)
- [第三方声明](THIRD_PARTY_NOTICES.md)（EasyTier 来源、捆绑组件与依赖许可证）

## 与 EasyTier 的关系

PactMesh 是 fork，不是对上游 EasyTier 的替代。该 fork 保留 EasyTier 的核心网络架构，把治理层从共享 `network_secret` 字符串改为显式信任域和签名配置。

上游 EasyTier 仍然是传输与路由栈的来源。原项目地址：<https://github.com/EasyTier/EasyTier>。

## 许可证

本 fork 按 LGPL-3.0-or-later 分发，与 EasyTier 的 LGPL 许可证口径保持一致。许可证和来源细节见 `LICENSE` 与 `THIRD_PARTY_NOTICES.md`。
