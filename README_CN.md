# PactMesh

PactMesh 是当前项目的产品名。它是一个基于 EasyTier 的 fork：保留 EasyTier 的去中心化数据面，并在其上增加签名信任层与签名配置层，面向私人和小团队内网穿透场景。

本仓库基于 EasyTier commit `5a1668c`（2026-04-25）。EasyTier 提供 P2P 传输、NAT 穿透、路由、隧道与 RPC 基础设施；PactMesh 增加自治信任域、成员证书、签名网络配置、ACL、MagicDNS hosts 渲染，以及跨信任域中继借用。

当前二进制名和本地配置目录仍沿用继承名称（`easytier-cli`、`easytier-core`、`~/.config/privateNetwork`）。crate、二进制和磁盘路径重命名会影响面较大，暂时推迟到 Alpha 流程稳定后单独处理。

## 状态

PactMesh 当前处于 Alpha 阶段，面向私人和小团队使用。公网 VPS + NAT 设备 + 在线准入 + TUN 路径已经验证可跑通，但还不是完整打磨后的最终用户产品，也不是企业 IAM 产品、托管控制面或多租户 SaaS 系统。

当前核心实现聚焦于：

- 以 Ed25519 `PK_root` / `SK_root` 为根的信任域。
- 通过不可信渠道分发但可本地验签的 `NetworkState` 与 `TrustDomainMeta`。
- 用于设备准入、吊销、临时禁用/恢复、hostname 分配的成员证书。
- 接入 EasyTier 握手路径和数据包路径的 trust-aware 验证与 ACL。
- 用于离线/在线分发公开信任域信息的 bootstrap invite/import 流程。

## 信任模型

每个用户拥有自己的信任域。信任域由 `trust_domain_id = SHA-256(PK_root)` 标识，持有 `SK_root` 的根设备负责签发该信任域内的成员证书和网络配置。

配置分发渠道不需要可信。节点在接受 `NetworkState`、`TrustDomainMeta`、成员证书或 join 相关 payload 前，会在本地验证签名。这样配置可以通过普通 EasyTier 路径、中继、文件、QR/bootstrap payload 或后续同步通道传播，但这些传播通道本身不拥有授权能力。

设备角色只表达治理身份，不表达具体网络功能：Root device 是能解锁本信任域 `SK_root` 的管理设备，Member device 是持有本域 `member_cert.pem` 的成员设备，External device 是被本域引用但不是本域成员的外部设备或服务资源。relay、打洞协助、子网代理属于 capability；tag 是人工分组；ACL 只负责判断数据面流量是否允许通过。

## 跨信任域中继借用

小团队信任域往往只有少量节点，且通常没有稳定的公网地址。PactMesh 允许一个信任域显式地把自己的中继借给另一个信任域使用——既不合并两个信任域，也不共享私钥。

该机制以 `TrustDomainMeta` 为载体：

- 由 `SK_root` 签名的 `TrustDomainMeta.active_relays` 列出本信任域名下的中继节点。
- `TrustDomainMeta.outbound_grants` 显式列出对外信任域的借用授权（含 `foreign_root_pk` + `foreign_trust_domain_id` + 能力位 + 过期时间）。
- 借用方节点在握手时附带 `BorrowedRelayProof`（从出借方签名后的 `TrustDomainMeta` 切片构造）；中继节点用本地 resolver 验证证明，过程不涉及任何中央协调机构。
- 能力位（`can_relay_data`、`can_assist_holepunch`）和过期时间随授权一并签名，借用容量、生命周期和范围都由出借方的根设备掌控。

这让非对称拓扑变得可行：一个网络条件好的朋友可以借给你几个月的中继容量，借期签进证书内，无共享密钥，也不需要联合运维。

## 快速开始

具体二进制名称和服务封装取决于你的构建/打包方式；信任层的基本流程如下：

```bash
# 1. 创建信任域。根私钥会在本地加密保存。
PNW_ROOT_PASSPHRASE='change-me-long-passphrase' \
  easytier-cli trust create-domain --label home --out-dir ~/.config/privateNetwork/trust-domains

# 2. 在该信任域下创建网络。
PNW_ROOT_PASSPHRASE='change-me-long-passphrase' \
  easytier-cli trust create-network <trust_domain_id> home --default-action accept

# 3. 为新设备导出 invite/bootstrap。
easytier-cli trust invite <trust_domain_id> home \
  --seed tcp://<reachable-node>:11010 \
  --format url

# 4. 在新设备上接受 invite，并生成 join request。
easytier-cli trust accept-invite '<privatenetwork://join?...>' \
  --device-label laptop \
  --hint 'Alice laptop'
```

如果要走在线审批流程，需要先运行启用了 trust services 的 daemon/instance，然后在 `trust accept-invite` 中使用 `--online`。`--online` 会从 invite 中的 `tcp://<reachable-node>:11010` seed 自动推导 join-admission 准入端口 `tcp://<reachable-node>:11011`，因此公网/防火墙需要放行 `11010/TCP` 与 `11011/TCP`；管理 RPC `15888` 只应绑定本机，不应暴露给新设备或公网。设备私钥默认以 `sk_self.raw` 存储并依赖本机文件权限保护，因此 daemon 可无交互重启；如果显式设置 `PNW_DEVICE_PASSPHRASE` 或 `--passphrase-file`，PactMesh 会改用 `sk_self.age`，daemon 才需要 `--sk-self-password-env`。不要把根密码放进 daemon 环境；审批和配置修改由管理 CLI 命令按需解锁 `SK_root` 后签名。不使用 `--online` 时，该命令只会准备本地设备密钥和待提交的 join request artifact，后续可再提交。

`easytier-core --daemon` 的含义是“按 daemon/instance 模式运行网络实例”；它不会自动 fork 到后台。人工测试建议使用 `nohup ... &`、`systemd`、`screen` 或 `tmux` 管理进程，并显式重定向日志。

## 构建与测试

项目基线是 Rust 1.95。

```bash
cargo build -p easytier
cargo test --test trust
cargo clippy -- -D warnings
```

部分集成测试和 e2e 测试会触发 EasyTier 隧道行为，具体运行权限取决于测试目标和操作系统网络能力。

## Release 二进制

当前 PactMesh Alpha 为了兼容仍保留继承来的二进制名：`easytier-core` 和 `easytier-cli`。

在 workspace 内构建 release 产物：

```bash
cd workspace/easytier
cargo build --release --bin easytier-core --bin easytier-cli
```

产物写在 workspace 级 target 目录，不在 crate 目录：

```text
workspace/target/release/easytier-core
workspace/target/release/easytier-cli
```

当前 Linux x86-64 构建机生成的是动态链接 ELF x86-64 二进制。实测大小约为：`easytier-core` 28M，`easytier-cli` 14M。x86-64 产物不能直接在 ARM 主机运行；ARM 机器要么在 ARM 主机本机构建，要么补齐 Rust target、交叉链接器和对应系统库后交叉编译。

复制到测试服务器示例：

```bash
scp workspace/target/release/easytier-core workspace/target/release/easytier-cli user@server:/opt/pactmesh/
ssh user@server 'chmod +x /opt/pactmesh/easytier-core /opt/pactmesh/easytier-cli'
```

## 设计文档

- [部署指南](deploy_CN.md)（英文版 [deploy.md](deploy.md)）
- [信任与配置模型设计](trust-and-config-design.md)
- [ACL schema 草案](acl-schema-draft.md)
- [第三方声明与许可证审计](THIRD_PARTY_NOTICES.md)

`THIRD_PARTY_NOTICES.md` 用于记录 EasyTier 来源、许可证声明和依赖许可证审计结果。

## 与 EasyTier 的关系

PactMesh 是 fork，不是对上游 EasyTier 的替代。该 fork 保留 EasyTier 的核心网络架构，把治理层从共享 `network_secret` 字符串改为显式信任域和签名配置。

上游 EasyTier 仍然是传输与路由栈的来源。原项目地址：<https://github.com/EasyTier/EasyTier>。

## 许可证

本 fork 按 LGPL-3.0-or-later 分发，与 EasyTier 的 LGPL 许可证口径保持一致。许可证和来源细节见 `LICENSE` 与 `THIRD_PARTY_NOTICES.md`。
