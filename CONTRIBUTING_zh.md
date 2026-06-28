# PactMesh 贡献指南

[English](CONTRIBUTING.md)

PactMesh 是构建在 EasyTier 数据面之上的自管理 Mesh VPN（上游归属见
`THIRD_PARTY_NOTICES.md`）。它是单一的纯 Rust 工作区，产出两个二进制——
`pactmesh`（CLI 及本地 Web 控制台）与 `pactmesh-core`（守护进程）。欢迎贡献。

## 项目结构

```
pactmesh/             # 主 crate：CLI、守护进程、信任层、Web 控制器
pactmesh/src/         # Rust 源码
pactmesh/webui/       # Web 控制台前端（Preact + Vite），构建后内联进二进制
pactmesh-rpc-build/   # Protobuf RPC 桩代码生成器（构建依赖）
.github/workflows/    # CI/CD 配置
```

## 环境要求

- Rust 工具链 1.95（由 `rust-toolchain.toml` 固定）
- Protoc（Protocol Buffers 编译器）
- LLVM / Clang
- Node.js + npm——仅在重建 `pactmesh/webui` 下的 Web 控制台时需要。
  构建产物已随仓库提交，常规构建无需 Node。

### Linux（Ubuntu/Debian）

```bash
sudo apt-get update && sudo apt-get install -y \
    llvm clang pkg-config protobuf-compiler libssl-dev
```

### Windows

安装 MSVC 构建工具与 `protoc`（例如 `winget install protobuf`）。

## 构建

```bash
cargo build --release -p pactmesh --bin pactmesh --bin pactmesh-core
```

产物：`target/release/pactmesh[.exe]` 与 `target/release/pactmesh-core[.exe]`。
支持平台：Windows x86_64 与 Linux x86_64。

### 重建 Web 控制台（可选）

```bash
cd pactmesh/webui
npm install
npm run build   # 生成由守护进程控制器内联服务的打包产物
```

## 测试

```bash
cargo test
```

## Pull Request

- 改动保持聚焦、原子化。
- 使用约定式提交信息（`feat:`、`fix:`、`docs:`、`test:`、`chore:`）。
- 确保 `cargo build` 与相关测试通过。
- 行为变更时同步更新文档。

## 许可证

PactMesh 按 LGPL-3.0-or-later 分发，与上游许可证口径一致。提交贡献即表示你同意
你的贡献以相同条款授权。详见 `LICENSE` 与 `THIRD_PARTY_NOTICES.md`。

## 资源

- [问题追踪](https://github.com/Detachment-x/PactMesh/issues)
