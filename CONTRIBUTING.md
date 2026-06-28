# Contributing to PactMesh

[中文版](CONTRIBUTING_zh.md)

PactMesh is a self-managed mesh VPN built on EasyTier's data plane (see
`THIRD_PARTY_NOTICES.md` for upstream attribution). It is a single pure-Rust
workspace that produces two binaries — `pactmesh` (CLI plus the local web
console) and `pactmesh-core` (daemon). Contributions are welcome.

## Project Structure

```
pactmesh/             # Main crate: CLI, daemon, trust layer, web controller
pactmesh/src/         # Rust sources
pactmesh/webui/       # Web console frontend (Preact + Vite), built and inlined into the binary
pactmesh-rpc-build/   # Protobuf RPC service stub generator (build dependency)
.github/workflows/    # CI/CD configuration
```

## Prerequisites

- Rust toolchain 1.95 (pinned in `rust-toolchain.toml`)
- Protoc (Protocol Buffers compiler)
- LLVM / Clang
- Node.js + npm — only needed to rebuild the web console under `pactmesh/webui`.
  The built bundle is committed, so a normal build does not require Node.

### Linux (Ubuntu/Debian)

```bash
sudo apt-get update && sudo apt-get install -y \
    llvm clang pkg-config protobuf-compiler libssl-dev
```

### Windows

Install the MSVC build tools and `protoc` (for example `winget install protobuf`).

## Building

```bash
cargo build --release -p pactmesh --bin pactmesh --bin pactmesh-core
```

Artifacts: `target/release/pactmesh[.exe]` and `target/release/pactmesh-core[.exe]`.
Supported platforms: Windows x86_64 and Linux x86_64.

### Rebuilding the web console (optional)

```bash
cd pactmesh/webui
npm install
npm run build   # emits the inlined bundle served by the daemon's controller
```

## Testing

```bash
cargo test
```

## Pull Requests

- Keep changes focused and atomic.
- Use conventional commit messages (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- Ensure `cargo build` and relevant tests pass.
- Update documentation when behavior changes.

## License

PactMesh is distributed under LGPL-3.0-or-later, matching its upstream. By
contributing you agree that your contributions are licensed under the same
terms. See `LICENSE` and `THIRD_PARTY_NOTICES.md`.

## Resources

- [Issue Tracker](https://github.com/Detachment-x/PactMesh/issues)
