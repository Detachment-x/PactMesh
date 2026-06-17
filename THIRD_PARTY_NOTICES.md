# Third-Party Notices

PactMesh redistributes and builds upon third-party software. This file records
the provenance of the upstream project, the licensing of bundled binary
components, and where to find the authoritative dependency license set.

## Upstream: EasyTier

PactMesh is a fork of **EasyTier** (<https://github.com/EasyTier/EasyTier>),
based on commit `5a1668c` (2026-04-25). EasyTier provides the P2P transport,
NAT traversal, routing, tunnel, and RPC substrate that PactMesh's trust and
configuration layers sit on top of.

EasyTier is distributed under **LGPL-3.0-or-later**. PactMesh keeps the same
license for consistency. See `LICENSE` for the full license text.

## Rust Dependencies

PactMesh links a large set of Rust crates from crates.io. The authoritative,
exact dependency set (with versions) is pinned in `Cargo.lock`; each crate is
distributed under its own license, predominantly MIT, Apache-2.0, or
MIT/Apache-2.0 dual licenses. To regenerate a per-crate license report:

```bash
cargo install cargo-license   # or cargo-about / cargo-deny
cargo license                 # summary by license
```

No crate is relicensed by this fork; each retains the license declared in its
own package metadata.

## Bundled Windows Components

The repository vendors prebuilt Windows driver/library binaries under
`pactmesh/third_party/{x86_64,arm64,i686}/`. These are **not** PactMesh code and
retain their own upstream licenses:

| Component | Files | Upstream / License |
| --- | --- | --- |
| Wintun | `wintun.dll` | WireGuard project — Wintun, redistributed under its own license (<https://www.wintun.net/>) |
| WinDivert | `WinDivert64.sys`, `WinDivert32.sys` | WinDivert — LGPLv3 / GPLv2 dual (<https://reqrypt.org/windivert.html>) |
| Npcap / WinPcap SDK | `Packet.dll`, `Packet.lib` | Packet capture library import stubs, redistributed under the upstream Npcap/WinPcap license (<https://npcap.com/>) |

When distributing PactMesh binaries that include these components, comply with
each component's redistribution terms.

## Notes

This file is a provenance and notices record, not a substitute for the upstream
licenses themselves. For the full and binding terms, consult `LICENSE` and the
license files shipped with each upstream component or crate.
