# PactMesh

PactMesh is the product name for this EasyTier fork. It keeps EasyTier's decentralized data plane and adds a signed trust/configuration layer for small private networks.

This repository is based on EasyTier commit `5a1668c` (2026-04-25). EasyTier provides the P2P transport, NAT traversal, routing, tunnels, and RPC substrate; PactMesh adds self-managed trust domains, member certificates, signed network configuration, ACLs, MagicDNS host rendering, and cross-trust-domain relay borrowing.

The current binaries and local config path still use the inherited names (`easytier-cli`, `easytier-core`, and `~/.config/privateNetwork`). Renaming crates, binaries, or on-disk paths is intentionally deferred so the Alpha workflow can stabilize first.

## Status

PactMesh is currently Alpha software for private and small-team use. A VPS + NAT device + online join + TUN path has been validated, but this is not yet a polished end-user product, an enterprise IAM product, a hosted control plane, or a multi-tenant SaaS system.

The core implementation is currently focused on:

- Trust domains rooted in an Ed25519 `PK_root` / `SK_root` pair.
- Signed `NetworkState` and `TrustDomainMeta` objects distributed over untrusted channels.
- Member certificates for device admission, revocation, disable/enable, and hostname assignment.
- Trust-aware EasyTier handshakes and packet ACL enforcement.
- Bootstrap invite/import flows for moving public trust-domain information between devices.

## Trust Model

Each user owns a trust domain. A trust domain is identified by `trust_domain_id = SHA-256(PK_root)`, and the holder of `SK_root` signs all member certificates and network configuration for that domain.

Configuration distribution does not need to be trusted. Nodes verify signatures locally before accepting a `NetworkState`, `TrustDomainMeta`, member certificate, or join-related payload. This keeps the network usable over ordinary EasyTier paths, relays, files, QR/bootstrap payloads, or future sync channels without giving those channels authority.

Device roles are governance identities, not feature toggles: a Root device can unlock this trust domain's `SK_root`, a Member device has this domain's `member_cert.pem`, and an External device is referenced by this domain without being a member. Network functions such as relay, holepunch assistance, and subnet proxying are capabilities. Tags are human grouping labels. ACLs only decide data-plane traffic permission.

## Cross-Trust-Domain Relay Borrowing

A small-team trust domain often has only a handful of nodes, none of which sit on a stable public address. PactMesh lets one trust domain explicitly lend its relays to another, without merging the two domains or sharing private keys.

The mechanism layers on top of `TrustDomainMeta`:

- A trust domain's `TrustDomainMeta.active_relays` list, signed by `SK_root`, enumerates the relays the domain operates.
- `TrustDomainMeta.outbound_grants` lists explicit, time-bounded grants of those relays to foreign trust domains (identified by `foreign_root_pk` + `foreign_trust_domain_id`).
- A borrowing node attaches a `BorrowedRelayProof` — built from the lender's signed `TrustDomainMeta` slice — to the relevant handshake messages. The relay verifies the proof locally against its own resolver, with no central authority involved.
- Capabilities (`can_relay_data`, `can_assist_holepunch`) and expiry are signed into each grant, so capacity, lifetime, and scope are all owned by the lending domain's root.

This makes asymmetric topologies practical: a friend with a well-connected home server can lend relay capacity to your domain for a few months, expiry signed in, with no shared secrets and no joint operations.

## Quick Start

The exact binary name and service wrapper depend on how you build or package this fork, but the trust workflow is:

```bash
# 1. Create a trust domain. The root private key is encrypted locally.
PNW_ROOT_PASSPHRASE='change-me-long-passphrase' \
  easytier-cli trust create-domain --label home --out-dir ~/.config/privateNetwork/trust-domains

# 2. Create a network inside that trust domain.
PNW_ROOT_PASSPHRASE='change-me-long-passphrase' \
  easytier-cli trust create-network <trust_domain_id> home --default-action accept

# 3. Export an invite/bootstrap bundle for another device.
easytier-cli trust invite <trust_domain_id> home \
  --seed tcp://<reachable-node>:11010 \
  --format url

# 4. On the new device, accept the invite and generate a join request.
easytier-cli trust accept-invite '<privatenetwork://join?...>' \
  --device-label laptop \
  --hint 'Alice laptop'
```

For an online approval flow, run the daemon/instance with trust services enabled and use the `--online` option on `trust accept-invite`. `--online` derives a join-admission endpoint from the invite's `tcp://<reachable-node>:11010` seed as `tcp://<reachable-node>:11011`, so public firewalls must allow `11010/TCP` and `11011/TCP`; the management RPC port `15888` should remain bound to localhost and must not be exposed to new devices or the public Internet. By default the device private key is stored as `sk_self.raw` with local file permissions, so the daemon can restart without an interactive device passphrase; if you set `PNW_DEVICE_PASSPHRASE` or use `--passphrase-file`, PactMesh stores `sk_self.age` instead and the daemon must be given `--sk-self-password-env`. Keep the root passphrase out of the daemon environment, and let management CLI commands unlock `SK_root` only when signing approvals or config changes. Without `--online`, the command prepares local device keys and a pending join request artifact that can be submitted later.

`easytier-core --daemon` means “run the network instance in daemon mode”; it does not fork itself into the background. For manual testing, run it under `nohup ... &`, `systemd`, `screen`, or `tmux`, and redirect logs explicitly.

## Build And Test

Rust 1.95 is the project baseline.

```bash
cargo build -p easytier
cargo test --test trust
cargo clippy -- -D warnings
```

Some integration and e2e tests exercise EasyTier tunnel behavior and may need Linux networking capabilities depending on the selected test target.

## Design Documents

- [Deployment guide](deploy.md) (Chinese: [deploy_CN.md](deploy_CN.md))
- [Trust and configuration model](trust-and-config-design.md)
- [ACL schema draft](acl-schema-draft.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

`THIRD_PARTY_NOTICES.md` is the audit target for EasyTier provenance, license notices, and dependency-license review.

## Relationship To EasyTier

PactMesh is a fork, not a replacement for the upstream EasyTier project. The fork keeps EasyTier's core networking architecture and changes the governance layer from shared network secrets toward explicit trust domains and signed configuration.

Upstream EasyTier remains the origin of the transport and routing stack. See the original project at <https://github.com/EasyTier/EasyTier>.

## License

This fork is distributed under LGPL-3.0-or-later, consistent with EasyTier's LGPL licensing. See `LICENSE` and `THIRD_PARTY_NOTICES.md` for license and provenance details.
