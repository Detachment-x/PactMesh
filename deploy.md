# Deployment Guide — PactMesh

This document covers building, installing, and operating PactMesh — an EasyTier fork that adds signed trust domains, member certificates, ACLs, MagicDNS, and cross-trust-domain relay borrowing on top of EasyTier's data plane.

The deployment model assumes one human operator (the trust-domain owner) and a small handful of nodes (typically 2-20). It is not a control-plane / multi-tenant blueprint.

## Contents

- Prerequisites
- Build from source
- File layout and environment
- Two-node happy path
- TUI quick setup
- Configuration file reference
- Running as a systemd service
- Firewall and reachability
- Multi-trust-domain setup
- Cross-trust-domain relay borrowing (incl. runtime grants and enforcement)
- Operational tasks (revoke, disable, set hostname, upgrade-to-root, peer hints)
- Windows deployment (CI artifact + real-device checklist)
- Troubleshooting

## Prerequisites

| Component | Required | Notes |
|---|---|---|
| OS | Linux (Ubuntu 20.04+ / Debian 11+ / Arch / etc.), macOS 12+, Windows 10+ | TUN/TAP support: kernel module on Linux, system TUN on macOS, WinTun driver on Windows. |
| Rust toolchain | 1.95 | Pinned via `rust-toolchain.toml`. |
| Build tools | `protoc 25.5`, `libclang-dev`, a C linker (`gold` or `lld`) | `protoc` ≥ 25 is required because the build uses `--experimental_allow_proto3_optional`. |
| Disk | ~2.5 GB for the release `target/` tree; resulting binaries: `pactmesh-core` ~28 MB + `pactmesh` ~13 MB (release + LTO + strip, default features) | |
| Network ports | 1 TCP/UDP port per node (default `11010`) | Listener port is configurable. |

For Ubuntu 20.04 the system `mold` package is unavailable; use `gold` (`binutils-gold`) and set `-fuse-ld=gold` in `.cargo/config.toml`. Newer distributions can use `lld` or `mold` directly.

## Build from source

```bash
git clone <your-fork-url> PactMesh
cd PactMesh
# Or, if you only have a tarball drop:
#   tar xf privatenetwork-src.tgz && cd privatenetwork

# Make sure cargo and protoc are on PATH.
export PROTOC=$(command -v protoc)

cargo build --release -p pactmesh
```

Two binaries land in `target/release/`:

- `pactmesh-core` — the daemon (long-running, runs the data plane and trust services).
- `pactmesh` — the operator CLI (signs certs, manages members, manipulates trust state on disk).

Install them to a system path:

```bash
sudo install -m 0755 target/release/pactmesh-core /usr/local/bin/
sudo install -m 0755 target/release/pactmesh /usr/local/bin/
```

Verify:

```bash
pactmesh --version
pactmesh-core --version
```

## File layout and environment

`pactmesh` writes trust-domain state under `$HOME/.config/privateNetwork/` by default. The layout is:

```
~/.config/privateNetwork/
├── trust-domains/
│   └── <trust_domain_id>/                       # one directory per owned domain
│       ├── pk_root.pem                          # PEM (PNW-PK-ROOT label), 32-byte Ed25519 root public key
│       ├── sk_root.age                          # age-encrypted (Argon2id) root private key
│       └── networks/
│           └── <network_local_id>/
│               ├── network_state.cbor.pem       # signed NetworkState payload
│               ├── network_state.v1.cbor.pem    # historical versioned state snapshot
│               ├── member_cert.pem              # local node's member cert (only on member devices)
│               ├── device_id                    # device key indirection
│               └── sk_self.raw                  # default unencrypted device signing key copy
└── devices/
    └── default/
        ├── pk_self.pem                          # default device public key
        └── sk_self.raw                          # default unencrypted device signing key
```

The management password is used by CLI commands that sign with `SK_root` (`create-domain`, `create-network`, `bootstrap-self`, `approve`, `revoke`, `disable`, `enable`, `set-hostname`, `unset-hostname`). Provide it interactively, through `PNW_ROOT_PASSPHRASE`, or via `--passphrase-file`. The daemon should not keep this password in its environment.

Device keys default to `sk_self.raw`, protected by local filesystem permissions, so the daemon can restart without a device-key passphrase. If you explicitly set `PNW_DEVICE_PASSPHRASE` or use a device `--passphrase-file`, PactMesh writes `sk_self.age`; then the daemon needs an environment variable named by `trust_domain.sk_self_password_env` (for example `PNW_DEVICE_PASSPHRASE`) and the matching `--sk-self-password-env` / TOML field.

## Two-node happy path

This walkthrough sets up a two-node home network. Node A is the operator (holds `SK_root`); node B is a joining device.

### On node A — create the domain and network

```bash
# Generate the root key pair. The root private key is sealed with PNW_ROOT_PASSPHRASE.
PNW_ROOT_PASSPHRASE='long-passphrase-please' \
  pactmesh trust create-domain \
    --label home \
    --out-dir "$HOME/.config/privateNetwork/trust-domains"
# Output includes the trust_domain_id (SHA-256 of PK_root); copy it down.

# Create a network inside the domain. The default ACL action is 'accept'
# (open by default; tighten later by editing network_state and re-signing).
PNW_ROOT_PASSPHRASE='long-passphrase-please' \
  pactmesh trust create-network <trust_domain_id> home \
    --default-action accept

# Export an invite bundle that node B can consume. The seed URL points at
# a node that the joining device can reach for the initial handshake.
pactmesh trust invite <trust_domain_id> home \
  --seed tcp://nodea.example.com:11010 \
  --format url \
  --out /tmp/invite.txt
# /tmp/invite.txt now contains a `privatenetwork://join?...` URL.
```

### Transport the invite

Move `/tmp/invite.txt` to node B over any reasonably trusted channel. The invite carries only public information (the lender's `PK_root`, the network's local id, and a seed peer address); it does not embed any private key.

### On node B — accept the invite

```bash
# Default (online) path: the CLI generates the device key locally on B, builds
# the join request, and connects directly to the invite seed's join-admission
# endpoint (= seed port + 1) to submit it, then polls for approval. Once node A
# approves, the CLI pulls the signed member_cert back and writes it to
# ~/.config/privateNetwork/trust-domains/<td_id>/networks/home/. No manual file
# shuffling is required.
pactmesh trust accept-invite "$(cat /tmp/invite.txt)" \
    --device-label nodeb-laptop \
    --hint 'nodeb laptop for Alice'
```

> The device private key is generated on B and never leaves it; the invite carries
> public information only; the member_cert flows back automatically over the
> admission endpoint.
>
> **Air-gapped fallback**: with `--offline`, the command only writes
> `pending_join_request.cbor.pem` and stops, contacting nothing — you must hand the
> file to a root operator for approval and copy the signed member_cert back to B.
> Use only when B cannot reach the seed's admission endpoint.

### Approve the join (on node A)

On the online path, the node A that the invite seed points to must be running its
daemon — it automatically exposes a join-admission endpoint on the listener port + 1.
The operator approves pending joins on A: the TUI Joins tab (`:approve <fp_prefix>` /
`:reject`), or the CLI `pactmesh trust list-members --include pending` with
approve/reject. Approval signs the member_cert with the root key; B's poll fetches it.

### Bring up the data plane

Both nodes need a daemon config that points at the trust domain. The minimal node config is:

```toml
# ~/.config/privateNetwork/networks/<td_id>_home.toml
network_name = "home"
hostname = "nodea"          # or "nodeb" on the other node
ipv4 = "10.244.0.1"         # or another IP within the network's allocated range
listeners = ["tcp://0.0.0.0:11010"]
peers = ["tcp://nodea.example.com:11010"]  # node B only; node A omits this

[trust_domain]
domain_dir = "/home/alice/.config/privateNetwork/trust-domains/<td_id>"
network_local_id = "home"
sk_self_password_env = "PNW_DEVICE_PASSPHRASE"
```

Start the daemon:

```bash
pactmesh-core --config-file ~/.config/privateNetwork/networks/<td_id>_home.toml
```

Both daemons should converge: the trust-aware handshake verifies the other side's member cert, ACL rules are loaded from the signed NetworkState, and traffic flows over the TUN interface (`et0` by convention).

## TUI quick setup (alternative to the CLI happy path)

`pactmesh tui` is a terminal UI that drives the same daemon RPC as the CLI, plus
one-shot setup wizards and a service supervisor. It avoids hand-editing TOML and
is the fastest path on a fresh node.

```bash
pactmesh tui                      # connects to a local daemon if one is running
```

Commands are typed at the `:` prompt:

| Command | Effect |
|---|---|
| `:setup-root` | Wizard: create a domain + network and write the node TOML, then arm a local daemon. With args: `:setup-root <network> <label> <seed-url> <listen_port> <rpc_port> [domain_label]`. |
| `:setup-join <invite-url> <network> <label> <rpc_port>` | Wizard: consume an invite URL, generate the device key + join request, and write the member TOML. Bare `:setup-join` opens the interactive form. The invite URL may contain spaces when quoted. |
| `:daemon <start\|stop\|restart\|status> [service]` | Supervise the local `pactmesh-core` daemon. |
| `:reconnect <peer_hostname>` | Force a fresh dial to a peer (see "Peer hints and LAN recovery"). |
| `:accept-root-upgrade [ttl_secs]` | Arm this node to accept a remote root-key push (see "Upgrade a member to root"). |
| `:relay-grant <foreign_td_hex> [data=true] [holepunch=true] [ttl=<secs>] [remove]` | Grant/revoke cross-trust relay at runtime (see "Cross-trust-domain relay borrowing"). |

The wizards write the same on-disk layout described above, so a node set up via
the TUI can later be operated entirely from the CLI and vice versa.

## Configuration file reference

The daemon TOML is the standard EasyTier config plus a `[trust_domain]` section. The fields specific to PactMesh are:

| Field | Type | Required | Description |
|---|---|---|---|
| `trust_domain.domain_dir` | path | yes | Absolute path to the trust-domain directory (`.../trust-domains/<td_id>/`). |
| `trust_domain.network_local_id` | string | yes | Network id within the domain; must match the directory at `<domain_dir>/networks/<network_local_id>/`. |
| `trust_domain.sk_self_password_env` | string | yes | Name of the env var the daemon reads to decrypt the device key. |
| `trust_domain.relay_serving[]` | table list | no | Entries that tell this node to act as a relay for foreign trust domains. See "Cross-trust-domain relay borrowing" below. |

Configuration precedence is **CLI flag > environment variable > TOML config**. The trust-domain flags on `pactmesh-core` are:

- `--trust-domain-dir <PATH>` / `ET_TRUST_DOMAIN_DIR`
- `--network-local-id <ID>` / `ET_NETWORK_LOCAL_ID`
- `--sk-self-password-env <VAR>` / `ET_SK_SELF_PASSWORD_ENV`

Use `pactmesh-core --check-config -c <PATH>` to validate a config file without starting the data plane.

## Running as a systemd service

A minimal unit file for a per-user install:

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

`/etc/privatenetwork/home.toml`: as above, with `domain_dir` pointing inside `/var/lib/privatenetwork/...`.

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now privatenetwork@home.service
sudo systemctl status privatenetwork@home.service
journalctl -u privatenetwork@home.service -f
```

If you configure encrypted device keys, the env file holds the device-key passphrase; restrict it to `0600` and root ownership (`chmod 600 /etc/privatenetwork/home.env; chown root:root /etc/privatenetwork/home.env`). With the default `sk_self.raw` layout, the daemon does not need a device-key passphrase. The daemon only needs `CAP_NET_ADMIN` for TUN provisioning, not root.

## Firewall and reachability

Inbound: open the listener port (default `11010/tcp` and `11010/udp`; both are typically declared since EasyTier supports either transport). If multiple listeners are configured, open each.

**Join-admission port (root nodes must open it)**: the daemon automatically exposes a
join-admission RPC on each TCP listener port **+1** (default `11011/tcp`). A new device's
online `accept-invite` connects to this port to submit its request and fetch the cert.
A root node acting as an invite seed must open this port to the public internet, or online
joins hang at "Connecting to join admission endpoint". Pure member nodes that never admit
joins can leave it closed.

```bash
# ufw
sudo ufw allow 11010/tcp
sudo ufw allow 11010/udp
sudo ufw allow 11011/tcp   # join-admission port (listener port + 1); root nodes

# firewalld
sudo firewall-cmd --add-port=11010/tcp --permanent
sudo firewall-cmd --add-port=11010/udp --permanent
sudo firewall-cmd --add-port=11011/tcp --permanent   # join-admission port
sudo firewall-cmd --reload
```

Outbound: most NATs are traversed automatically (EasyTier handles STUN, hole-punching, and relay fallback). If you operate a relay node behind a stable address, that node's listener port must be reachable from the public internet. If no node has a public address, configure `trust_domain.relay_serving` on a friend's trust domain (see below) so their relay can be borrowed.

ICMP/IPv4: ensure the TUN subnet (default in the 10.244.0.0/16 range; configurable per network) is not filtered by host firewalls on either side.

## Multi-trust-domain setup

A single device can participate in multiple trust domains as separate members. Each membership maps to its own daemon instance with its own config file:

```
~/.config/privateNetwork/
├── trust-domains/
│   ├── <td_alice>/
│   │   └── networks/home/    (membership as nodea-laptop in Alice's network)
│   └── <td_bob>/
│       └── networks/team/    (membership as alice-laptop in Bob's network)
└── networks/
    ├── <td_alice>_home.toml
    └── <td_bob>_team.toml
```

Run two daemons:

```bash
# Alice's home network
pactmesh-core --config-file ~/.config/privateNetwork/networks/<td_alice>_home.toml &

# Bob's team network
pactmesh-core --config-file ~/.config/privateNetwork/networks/<td_bob>_team.toml &
```

If you use encrypted device keys, set distinct `sk_self_password_env` values in each config so the two daemons unlock their own device keys. With systemd, use template instances (`privatenetwork@home` and `privatenetwork@team`).

The two networks share neither key material nor ACL policy. Cross-traffic between them flows only via the host's normal IP stack (i.e., the two TUN interfaces are independent).

## Cross-trust-domain relay borrowing

Borrowing lets a node in trust domain A use a relay in trust domain B without the two domains merging.

### On the lending side (trust domain B, owner Bob)

1. Add the relay node into `TrustDomainMeta.active_relays` (signed when Bob creates the network or refreshes the meta).
2. Sign an `OutboundGrant` for trust domain A:

```bash
# Conceptually — these commands are surfaced through the daemon RPC and CLI
# trust subcommands. The grant carries (foreign_root_pk, foreign_td_id,
# capabilities, expires_at) and is included in the next TrustDomainMeta
# revision.
```

3. Distribute the updated `TrustDomainMeta` to A (a file copy or QR-coded `NetworkBootstrap` is enough; signatures are self-validating).

4. On Bob's relay node, configure `relay_serving` so the daemon will accept relay requests from A:

```toml
[[trust_domain.relay_serving]]
foreign_root_pk_hex = "abcdef0123...64-hex-chars"
foreign_trust_domain_meta_pem = "/etc/privatenetwork/foreign/td_alice_meta.pem"
can_relay_data = true
can_assist_holepunch = true
expires_at = 1782345600     # unix seconds; should match the grant expiry
```

### On the borrowing side (trust domain A)

1. Place the signed `TrustDomainMeta` from Bob into a path that A's nodes can read (the daemon attaches a `BorrowedRelayProof` derived from this meta when handshaking with Bob's relay).

2. Reference Bob's relay node in `peers` exactly the same as any seed:

```toml
peers = [
    "tcp://relay.bob.example.com:11010",
]
```

The borrow proof and capability flags are verified locally by Bob's relay; no central coordination happens.

### Runtime grants and enforcement

Relay grants are **enforced** end to end. When a foreign peer dials Bob's relay,
the relay checks the borrow proof against the grant table before forwarding:

- A grant with `can_relay_data = true` lets the foreign peer relay data traffic.
- A grant with `can_assist_holepunch = true` lets it use the relay only to
  coordinate hole-punching (control/RPC); data packets are still dropped.
- A peer presenting a borrow proof with **neither** capability granted is
  rejected at connection time — there is no implicit fallback.

Bob can add or revoke a grant **without restarting the daemon** from the TUI:

```text
:relay-grant <foreign_td_hex> data=true holepunch=true ttl=86400
:relay-grant <foreign_td_hex> remove
```

This patches the running config's `relay_serving` list in memory and hot-reloads
the grant table (default `ttl` is 86400s when omitted). The change is not
persisted to TOML — re-add the `[[trust_domain.relay_serving]]` block for it to
survive a restart.

## Operational tasks

### Revoke a member (permanent)

```bash
PNW_ROOT_PASSPHRASE='...' \
  pactmesh trust revoke <trust_domain_id> home <member_cert_fingerprint> \
    --reason key-compromise \
    --note 'lost laptop 2026-05-10'
```

Revocation is irreversible: the entry is recorded in `NetworkState.revoked_certs` and propagates through the next signed-config refresh. Other nodes reject any traffic from the revoked fingerprint.

When a node applies a signed state that revokes (or disables) a member, it
**immediately invalidates that peer's live data-plane session** — the existing
traffic keys stop decrypting and the connection is torn down. Revocation does not
wait for a key-rotation interval; a compromised member is cut off as soon as the
revoking state reaches each node.

### Disable a member (reversible)

```bash
PNW_ROOT_PASSPHRASE='...' \
  pactmesh trust disable <trust_domain_id> home <member_cert_fingerprint> \
    --until 2026-06-01T00:00:00Z \
    --note 'travel ban'

# To reinstate before the expiry:
PNW_ROOT_PASSPHRASE='...' \
  pactmesh trust enable <trust_domain_id> home <member_cert_fingerprint>
```

### Set a hostname (MagicDNS)

```bash
PNW_ROOT_PASSPHRASE='...' \
  pactmesh trust set-hostname <trust_domain_id> home <member_cert_fingerprint> alice-laptop
```

The hostname is signed into a new `MemberCert` (superseding the previous one). Other nodes write a `# privateNetwork` block into their hosts file with one line per active member.

### List members

```bash
pactmesh trust list-members <trust_domain_id> home --include active
pactmesh trust list-members <trust_domain_id> home --include all --json
```

`--include` accepts `active | revoked | disabled | pending | all`.

### List local trust domains

```bash
pactmesh trust list-domains
```

### Upgrade a member to a root device

A trust domain can have more than one device holding `SK_root`. To promote an
existing member node to a root device, the current root pushes the (re-encrypted)
root key to the target over the authenticated mesh. The target never reads the
passphrase from its environment — it must explicitly **arm a one-shot acceptance
token** first:

1. On the **target** node's TUI, arm acceptance and enter the passphrase that
   will seal the incoming `sk_root.age`:

   ```text
   :accept-root-upgrade            # default TTL; or ":accept-root-upgrade 300" for 5 min
   ```

   A passphrase modal opens; the token is single-use and expires when the TTL
   elapses.

2. From the **current root**, trigger the push (daemon RPC `UpgradePeerToRoot`,
   surfaced through the operator CLI/TUI). The target consumes its armed token,
   verifies that `SK_root` derives the expected `PK_root` (`pk_root.pem`), and
   writes `sk_root.age`. No member cert is issued by this step.

If the token is absent, already used, or expired, the target rejects the push
with "no armed root-upgrade acceptance". Re-arm and retry.

### Peer hints and LAN recovery

Each node remembers recently seen peer addresses ("hints") so it can re-establish
direct links after a transport blip or an IP change without waiting for a full
seed re-handshake. To force an immediate redial of a specific peer (for example
after moving a laptop between networks):

```text
:reconnect <peer_hostname>
```

On a shared LAN, nodes also rediscover each other via local broadcast, so a
network that loses its public seed can keep converging as long as the members
share a segment.

## Windows deployment

PactMesh's Windows binaries are produced by the `windows-x86_64` GitHub Actions
workflow (authoritative MSVC build). Cross-compiling to Windows from Linux is not
supported (the `ring` crypto crate requires the MSVC toolchain), so use the CI
artifact rather than a local cross build.

### Obtain the artifact

1. Push to `main` (paths under `pactmesh/**`, `Cargo.*`, or the workflow file) or
   run the workflow manually (`Actions → Windows x86_64 Build → Run workflow`).
2. When the run goes green, download the `pactmesh-windows-x86_64` artifact. It
   contains `pactmesh.exe`, `pactmesh-core.exe`, the bundled `wintun.dll` /
   `Packet.dll`, and `WinDivert64.sys`.
3. Unzip into a working directory, e.g. `C:\PactMesh\`. Keep the `.dll`/`.sys`
   files next to the executables.

### Run on Windows

- Open **PowerShell or Command Prompt as Administrator** — TUN provisioning and
  writing the hosts file both require elevation.
- The WinTun driver is loaded from the bundled `wintun.dll`; no separate install
  is needed. Windows may prompt to trust `WinDivert64.sys` on first use.
- MagicDNS writes its `# privateNetwork` block to
  `C:\Windows\System32\drivers\etc\hosts`; this only succeeds from an elevated
  process.

```powershell
cd C:\PactMesh
.\pactmesh.exe tui              # setup wizards + supervisor, same as Linux
# or run the daemon directly:
.\pactmesh-core.exe --config-file C:\PactMesh\home.toml
```

Use `:setup-join` in the TUI to consume an invite and write the node config, then
`:daemon start` to launch `pactmesh-core`. Config and trust-domain state live
under `%USERPROFILE%\.config\privateNetwork\` mirroring the Linux layout.

> Real-device checklist for a mixed A/B/C test (Linux A + Linux B + Windows C):
> (1) create the domain/network on A; (2) invite + `accept-invite` on B and C;
> (3) approve both joins on A; (4) start all three daemons; (5) confirm C reaches
> A and B over the TUN subnet and that MagicDNS hostnames resolve on C.

## Troubleshooting

| Symptom | First checks |
|---|---|
| Daemon exits with "trust_domain.domain_dir is required" | The TOML config either lacks the `[trust_domain]` section or one of the three required fields. Run `pactmesh-core --check-config -c <file>`. |
| Daemon exits with "trust_domain member_cert.pem not found" | The path `<domain_dir>/networks/<network_local_id>/member_cert.pem` doesn't exist. Either the device hasn't completed `accept-invite`, or the network_local_id doesn't match the directory name. |
| Online `accept-invite` hangs at "Connecting to join admission endpoint" | Can't reach the seed node's join-admission port (listener port + 1, default `11011`). Confirm the root node acting as seed has that port open to the public internet and its daemon is running; on air-gapped networks use `--offline` for manual approval. |
| Daemon exits with "failed to read sk_self password from env var" | The device key is encrypted as `sk_self.age`, but the env var named in `sk_self_password_env` is not set in the daemon environment. With systemd, check `EnvironmentFile=`. The default `sk_self.raw` path does not need this. |
| Daemon starts but no peers connect | (1) Verify listener port is open (firewall). (2) Verify the `peers` URLs are reachable. (3) Inspect logs for `member_cert verify failed` or `handshake rejected`. |
| `member_cert verify failed` in logs | The other side presented a member cert that didn't verify against the local trust-domain root. Likely a different trust domain, a wrong network, or a revoked/superseded cert. |
| `trust_domain_id mismatch` | The TOML's `domain_dir` points at a directory whose `pk_root.pem` does not hash to a `trust_domain_id` consistent with the loaded member cert. Typically caused by editing or restoring directories across domains. |
| Traffic flows but ACL drops everything | Either the network was created with `--default-action drop`, or the trust ACL policy is missing/undecodable. Trust networks **fail closed**: with no usable ACL policy, member-to-member *data* is dropped (control/RPC/handshake channels stay exempt). Sign and distribute a valid ACL policy, or re-create the network with `--default-action accept`. |
| A peer's advertised subnet routes are ignored | Proxy CIDRs are trimmed against the advertiser's member-cert `can_proxy_subnet`. A peer (or this node) can only announce subnets its cert authorizes; anything beyond is dropped. Re-issue the member cert with the needed `can_proxy_subnet` entries. |
| Foreign relay peer rejected at connect | The borrow proof lacks a matching grant. On the relay, add one with `:relay-grant <foreign_td_hex> data=true` (and/or `holepunch=true`), or restore the `[[trust_domain.relay_serving]]` block. |
| Hostname not resolving | (1) The member cert may lack a hostname; run `trust set-hostname`. (2) The host's `/etc/hosts` (or Windows equivalent) may not yet have the `# privateNetwork` block — wait for the next sync cycle or restart the daemon. |
| `cargo build` fails with "experimental_allow_proto3_optional" | Install protoc 25.5 or later. The Ubuntu 20.04 package ships 3.6.1, which does not accept the flag. |

For deeper investigation, enable trace logging:

```bash
RUST_LOG=pactmesh::trust=debug,pactmesh::peers=debug \
  pactmesh-core --config-file <file>
```

Key log targets:

- `pactmesh::trust::*` — trust-pool verification, member-cert lifecycle, ACL decisions.
- `pactmesh::peers::peer_conn` — handshake states (noise / plain / routing).
- `pactmesh::peers::peer_manager` — peer membership churn.

If a `cargo test --test trust` regression is suspected on a build host, also run:

```bash
cargo test --workspace --no-run                # ensures everything compiles
cargo test --test trust                        # umbrella trust unit tests
cargo test --test acl_e2e --test magicdns_e2e  # e2e scenarios
```

## Further reading

- `README.md` — feature overview and quick start.
- `trust-and-config-design.md` — trust model, NetworkState, TrustDomainMeta, signing flows.
- `acl-schema-draft.md` — ACL schema and validation rules.
- `THIRD_PARTY_NOTICES.md` — license notices and dependency provenance.
