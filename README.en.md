# Veilink

> **Important (read this first)**
>
> Veilink is an **explicit HTTP proxy**: it only handles traffic that is explicitly sent to it. Anything
> that bypasses the proxy — and any name resolution that happens outside it — is not protected by
> Veilink. In particular, you must verify each of these yourself:
>
> - **Browser/OS direct connections**: if the proxy configuration is incomplete (for example HTTP is
>   configured but HTTPS is not, or a "no proxy for" list is filled in, or an application ignores the
>   system proxy), traffic goes out directly.
> - **DNS pre-resolution (prefetch/preconnect) and DoH/DoT**: the browser may resolve names locally, or
>   send the query to a DoH provider, completely bypassing the proxy. On the `PROXY` path the Veilink
>   client does not resolve names, but it cannot stop the browser from doing so.
> - **UDP / QUIC (HTTP/3)**: Veilink carries **TCP only**. When a browser enables QUIC, HTTP/3 traffic
>   is UDP and will bypass the proxy; verify the browser's QUIC/HTTP3 behaviour and disable it if needed.
> - **Non-HTTP protocols**: SSH, SMTP, BitTorrent and so on are not HTTP proxy traffic and will not go
>   through Veilink (SSH-over-CONNECT is described under "Git proxy configuration").
>
> In short: **installing Veilink does not mean all your traffic is protected.** Check the actual path
> using the `route=DIRECT` / `route=PROXY` log lines, packet capture, or your browser's developer tools.

---

## Introduction

Veilink is a privacy-focused **encrypted HTTP/HTTPS proxy**. It has two parts:

- a **client** that listens on a normal HTTP proxy port on your machine (default `127.0.0.1:7890`) and
  decides, per request, whether the traffic is **connected directly (`DIRECT`)** or **forwarded through
  your VPS (`PROXY`)**;
- a **server** that runs on your VPS, authenticates clients, **resolves names remotely**, connects to
  the target under an egress policy, and splices bytes between the encrypted tunnel and the target
  socket.

Traffic between them uses the **VLP/1** protocol: a PSK-authenticated connection bound to the specific
TLS session, multiplexing many streams, where **every frame is protected by a key derived from a
one-time X25519 exchange** (forward secret). The outer layer is TLS 1.3 + HTTP/2 by default, so it
looks like an ordinary HTTP/2 session; a raw TLS frame stream is also available.

The motivation: keep the target host name and the traffic content hidden from the local network and
intermediate networks, while **not** turning the VPS into a pivot into its own private network or
cloud metadata (the server denies loopback, private and link-local destinations by default).

To be clear: Veilink **cannot** make you anonymous, **cannot** defeat traffic analysis or website
fingerprinting, and **cannot** hide the fact that you are using Veilink. The full boundary is in
[Security model](#security-model), [docs/privacy.md](docs/privacy.md) and
[docs/threat-model.md](docs/threat-model.md) (both in Chinese).

---

## Features

**Protocol and cryptography**

- `VLP/1` framing: `0x56` version byte, a 76-byte authenticated header (the whole header is the AEAD
  associated data), and cleartext handshake frames.
- Per-frame forward secrecy: a receiver-side pool of one-time X25519 keys (default 256, published in
  batches of 64, destroyed on use) and a fresh sender ephemeral for every frame.
- Backpressure-driven replenishment: `KEY_OFFER` / `KEY_ACK` driven by peer traffic, with no separate
  timer.
- Three AEADs rotated per frame: AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM (chosen from the
  receiver's advertised set).
- A hash ratchet for the control channel, advanced only after a frame authenticates.
- Replay, tampering, relabelling and cross-session transplants are rejected; the sequence counter
  fails at `u64::MAX` instead of wrapping.
- Low-order and all-zero X25519 public keys are rejected; unauthenticated plaintext is wiped on tag
  failure.
- Keys are erased with `zeroize`; `Debug`/`Display` are redacted; a failing RNG fails closed (there is
  no fallback).

**Transport**

- TLS 1.3 (rustls + ring), ALPN `h2` / `vlp/1`; `transport: h2` (default) or `tls`.
- HTTP/2 as a **carrier**: one long-lived `POST` with a streaming response body; VLP/1 does the real
  multiplexing.
- Self-signed certificate plus TLS-exporter channel binding: **authentication comes from the PSK, not
  from a CA**; relays and replayed handshakes fail.
- Server identity pinning: `server_identity_pin` accepts the full fingerprint or a prefix of at least
  4 bytes, and refuses the connection before any traffic is forwarded when the identity does not match.

**Client**

- HTTP/1.1 forward proxy: absolute-form, origin-form, `CONNECT`, `Upgrade` (WebSocket), chunked and
  streamed responses, keep-alive, upstream connection reuse.
- **Byte-level**: after `CONNECT` or `101` it becomes a raw byte splice; no TLS termination, no URL
  rewriting, no caching.
- Local answers for `Expect: 100-continue`; hop-by-hop headers stripped; `Host` preserved or
  synthesised.
- Whitelist routing (`DOMAIN` / `DOMAIN-SUFFIX` / `IP` / `CIDR` / `*`) with domain canonicalisation
  (lower-case, trailing root dot removed, IDNA).
- **Fail closed**: a whitelisted request fails (502) when the tunnel is unavailable and is **never**
  served by a direct connection.
- The `PROXY` path performs **no local DNS resolution**; the name goes into the encrypted frame
  verbatim.
- Configuration hot reload (atomic whitelist replacement; session rebuild on endpoint/key/transport
  change).
- Jittered exponential backoff reconnection (500 ms → 60 s); whitelisted requests fail immediately
  during an outage instead of queueing.

**Server**

- **Authentication is mandatory**: the VLP/1 handshake must complete before any proxy request is read;
  there is no unauthenticated mode and no diagnostic oracle on failure.
- IPv4-only remote DNS (A records) with a bounded TTL cache (default 512 entries), timeouts and
  retries; no negative caching.
- Egress policy denying IANA special-use IPv4 ranges by default: loopback, RFC 1918, link-local
  (including cloud metadata `169.254.169.254`), CGNAT, benchmarking, documentation, multicast and
  reserved.
- `0.0.0.0/8`, `224.0.0.0/4`, `240.0.0.0/4`, `255.255.255.255/32` and `192.0.0.0/24` are **always**
  denied, even with `allow_private_targets` enabled.
- DNS-rebinding safe: the policy applies to **resolved addresses**, the connection is made to a
  **checked address**, and a mixed public/private answer is refused entirely.
- Optional destination port allow-list (`allowed_ports`), checked before resolution.
- Per-source-IP connection rate limiting, connection/stream/header/frame limits, idle timeouts, and
  periodic statistics logging.

**Privacy (Strict Privacy layer, on by default, not configurable)**

- Fixed-bucket padding: `512/1024/2048/4096/8192` and multiples of 8192 (up to 64 KiB), applied inside
  the AEAD; under budget pressure it **degrades to the smallest bucket** instead of switching off.
- Send batching: up to 16 frames / 64 KiB coalesced into one write.
- Idle cover traffic: real VLP/1 application frames using the same per-frame cryptography; starts
  after 750 ms of idleness, bursts of up to 3 frames (64–4096 bytes) every 1.5 s, capped at 40 bursts.
- Hard budgets: cover 4 KiB/s and 256 MiB per session; padding 4 MiB/s (separate windows).
- `log.log_domains` defaults to `false`, so targets print as `domain:<redacted>`; statistics contain
  no domain names or URLs.

**Engineering**

- Two YAML schemas with `deny_unknown_fields`, two-phase validation that reports **all** problems at
  once.
- CLI: `veilink client` / `server` / `keygen` / `check`.
- Unit tests plus integration tests (real `curl`, real TCP/TLS origins, a DNS stub, end-to-end tunnel)
  and Criterion benchmarks.
- GitHub Actions: fmt, clippy (`-D warnings`), tests, release build, a five-target cross-compilation
  matrix, a non-blocking `cargo audit`; `v*` tags trigger the release workflow and `SHA256SUMS`.

---

## Architecture

```text
┌──────────────┐   HTTP / CONNECT    ┌──────────────────────────────┐
│ Browser/curl │ ──────────────────► │  Veilink Client              │
│   git  ...   │   127.0.0.1:7890    │  ┌────────────────────────┐  │
└──────────────┘                     │  │ HTTP parse + framing   │  │
                                     │  └───────────┬────────────┘  │
                                     │              ▼               │
                                     │  ┌────────────────────────┐  │
                                     │  │ Rule Engine (whitelist)│  │
                                     │  └───────┬────────┬───────┘  │
                                     └──────────┼────────┼──────────┘
                                                │        │
                       DIRECT (local TCP,       │        │  PROXY (VLP/1 tunnel,
                       system resolver)         │        │  name encrypted, resolved remotely)
                                                ▼        ▼
                                        ┌──────────┐  ┌────────────────────────────┐
                                        │  Target  │  │ Secure Tunnel (TLS1.3/h2)  │
                                        └──────────┘  │  PSK auth + exporter bind  │
                                                      │  multiplexing + per-frame  │
                                                      │  one-time keys             │
                                                      └──────────────┬─────────────┘
                                                                     ▼
                                                        ┌──────────────────────────┐
                                                        │ VPS: veilink server      │
                                                        │  ├ auth (no PSK: close)  │
                                                        │  ├ remote DNS (A only)   │
                                                        │  ├ egress policy (deny   │
                                                        │  │  private/special)     │
                                                        │  └ splice(tunnel, target)│
                                                        └────────────┬─────────────┘
                                                                     ▼
                                                                  Target
```

Order of operations for one plaintext HTTP request inside the client: read the head (bounded) → parse →
derive the authority → canonicalise the target → whitelist decision → open a byte pipe (`DIRECT` or
`PROXY`) → forward head and body (exact framing) → read the response head (relaying 1xx) → forward the
response body → decide on keep-alive. `CONNECT` takes a separate path: consume the request head → open
the pipe → answer `HTTP/1.1 200 Connection Established` → raw byte splice. See
[docs/architecture.md](docs/architecture.md) (Chinese).

---

## Requirements

| Item | Requirement |
|------|-------------|
| Rust | 1.83 or newer (`rust-version = 1.83`), stable toolchain (the repo ships `rust-toolchain.toml`) |
| Platform | Builds on Linux / macOS / Windows; **Linux is recommended for the server** |
| System libraries | No OpenSSL: TLS comes from rustls + ring (ring compiles a little C, so a working C toolchain is needed) |
| Network | TCP reachability between client and server (default 443); the server needs outbound access to arbitrary public IPv4 addresses and UDP 53 for DNS |
| Privileges | Binding port 443 on the server needs root or `CAP_NET_BIND_SERVICE` (see [Server deployment](#server-deployment)) |
| Testing | Integration tests need the `curl` executable |
| Not supported | IPv6 egress, UDP/QUIC relay |

---

## Building

```bash
git clone https://github.com/veilink/veilink.git
cd veilink

# Release build (output: target/release/veilink)
cargo build --release

./target/release/veilink --version
./target/release/veilink --help

# Validate a configuration (starts nothing). Note: the `key` in examples/*.yaml is a
# placeholder, so checking them as-is reports a key error — replace it with the output of
# `veilink keygen` first:
./target/release/veilink check --config examples/client.yaml --verbose
./target/release/veilink check --config examples/server.yaml --verbose

# Tests (integration tests need curl)
cargo test --workspace

# Benchmarks (optional; compile only with --no-run)
cargo bench -p veilink-benches
cargo bench --no-run -p veilink-benches
```

The release profile uses `lto = "thin"`, `codegen-units = 1`, `panic = "abort"` and stripped symbols.
The binary is always named `veilink` (`veilink.exe` on Windows).

---

## Server deployment

> The complete guide (backup, upgrades, firewall details, running behind a middlebox) is in
> [docs/deployment.md](docs/deployment.md) (Chinese). The minimum steps are below.

**1. Create a user and directories (do not run the server as root)**

```bash
sudo useradd --system --home /var/lib/veilink --shell /usr/sbin/nologin veilink
sudo install -d -o veilink -g veilink -m 0700 /var/lib/veilink
sudo install -d -o root -g veilink -m 0750 /etc/veilink
sudo install -m 0755 target/release/veilink /usr/local/bin/veilink
```

**2. Generate the authentication key (once; both sides use the same value)**

```bash
veilink keygen          # Base64URL by default; --encoding hex for hexadecimal
veilink keygen --output /etc/veilink/psk.txt   # writes a 0600 file, refuses to overwrite
```

**3. Write the configuration**

```bash
sudo install -o root -g veilink -m 0640 examples/server.yaml /etc/veilink/server.yaml
sudoedit /etc/veilink/server.yaml
```

```yaml
listen: "0.0.0.0:443"
key: "<output of veilink keygen>"
state_dir: "/var/lib/veilink"
# Recommended: restrict which destination ports clients may reach
allowed_ports: [80, 443]
```

On first start the server creates `identity.key` (0600), `tls_cert.pem` and `tls_key.pem` (0600) in
`state_dir`.

**4. systemd unit** (key parts; the fully hardened unit is in the deployment document)

```ini
[Unit]
Description=Veilink encrypted proxy server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=veilink
Group=veilink
StateDirectory=veilink
StateDirectoryMode=0700
ExecStart=/usr/local/bin/veilink server --config /etc/veilink/server.yaml
Restart=on-failure
RestartSec=2s

# The minimal privilege needed to bind 443
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Hardening
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
UMask=0077

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now veilink
sudo journalctl -u veilink -f
```

**Why port 443 needs privilege**: Linux only allows `CAP_NET_BIND_SERVICE` (historically only root) to
bind ports below 1024. Besides the systemd capability above you can set
`net.ipv4.ip_unprivileged_port_start=443`, or listen on a high port and use a firewall REDIRECT.
**Do not run the server as root.**

**Firewall**: allow inbound 443 only (keep your SSH rules), and allow outbound as needed. nftables
example:

```nft
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif "lo" accept
    ct state established,related accept
    tcp dport 22 accept      # adjust as needed
    tcp dport 443 accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output priority 0; policy accept; }
}
```

**State directory and backup**: `state_dir` contains only `identity.key`, `tls_cert.pem` and
`tls_key.pem`. **Back up `identity.key` if you want the same server fingerprint**; deleting it
generates a new identity. Backups contain private keys and must be treated as secrets (and note the
server refuses to load an `identity.key` that is readable by group or others).

**Behind a middlebox**: only **L4 (TCP/SNI) passthrough** is supported. VLP/1 authentication is bound
to the outer TLS session's exporter, which only the endpoint terminating TLS can compute; terminating
TLS offload (for example nginx `proxy_pass` or HAProxy `mode http`) is **not** supported. See section 8
of [docs/deployment.md](docs/deployment.md).

---

## Client deployment

**1. Get the binary**: unpack a release archive, or build with `cargo build --release` and use
`target/release/veilink`.

**2. Configure**

```bash
cp examples/client.yaml client.yaml
$EDITOR client.yaml
```

```yaml
server: "203.0.113.10:443"      # your VPS (host name or IPv4 literal)
key: "<exactly the same key as the server>"
whitelist:
  - "DOMAIN,github.com"
  - "DOMAIN-SUFFIX,githubusercontent.com"
  - "CIDR,140.82.112.0/24"
# Optional:
# listen: "127.0.0.1:7890"
# transport: h2                 # or tls; must match the server
# server_identity_pin: "aa:bb:cc:dd"   # recommended: the identity= value the server logs
```

**3. Validate and run**

```bash
veilink check --config client.yaml --verbose

# Foreground (Ctrl-C to stop)
veilink client --config client.yaml

# Or as a user service (systemd --user)
# veilink client --config ~/.config/veilink/client.yaml --no-reload
```

Startup logs the listen address, the remote address, the number of whitelist rules, and
`configure your application to use http://127.0.0.1:7890 as its HTTP and HTTPS proxy`. Every request
then logs `route=DIRECT` or `route=PROXY` (with the domain only when `log_domains` is enabled).

**Security note**: `listen` defaults to `127.0.0.1`. **Do not** change it to `0.0.0.0` — that exposes
your proxy to the whole local network or the internet (the local proxy does not authenticate clients).

---

## Generating the authentication key

```bash
veilink keygen
# 34Xv... (unpadded Base64URL, 43+ characters, decoding to 32 bytes = 256 bits)

veilink keygen --encoding hex          # 64 hexadecimal characters
veilink keygen --count 3               # 3 keys at once (1–64)
veilink keygen --output key.txt        # write to a file, mode 0600 on Unix; refuses to overwrite unless --force
veilink keygen --quiet                 # print only the key
```

Requirements and caveats:

- The key must be a **high-entropy random value**, not a passphrase. `Psk::parse` rejects inputs that
  are too short, a single repeated byte, all zeroes, a repeating pattern of ≤8 bytes, or that contain
  too few distinct byte values, and tells you to run `veilink keygen`.
- Client and server must use **exactly the same** `key`.
- The key is a **symmetric shared secret**: anyone holding it can use your server and can impersonate
  it. If it leaks, both sides must be changed **together** (there is no graceful rotation).
- Put the `identity=` value printed by `veilink server` into the client's `server_identity_pin`: a swapped
  VPS then becomes a visible connection failure instead of a silent one.

---

## Whitelist YAML example

```yaml
whitelist:
  # Exact match: github.com only
  - "DOMAIN,github.com"
  # The domain and every subdomain (DNS label boundary; does not match fakegithub.com)
  - "DOMAIN-SUFFIX,githubusercontent.com"
  # Single-label wildcard: matches api.dev.example.com, not api.example.com
  - "DOMAIN,api.*.example.com"
  # Matches IPv4 literal targets only
  - "IP,1.1.1.1"
  # IPv4 network (host bits are normalised away)
  - "CIDR,140.82.112.0/24"
  # Catch-all: everything goes through the server (enable if you want it)
  # - "*"
```

Semantics:

- Rules are evaluated **in order** and the **first match wins**; an empty `whitelist` means
  **everything is DIRECT**.
- Domain targets are only compared against `DOMAIN`, `DOMAIN-SUFFIX` and `*`; IPv4 literals only
  against `IP`, `CIDR` and `*`. So `IP`/`CIDR` **never** trigger a local DNS lookup in order to match.
- Before matching, names are canonicalised: trimmed, one trailing root dot removed, lower-cased, and
  non-ASCII labels converted to IDNA A-labels.
- Duplicate rules (by canonical identity) are rejected.
- The full syntax, every error message and every configuration field are in
  [docs/configuration.md](docs/configuration.md) (Chinese).

---

## curl tests

Make sure the client is running and that `whitelist` covers the target you are testing.

```bash
# 1) Basic connectivity (DIRECT or PROXY depending on the whitelist)
curl -x http://127.0.0.1:7890 http://example.com/ -o /dev/null -w '%{http_code}\n'

# 2) HTTPS (CONNECT tunnel; Veilink does not terminate TLS)
curl -x http://127.0.0.1:7890 https://github.com/ -o /dev/null -w '%{http_code}\n'

# 3) Confirm the path taken: the client logs route=PROXY / route=DIRECT
curl -x http://127.0.0.1:7890 -v https://github.com/ 2>&1 | grep -E 'CONNECT|200 Connection'

# 4) Large-transfer integrity (compare sha256 through the proxy and directly)
curl -x http://127.0.0.1:7890 https://raw.githubusercontent.com/.../file.bin -o via-proxy.bin
curl                       https://raw.githubusercontent.com/.../file.bin -o direct.bin
sha256sum via-proxy.bin direct.bin

# 5) Upload and streaming responses
curl -x http://127.0.0.1:7890 -X POST --data-binary @some-file.txt http://example.com/upload

# 6) Confirm fail-closed: point `server` at an unreachable address (or stop the VPS).
#    A whitelisted request must fail (502) rather than silently succeed over a direct connection.
curl -x http://127.0.0.1:7890 https://github.com/ -o /dev/null -w '%{http_code}\n'
```

**Checklist** (more important than "the page loads"):

1. the log shows `route=PROXY`, not `route=DIRECT`;
2. on the VPS, packet capture / logs confirm the target connection came from the VPS;
3. stopping the VPS makes whitelisted requests **fail** (proving there is no direct fallback);
4. `dig`/`tcpdump` confirm the local resolver never sees the proxied name;
5. disabling QUIC/HTTP3 in the browser removes bypassing UDP traffic.

---

## Browser proxy configuration

**Firefox**

1. Settings → Network Settings → Manual proxy configuration;
2. HTTP proxy `127.0.0.1`, port `7890`; **also tick "Also use this proxy for HTTPS"**;
3. leave the "No proxy for" list **empty** (any entry there bypasses Veilink);
4. set `network.http.http3.enable` to `false` in `about:config` to avoid QUIC bypass.

**Chrome / Edge / Chromium**

- Use the system proxy (below), or start with:
  ```bash
  google-chrome --proxy-server="http://127.0.0.1:7890"
  ```
- Set `chrome://flags/#enable-quic` to `Disabled` so HTTP/3 does not go out over UDP.

**macOS**: System Settings → Network → Details → Proxies → enable **Web Proxy (HTTP)** and
**Secure Web Proxy (HTTPS)**, server `127.0.0.1`, port `7890`, and clear the bypass list.

**Windows**: Settings → Network & Internet → Proxy → Manual proxy setup → address `127.0.0.1`, port
`7890`; adjust "don't use the proxy server for local addresses" as needed.

**Always verify**: configuring HTTP but not HTTPS is a common mistake that leaves all HTTPS traffic
direct, and so is a populated bypass list. Use developer tools or packet capture to confirm the
connection really goes to `127.0.0.1:7890`.

---

## Git proxy configuration

**HTTPS remotes (`https://github.com/...`)**

```bash
# Globally
git config --global http.proxy  http://127.0.0.1:7890
git config --global https.proxy http://127.0.0.1:7890

# For one host only
git config --global http.https://github.com/.proxy http://127.0.0.1:7890

# Undo
git config --global --unset http.proxy
git config --global --unset https.proxy

# Test
GIT_CURL_VERBOSE=1 git ls-remote https://github.com/veilink/veilink.git | head
```

Make sure `whitelist` covers `github.com` and `githubusercontent.com`
(`DOMAIN,github.com` + `DOMAIN-SUFFIX,githubusercontent.com` + `DOMAIN-SUFFIX,githubassets.com`).

**SSH remotes (`git@github.com:...`)**: Git's HTTP proxy settings **do not affect SSH**. Two options:

1. switch to an HTTPS remote (recommended; it is covered by the whitelist and the proxy):
   ```bash
   git remote set-url origin https://github.com/veilink/veilink.git
   ```
2. route SSH through CONNECT (requires a `netcat` that supports `-X connect`), in `~/.ssh/config`:
   ```
   Host github.com
     ProxyCommand nc -X connect -x 127.0.0.1:7890 %h %p
   ```
   Note: the whitelist must match `github.com`, and the server's `allowed_ports` must permit **port
   22** (the default empty list allows all ports; if you restricted it to `[80,443]`, this fails).

---

## FAQ

**Q: A site is not going through the proxy.**
A: Look at the `route=` field in the client log. `route=DIRECT` means the whitelist did not match —
check the rule type (`DOMAIN` matches the exact host only; use `DOMAIN-SUFFIX` for subdomains) and the
canonicalisation (IDNA, trailing dot, case). Browser pre-resolution, DoH, QUIC and bypass lists can
also make it *look* like the proxy is not being used.

**Q: The browser says "the proxy server is refusing connections".**
A: The client is not running, `listen` does not match the browser configuration, or the port is in use.

**Q: A whitelisted request returns 502.**
A: That is **by design (fail closed)**: an unavailable tunnel, an egress-policy denial, or a remote
resolution failure all return 502 instead of falling back to a direct connection. Check the client and
server logs for the exact reason (`egress policy denied`, `remote DNS resolution failed`,
`cannot establish a secure session`).

**Q: Is IPv6 supported?**
A: **No.** IPv6 literals are rejected in rule parsing, request-target parsing and remote resolution;
the server has only IPv4 egress.

**Q: Is UDP / HTTP3 / QUIC supported?**
A: **No.** Veilink carries TCP only. With QUIC enabled, the browser's HTTP/3 traffic bypasses the
proxy; disable it.

**Q: Why does the connection drop after about five minutes?**
A: The idle timeout (`limits.idle_timeout_ms`, default 300000). There is currently **no** periodic
keepalive, so an idle session is closed; it reconnects automatically.

**Q: Why is there traffic while I am idle?**
A: The Strict Privacy layer's cover traffic (starts after 750 ms of idleness, runs for at most about
60 seconds, with both a rate and a lifetime budget) to weaken the "completely silent" signal. It does
not affect your target names or content.

**Q: Can several clients share one key?**
A: Yes, but they are equivalent: the server has **no per-client identity, quotas or revocation**.
Removing one client means rotating the PSK, which affects them all.

**Q: Can the server see what I visit?**
A: Yes. The server is the egress: it sees the host names and ports of all **PROXY** targets (it
resolves them), and the content of plaintext HTTP. `DIRECT` traffic never reaches it, and HTTPS
content is end-to-end encrypted between you and the target, so the server cannot read it.

**Q: `veilink check` reports errors. What do I do?**
A: It lists **all** problems at once as `field: reason` (for example `whitelist[2]`, `key`,
`dns.servers[0]`). Fix them one by one; `--verbose` prints the effective settings (never the key).

**Q: How much concurrency does it handle?**
A: Defaults are `max_connections: 1024`, `max_streams_per_session: 512`, a 64 KiB maximum frame
payload and 16 KiB per `STREAM_DATA`. These limits are deliberately conservative and can be tuned (see
the configuration document).

---

## DNS privacy boundary

| Scenario | Who resolves | Does the local resolver see the name? |
|----------|--------------|--------------------------------------|
| Whitelisted domain (`PROXY`) | **the server** (A records only) | **No** |
| Whitelisted IPv4 literal | nobody | No |
| Non-whitelisted domain (`DIRECT`) | the client's system resolver | **Yes** |
| Whitelisted but tunnel down | nobody; the request fails | No |
| Client → server connection (`server` is a name) | the client's system resolver | Yes (it sees the VPS name) |

Leak paths you must verify yourself:

- browser/OS **DNS pre-resolution** may query the local resolver directly;
- with **DoH/DoT** the browser sends queries straight to the DoH provider, bypassing the proxy entirely;
- applications that ignore the proxy, or that use non-HTTP protocols;
- the **`DIRECT` path**, where names and plaintext content are visible to the local resolver, the ISP
  and network observers (that is what "direct" means);
- on the server side, names are visible to the VPS operator (it needs them).

The server resolver queries A records only (no IPv6), clamps TTLs to 5 s–1 h, defaults to a 5 s timeout
and 2 attempts, and does not cache negative answers. See [docs/privacy.md](docs/privacy.md) (Chinese).

---

## Security model

**Protected (verifiable in the code)**

- Content confidentiality and integrity: bodies, methods, URLs, headers, cookies, target names and
  ports are all inside the AEAD ciphertext; the whole 76-byte header is the AAD, so any field change
  fails.
- Peer authentication: a PSK-bound handshake with TLS-exporter channel binding. Without the PSK the
  handshake cannot complete; relays, transparent proxies and replayed handshakes all fail; there is no
  downgrade path.
- Per-frame forward secrecy: every frame comes from a one-time X25519 exchange, and the receiver
  destroys its private half on use. Obtaining the PSK or the server's long-term identity key later
  does **not** decrypt recorded application frames.
- Replay and protocol-confusion resistance: sequence numbers plus one-time keys (application frames),
  a hash ratchet (control frames), and AAD binding (relabelling/cross-session).
- Local hiding of target names: the `PROXY` path does not resolve locally.
- Egress constraints: loopback/private/link-local/cloud-metadata destinations denied by default;
  connections made to a checked address; mixed public/private answers refused; optional port
  allow-list; resource limits.
- Fail-closed routing: a whitelisted request fails when the tunnel is unavailable, never falling back
  to direct.
- Key hygiene: redacted logs and `Debug`, private key files at 0600, an insecure `identity.key` stops
  startup, and buffers are wiped on tag failure.

**Explicitly not protected (must be told to users)**

- **Metadata**: server IP/port, the TLS handshake (including the self-signed certificate and SNI),
  connection timing, frame counts, bucket-sized lengths, direction and sequence numbers — and **the
  fact that Veilink is in use**.
- **Identifiability**: the frame header (`0x56`), ALPN, `veilink.invalid` and the self-signed
  certificate are strong features. **No claim of a zero detection rate.**
- **Traffic correlation and website fingerprinting**: padding only coarsens length; cover traffic only
  covers idle periods (and stops after about 60 seconds); scheduler pacing is bounded and
  unmeasured. There is **no** detection-rate evaluation in this repository. **No claim of being
  un-fingerprintable.**
- **Anonymity**: the server knows your IP; network observers know you talk to it. **No claim of
  absolute anonymity or untraceability.**
- **Endpoint security**: a compromised client host or VPS defeats everything; software erasure cannot
  defend against memory snapshots, swap, hibernation images or a hypervisor.
- **A malicious server**: it sees `PROXY` target names and plaintext HTTP content, and can modify or
  drop traffic.
- **Anything beyond authentication**: PSK holders are all equivalent; there are no per-client quotas or
  revocation.
- **Censorship resistance**: no domain fronting or traffic-camouflage guarantee, and no fallback
  channel when blocked.
- **Post-quantum**: X25519 is not quantum-resistant and there is no PQ hybrid.

**The real limits of software erasure**: `zeroize` only overwrites the memory it controls. Memory
snapshots, swap, hibernation images, core dumps, a compromised host or a hypervisor can all capture
secrets *before* erasure. Forward secrecy holds only if the private keys were genuinely erased and the
attacker had no memory access before that. Recommended: full-disk encryption, hibernation disabled,
swap restricted or encrypted, and a protected host.

Full analysis: [docs/cryptography.md](docs/cryptography.md), [docs/privacy.md](docs/privacy.md),
[docs/threat-model.md](docs/threat-model.md) and [SECURITY.md](SECURITY.md).

---

## Not implemented / current limitations

- **No IPv6** (no IPv6 egress; IPv6 literals are explicitly rejected).
- **No UDP / QUIC / HTTP3** (TCP only).
- **No terminating TLS offload**: a middlebox can only do L4 (TCP/SNI) passthrough.
- **No per-client identity, quotas or revocation**; PSK rotation is not graceful (both sides must
  change together).
- **Server identity is not pinned by default**: without `server_identity_pin` only the PSK is trusted, so
  another server sharing the same PSK is not detected (setting the pin is recommended).
- **Send pacing works but its effect is unmeasured**: batching and jittered pacing both take effect
  (a frame waits only when more messages are queued behind the current batch, and for at most 50 ms;
  see section 3.2 of [docs/privacy.md](docs/privacy.md)). No detection-rate measurement exists, so
  this is not evidence of fingerprinting resistance.
- **Cover traffic only covers idle periods** and stops after at most about 40 bursts; it is not a
  constant-rate generator.
- **No periodic keepalive**: idle sessions are closed by `idle_timeout`.
- **No metrics endpoint or management interface** (only periodic statistics logs).
- **`ERROR` (`0x7f`) is never sent**; `SequenceMode::Exact` is not used by the session codec.
- **No anti-fingerprinting/anti-classification evaluation**, and no real-network detection-rate data.
- Integration tests depend on `curl`; the repository currently has **no** automated real-network (for
  example GitHub) test (see [docs/testing.md](docs/testing.md)).
- **Fuzzing is a bounded smoke run, not a continuous campaign**: `fuzz/` holds five `cargo-fuzz`
  targets (frame reader, frame header, message decoder, rule parser, YAML validation). CI runs each
  for 60 seconds and uploads a crash artifact on failure; it does not run for long and keeps no
  long-lived corpus. The completed run covered about 15.4 million executions with no crash — that is
  a sample, not a proof. See section 7 of [docs/testing.md](docs/testing.md).

---

## License

MIT License. See [LICENSE](LICENSE).

Copyright (c) 2026 The Veilink Contributors.
