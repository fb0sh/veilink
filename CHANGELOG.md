# Changelog

All notable changes to Veilink are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Because the project is pre-1.0, the
`VLP/1` protocol version (`PROTOCOL_VERSION = 1`, frame version byte `0x56`) and the configuration
schemas are versioned separately from the crate version; any change to them is called out explicitly
below.

## [Unreleased]

### Added

- Five `cargo-fuzz` targets covering every synchronous parser that consumes untrusted bytes: the
  frame reader, the authenticated frame header, the message decoder, the whitelist rule parser and
  both YAML configuration parsers. Each asserts structural invariants (bounded lengths, canonical
  encodings, deterministic validation, no panic) rather than specific error variants. A `fuzz` job
  in CI runs every target for 60 seconds and uploads a crash artifact on failure.
- A `bind_client_with_retry` helper and deadline polling in the integration harness, so a port probe
  race or a background statistics reporter can no longer fail an unrelated test.

## [0.1.0] - 2026-10-12

The initial release: a working encrypted HTTP/HTTPS proxy with a client/server split, a per-frame
forward-secret protocol, and a strict-privacy layer.

### Added

**Protocol (`veilink-protocol`, the `VLP/1` wire protocol)**

- Frame layer with a 2-byte cleartext prefix (`0x56`, type byte) and a 76-byte authenticated header:
  session id, epoch, direction, sequence, algorithm id, key id, ciphertext length, sender ephemeral
  X25519 public key and nonce. The encoded header is the AEAD associated data, so every field is
  authenticated but none is encrypted.
- Cleartext handshake frames with a 16-bit length prefix, refused after the handshake completes.
- Authenticated payload layout `u16 real length | message | padding`, with the total rounded to a
  fixed bucket inside the AEAD plaintext.
- Thirteen message types with explicit, position-based big-endian encodings: `KEY_OFFER`,
  `KEY_ACK`, `OPEN_STREAM`, `OPEN_RESULT`, `STREAM_DATA`, `STREAM_FIN`, `STREAM_RESET`,
  `STREAM_WINDOW`, `PING`, `PONG`, `COVER_DATA`, `GOAWAY`, `ERROR`. Every variable-length field is
  bounded and validated before allocation.
- Two epochs: `0` for control frames (ratcheted key chain, `key_id = 0`, fixed ChaCha20-Poly1305)
  and `1` for application frames (fresh X25519 exchange per frame).
- Sequence-number semantics: strictly increasing send counter (fails at `u64::MAX` instead of
  wrapping); application frames checked monotonically before a one-time key is consumed and recorded
  only after authentication; control-frame replay prevented by the ratchet.
- Multiplexed streams with client-allocated odd ids and server-allocated even ids, a documented
  stream state machine, half-close (`STREAM_FIN`) and abort (`STREAM_RESET`).
- Credit-based flow control in both directions with a 256 KiB default window, a 16 KiB minimum and
  16 KiB maximum `STREAM_DATA`; a sender that runs out of credit parks instead of buffering.
- Bounded per-connection memory: strict maximum frame size, validated lengths before allocation, and
  a bounded outbound queue that applies backpressure.
- `duplex` plumbing shared by both peers: buffered head reads that preserve pipelined body bytes,
  exact byte-accounted forwarding, and a full-duplex splice with correct half-close behaviour.

**Cryptography (`veilink-crypto`)**

- Pre-shared authentication key (256-bit minimum) accepted as hexadecimal or unpadded Base64URL,
  with low-entropy sanity checks and redacted `Debug`/`Display`.
- PSK-bound handshake with fixed-size `CLIENT_HELLO` (36 bytes) and `SERVER_HELLO` (70 bytes),
  `AUTH_CONFIRM` (32-byte HMAC-SHA256), and a SHA-256 transcript over length-prefixed messages.
- Channel binding to the live TLS session through the exporter
  `EXPORTER-Veilink-VLP1`, so a relay between two TLS sessions, an unauthenticated peer and a
  replayed handshake all fail before any proxy request is read.
- Key schedule (HKDF-SHA256) deriving direction-separated handshake MAC keys, control-chain roots
  and the session identifier from the PSK, the transcript and the exporter.
- Control-channel hash ratchet `k(n+1) = HKDF(k(n))` advanced only after a frame authenticates.
- Per-frame key derivation mixing the X25519 shared secret with session id, direction, epoch,
  sequence, key id, algorithm and the sender's ephemeral public key.
- Three permitted AEADs behind one interface — AES-256-GCM, ChaCha20-Poly1305, AES-128-GCM — with
  per-frame algorithm rotation from the receiver's advertised set.
- Receiver-side one-time X25519 key pool: batched publication, watermarked replenishment, "one key,
  one frame" enforced structurally by removal on use, and unknown/already-consumed identifiers
  rejected.
- Low-order and all-zero public keys rejected; unauthenticated plaintext wiped on tag failure.
- Long-term server identity (X25519) generated on first start, stored at mode `0600`, refusing to
  load if group- or other-readable; SHA-256 fingerprint for logging and for client pinning
  (`server_identity_pin`).
- Fail-closed randomness: a single `OsRng`-based source, no fallback, unbiased uniform sampling.
- `zeroize`-based erasure of keys and buffers, with the limitations documented rather than hidden.

**Transport (`veilink-transport`)**

- TLS 1.3 via rustls with the `ring` provider; ALPN `h2` / `vlp/1`. The transport is selected by
  configuration and a mismatch is a clear failure rather than a silent downgrade.
- Self-signed certificate generated with SANs derived from the listen address, stored as
  `tls_cert.pem` / `tls_key.pem` with owner-only permissions on the key.
- A certificate verifier that performs structural checks and handshake signature verification but no
  PKI validation — safe only because authentication happens inside `VLP/1`; the argument and its
  residual risks are documented.
- Extraction of the TLS exporter and its use as the channel binding value.
- Optional HTTP/2 carrier: one long-lived `POST` with a streaming body and a `200` streaming
  response, with VLP/1 providing the real multiplexing; a second stream on the same connection is
  refused.

**Client (`veilink-client`)**

- HTTP/1.1 forward proxy on `127.0.0.1:7890` by default, covering absolute-form, origin-form and
  `CONNECT` requests, plus `Upgrade` (WebSocket) and chunked or streamed bodies.
- Byte-level handling: bounded head reads, request/response framing per RFC (`Content-Length`,
  chunked with trailers, EOF-delimited), hop-by-hop header removal, `Host` preservation/synthesis,
  and local answers for `Expect: 100-continue`.
- Raw byte splice after `CONNECT` and after `101 Switching Protocols`, preserving bytes that were
  already buffered with the request.
- Per-request routing: whitelist match → `PROXY` (through the encrypted tunnel), otherwise `DIRECT`
  (local TCP, system resolver). Whitelisted names are forwarded unresolved, so the local resolver
  never sees them.
- Fail-closed routing: a whitelisted request fails with `502` when the tunnel is unavailable; it is
  never served by a direct connection.
- Upstream connection reuse keyed by target and route, with poisoning when framing consumes the
  stream.
- Connection caps, idle timeouts and header-size limits; `arc-swap` hot reload of the whitelist and
  session rebuild on endpoint/key/transport change.
- Uplink supervisor with jittered exponential backoff (500 ms → 60 s), prompt fail-closed behaviour
  during outages, byte and frame counters, and no replay of in-flight requests across reconnects.

**Server (`veilink-server`)**

- Mandatory authentication: nothing is read from a peer before the `VLP/1` handshake completes, and
  failures close the connection without a diagnostic oracle.
- Remote IPv4-only DNS (A records) with a bounded TTL cache, per-query timeout, a small number of
  attempts, IDNA-normalised cache keys and no negative caching.
- Egress policy denying IANA special-use IPv4 ranges by default — loopback, RFC 1918, link-local
  (including cloud metadata `169.254.169.254`), carrier-grade NAT, benchmarking, documentation,
  multicast and reserved — with `0.0.0.0/8`, `224.0.0.0/4`, `240.0.0.0/4`, `255.255.255.255/32` and
  `192.0.0.0/24` always denied even in testing mode.
- Check-then-connect safety: the policy is applied to resolved addresses, the connection is made to
  a checked address, and a mixed public/private answer is refused entirely.
- Optional destination port allow-list, checked before resolution.
- Per-source-address connection rate limiting and a global connection cap; stream, header and
  timeout limits; server statistics reported periodically.

**Rules (`veilink-rules`)**

- Rule types `DOMAIN` (with whole-label `*` wildcards), `DOMAIN-SUFFIX` (label-boundary semantics),
  `IP`, `CIDR` and the bare catch-all `*`.
- Canonicalisation before matching: trim, one trailing root dot removed, lower-casing, IDNA
  A-labels, label-length and total-length bounds.
- OR semantics with first-match-wins, empty set meaning "everything DIRECT", duplicate detection on
  canonical identity, and hot-swappable rule sets via `ArcSwap`.
- Actionable, specific parse errors (for example "use CIDR for network ranges", "IPv6 target … is
  not supported by this release").

**Strict Privacy layer (`veilink-privacy`)**

- Fixed-bucket padding always on, wrapped in a resource budget that degrades to the smallest bucket
  instead of silently disabling padding.
- Send scheduler that coalesces queued frames into one write (up to 16 frames / 64 KiB) with a
  bounded, jittered pacing policy.
- Idle-only cover traffic: real `VLP/1` application frames carrying random bytes, sealed with the
  same per-frame cryptography, starting after 750 ms of idleness in bursts of up to 3 frames every
  1.5 s, capped at 40 bursts.
- Hard budgets for cover traffic (4 KiB/s and 256 MiB per session) and padding (4 MiB/s) on separate
  sliding windows, with partial grants and counters.

**Configuration and CLI (`veilink-config`, `veilink-cli`)**

- Two YAML schemas with `deny_unknown_fields` everywhere and two-phase validation that reports every
  problem at once.
- `veilink client`, `veilink server`, `veilink keygen` (Base64URL or hex, optional file output at
  `0600`, `--count`, `--quiet`) and `veilink check` (`--type auto|client|server`, `--verbose`).
- Text or JSON logging driven by `RUST_LOG` or `log.level`, with `log.log_domains: false` by default
  so target domains are printed as `<redacted>`.
- Configuration watcher observing the parent directory, validating before replacing, applying
  whitelist changes atomically and rebuilding the session when the endpoint, transport or key
  changes.

**Tests, benchmarks, CI and documentation**

- Unit tests in every crate, plus integration tests that drive real `curl` through a real proxy
  against real TCP and TLS origins: HTTP conformance, `CONNECT`, WebSocket upgrade, streaming and
  chunked bodies, concurrency, whitelist routing and fail-closed behaviour, end-to-end proxying over
  both transports, DNS-locality proof with a DNS stub, cryptographic round trips, replay and
  tampering resistance, forward-secrecy attack attempts, and recovery/reconnection.
- A shared test harness (HTTP/TLS test origins, a DNS stub, a curl driver, and real client/server
  runners) plus CLI tests for `keygen` and `check`.
- Criterion benchmarks for the three AEADs, X25519 key generation and agreement, the key schedule,
  complete frame seal/open through the session codec, the message codec, and the padding and
  cover-traffic overheads.
- GitHub Actions CI: `cargo fmt --check`, clippy with `-D warnings`, the full test suite, a release
  build, a five-target cross-compilation matrix, and a non-blocking `cargo audit` job.
- A release workflow triggered by `v*` tags that builds all five targets, packages
  `veilink-linux-x86_64.tar.gz`, `veilink-linux-aarch64.tar.gz`, `veilink-windows-x86_64.zip`,
  `veilink-macos-x86_64.tar.gz` and `veilink-macos-aarch64.tar.gz` (each containing the binary,
  `README.md`, `LICENSE` and `examples/`), generates `SHA256SUMS` and publishes a GitHub Release.
- Documentation: `README.md` / `README.en.md`, `SECURITY.md`, and `docs/architecture.md`,
  `docs/protocol.md`, `docs/cryptography.md`, `docs/privacy.md`, `docs/threat-model.md`,
  `docs/configuration.md`, `docs/deployment.md`, `docs/testing.md`.

### Security

- Authentication is mandatory and has no unauthenticated or downgrade path; failed handshakes are
  non-distinguishing and are counted.
- Frame integrity covers the entire 76-byte header as associated data; a frame cannot be relabelled,
  reordered, moved to another stream or session, or replayed.
- Application frames use a fresh one-time X25519 key pair per frame; the receiver's private half is
  removed and erased on use, so recorded frames cannot be decrypted after the fact by someone who
  later obtains the PSK or the server's long-term identity.
- The server cannot be used as a pivot into its own loopback, private network or cloud metadata
  service, including via DNS rebinding.
- Secret material is redacted from logs and `Debug` output, private key files are created with
  `0600`, and an insecure `identity.key` stops startup.
- Known limitations are documented rather than papered over: no IPv6, no UDP/QUIC, no graceful PSK
  rotation or per-client identity/quotas, scheduler *pacing* not currently effective, cover traffic
  limited to idle periods, and no resistance to metadata analysis, website fingerprinting, endpoint compromise or
  quantum cryptanalysis. Veilink makes **no** claim of zero detection rate, absolute anonymity or
  untraceability.

[Unreleased]: https://github.com/fb0sh/veilink/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/fb0sh/veilink/releases/tag/v0.1.0
