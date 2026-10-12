# Security Policy

Veilink is a privacy-focused encrypted HTTP/HTTPS proxy. It protects traffic in transit; it does not
protect endpoints. This document states which security properties are in scope, how to report a
problem, and which guarantees Veilink deliberately does **not** make.

---

## Supported versions

Veilink is pre-1.0. Only the latest released version is supported with security fixes; there are no
LTS branches and no backports.

| Version | Supported |
|---------|-----------|
| 0.1.x (latest) | ✅ |
| older | ❌ |

Security fixes are released as a new patch version and documented in
[`CHANGELOG.md`](CHANGELOG.md). Configuration formats and the `VLP/1` wire protocol are versioned
separately: the frame version byte is `0x56` and `PROTOCOL_VERSION` is `1`; a change to either is a
breaking change and will be called out in the changelog.

---

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

1. Prefer GitHub's private vulnerability reporting:
   *Security* → *Report a vulnerability* on the repository's **Security** tab.
   This creates a private advisory visible only to the maintainers.
2. If that is unavailable, contact the maintainers privately and include `SECURITY` in the subject.

Please include, as far as you can:

- the affected version (`veilink --version`) and platform;
- the affected component (crate, module, or configuration field);
- a description of the impact, and which security property from the list below it breaks;
- a reproduction: configuration snippets, commands, and any proof-of-concept;
- whether the finding requires a compromised client host, a malicious server operator, or an
  already-leaked pre-shared key.

There is no bug bounty. What you can expect:

| Stage | Target |
|-------|--------|
| Acknowledgement | within 7 days |
| Initial assessment (in scope / out of scope, severity) | within 14 days |
| Fix or documented mitigation | best effort, aiming for 90 days for high-severity findings |
| Credit in the changelog / advisory | on request |

If a finding is out of scope we will explain why, referencing this document. Coordinated disclosure
is appreciated: we will agree a disclosure date with you and publish an advisory with the fix.

---

## In-scope security properties

A report is in scope if it breaks one of these:

1. **Content confidentiality.** An attacker who observes the wire (passive or active) can read
   proxied HTTP request/response bytes, target host names, target ports, stream identifiers, or
   message contents.
2. **Frame integrity.** A frame can be modified, re-labelled, re-ordered, moved to another stream,
   moved to another session, or replayed without the receiver rejecting it.
3. **Peer authentication.** A peer without the pre-shared key can complete the `VLP/1` handshake, or
   a relay / man-in-the-middle between two different TLS sessions can complete it on both legs
   (that is: the TLS-exporter channel binding can be bypassed).
4. **Forward secrecy of recorded frames.** A recorded application frame can be decrypted after the
   fact using only the pre-shared key, only the server's long-term identity key, or only data
   recorded from the wire (i.e. a one-time receiver key can be reused, recovered, or recomputed).
5. **Key hygiene.** Secret material (PSK, one-time private keys, frame keys, the server identity)
   is logged, rendered by `Debug`/`Display`, exposed in error messages, written with unsafe file
   permissions, or left in memory after an authentication failure.
6. **Egress policy bypass.** An authenticated client can reach a destination the policy should
   deny — loopback, RFC 1918, link-local (including cloud metadata `169.254.169.254`), carrier-grade
   NAT, benchmarking/documentation/multicast/reserved space — including via DNS rebinding or a
   check-then-connect race.
7. **Fail-closed routing.** A request that matches the whitelist is served by a direct connection
   instead of failing, when the secure tunnel is unavailable.
8. **Resource bounds.** A peer can force unbounded memory growth, unbounded key generation, an
   unbounded delay, or an unbounded allocation by declaring a length or count that is never
   validated before use.
9. **Memory safety.** Any `unsafe` code (the workspace forbids it in every crate), panic reachable
   from network input, or arithmetic overflow that affects framing or key handling.

---

## Out-of-scope properties

These are known, documented limitations rather than vulnerabilities. Reports about them will be
closed with a pointer here (see also [`docs/threat-model.md`](docs/threat-model.md) and
[`docs/privacy.md`](docs/privacy.md)).

1. **Metadata and traffic analysis.** The server's IP address and port, the TLS handshake, connection
   timing, frame counts, bucket-sized lengths, direction, sequence numbers and the fact that Veilink
   is in use are all visible by design. Veilink makes **no** claim of zero detection rate, absolute
   anonymity, unlinkability or resistance to website fingerprinting.
2. **Endpoint compromise.** Malware on the client host, a rooted client, or a compromised server
   host can read process memory, keys and plaintext. Veilink protects traffic in transit, not
   endpoints. Software key erasure does not defend against memory snapshots, swap, hibernation
   images or a hypervisor.
3. **A malicious server operator.** The server is the egress: it sees destination host names and
   ports, and the plaintext of proxied non-TLS traffic, and it can modify or drop that traffic.
   That is inherent to using a proxy you operate.
4. **Denial of service by volume.** Traffic flooding, bandwidth exhaustion, and resource exhaustion
   that stays within the documented limits are not treated as vulnerabilities. Bypassing a *specific
   documented bound* (property 8 above) is in scope.
5. **Self-signed certificate.** The server presents a self-signed certificate and the client does not
   validate it against a PKI. Authentication comes from the pre-shared key bound to the live TLS
   session. "The certificate is not CA-signed" is by design, not a bug.
6. **Attacks that require the pre-shared key**, beyond what the key is documented to grant: an
   attacker holding the PSK can impersonate the server for future sessions and can use the server as
   an egress. Reports that only demonstrate this are out of scope. A way for a PSK holder to decrypt
   *recorded* frames or to exceed the documented egress/authentication consequences **is** in scope.
7. **Missing or non-configurable features.** IPv6 egress, UDP/QUIC relay, per-client quotas and
   revocation, and graceful PSK rotation are not implemented. The privacy mechanisms (padding
   buckets and their budgets, the send scheduler, cover traffic) are implemented and always on, but
   their parameters are internal constants with no YAML field; "I cannot tune the cover-traffic
   rate" is a feature request, not a vulnerability. So is the fact that scheduler *pacing* does not
   currently take effect (documented in `docs/privacy.md`), unless you can show it breaks a
   documented bound.
8. **Dependency advisories with no reachable path.** Please still report them, but a `cargo audit`
   finding in an unreachable code path is a maintenance item, not a vulnerability in Veilink.
9. **DNS leakage outside the proxy.** Browser/OS DNS pre-resolution, DoH/DoT, applications that
   ignore the proxy, and direct connections cannot be prevented by an explicit HTTP proxy.

---

## Hardening checklist for operators

Not vulnerabilities, but the operational measures that the security properties above assume:

- Put an encrypted container or full-disk encryption under `state_dir`; `identity.key` and
  `tls_key.pem` are private keys.
- Keep `identity.key` at mode `0600` (the server refuses to start otherwise) and back it up
  securely if you rely on a stable server identity.
- Disable swap or use encrypted swap, and disable hibernation: software key erasure cannot reach
  data that has been paged out.
- Bind the client proxy to `127.0.0.1` (the default) and never expose it to a network.
- Run the server as an unprivileged user with only `CAP_NET_BIND_SERVICE`; see
  [`docs/deployment.md`](docs/deployment.md) for a systemd unit.
- Keep `allow_private_targets: false` in production; it exists for local integration testing.
- Consider setting `allowed_ports` so an authenticated client cannot turn your VPS into a general
  purpose relay.
- Leave `log.log_domains: false` unless you have a specific need and have accepted the privacy cost.
- Rotate the pre-shared key if it may have been exposed; both sides must be updated together.

---

## 中文摘要

- **支持版本**：仅最新发布版本（当前 `0.1.x`），pre-1.0 无 LTS、无向后移植。
- **报告方式**：请使用 GitHub 的**私密漏洞报告**（仓库 Security 标签页），不要开公开 issue。
  请在报告中说明受影响版本、组件、被破坏的安全属性、复现步骤，以及是否需要已泄露的 PSK
  或已失陷的主机。
- **时间线**（尽力而为，无赏金）：7 天内确认、14 天内给出范围判断、高危目标 90 天内修复。
- **在范围内**：内容机密性、帧完整性、对端认证与 TLS channel binding、已录制帧的前向保密、
  密钥卫生（日志/权限/内存）、egress 策略绕过（含 DNS rebinding）、fail-closed 路由、
  资源边界、内存安全。
- **不在范围内**：元数据与流量分析（**不声称零检测率、绝对匿名或不可追踪**）、端点失陷、
  恶意服务端运营者、纯流量型 DoS、自签名证书本身、仅证明"持有 PSK 可冒充"的报告、
  尚未实现或不可配置的功能（IPv6、UDP、按客户端配额与吊销、隐私参数不可调；调度器节奏整形当前
  不生效，除非能证明它破坏了文档化的边界）、不可达的依赖告警、
  代理之外的 DNS 泄露（浏览器预解析 / DoH / 绕过代理的应用）。
