# 密码学设计

本文档说明 Veilink 使用了哪些算法、密钥如何派生与销毁、以及安全性主张的**确切边界**。
所有内容都可在代码中核对：

- [`crates/veilink-crypto/src/`](../crates/veilink-crypto/src/)：算法封装与密钥调度
- [`crates/veilink-transport/src/tls.rs`](../crates/veilink-transport/src/tls.rs)：TLS 1.3 与 channel binding
- [`crates/veilink-protocol/src/codec.rs`](../crates/veilink-protocol/src/codec.rs)：每帧加解密与填充

> 原则：本库**不发明任何密码学原语**。所有运算交给成熟实现：AES-GCM、ChaCha20-Poly1305、
> HKDF、SHA-256、HMAC 来自 RustCrypto，X25519 来自 `dalek`。本库负责的是**组合**：存在哪些密钥、
> 它们绑定到什么、何时销毁、以及某一把密钥泄露后攻击者能得到什么。

---

## 1. 使用的算法

| 用途 | 算法 | 参数 | 实现 |
|------|------|------|------|
| 帧加密（AEAD） | AES-256-GCM | 密钥 32 B，nonce 12 B，tag 16 B | `aes-gcm` |
| 帧加密（AEAD） | ChaCha20-Poly1305 | 密钥 32 B，nonce 12 B，tag 16 B | `chacha20poly1305` |
| 帧加密（AEAD） | AES-128-GCM | 密钥 16 B，nonce 12 B，tag 16 B | `aes-gcm` |
| 密钥协商 | X25519 | 32 B 公钥 / 32 B 共享秘密 | `x25519-dalek` |
| 密钥派生 | HKDF-SHA256 | 输出 32 或 44 B | `hkdf` + `sha2` |
| 握手确认 MAC | HMAC-SHA256 | 输出 32 B | `hmac` + `sha2` |
| 转录哈希、指纹 | SHA-256 | 32 B | `sha2` |
| 常量时间比较 | `subtle::ConstantTimeEq` | — | `subtle` |
| 秘密擦除 | `zeroize` | — | `zeroize` |
| 随机数 | 操作系统 CSPRNG（`getrandom` / `OsRng`） | — | `rand_core` + `getrandom` |
| 外层 TLS | TLS 1.3（rustls，`ring` provider） | — | `rustls` |

算法标识（写在线路头部 `algorithm` 字节中）：

| id | 算法 | 密钥长度 | 协商掩码位 |
|----|------|---------|-----------|
| 1 | AES-256-GCM | 32 | `0x01` |
| 2 | ChaCha20-Poly1305 | 32 | `0x02` |
| 3 | AES-128-GCM | 16 | `0x04` |

允许列表是固定的：`AlgorithmId::from_u8` 只接受 1/2/3，其它值返回 `UnsupportedAlgorithm`。
协商掩码中的未定义位与空掩码同样被拒绝。

### 1.1 随机数

`crates/veilink-crypto/src/rng.rs` 是代码库中**唯一**接触 CSPRNG 的地方。
`OsRng::try_fill_bytes` 失败会返回 `RngError` 而不是 panic，调用方必须向上传播并中止操作；
不存在"退化到较弱随机源"的回退路径。`random_below` 使用拒绝采样（而非取模）以避免偏置。

---

## 2. 密钥层级：从 PSK 到每帧密钥

```text
                 操作者配置的 PSK（≥ 256 bit，hex 或 Base64URL）
                              │
              ┌───────────────┴────────────────────────────┐
              │  HKDF-SHA256(salt = transcript_hash ||      │
              │              exporter || "VLP/1",           │
              │              ikm  = PSK)                    │
              └───────────────┬────────────────────────────┘
                              │
    ┌──────────────┬──────────┴───────────┬──────────────────┬─────────────────┐
    │              │                      │                  │                 │
 auth_c2s       auth_s2c         control_root_c2s   control_root_s2c   session_id (§)
 (HMAC 密钥)    (HMAC 密钥)      (控制链根)          (控制链根)          (8 字节)
    │              │                      │                  │
 握手 MAC       握手 MAC            棘轮 k(0)         棘轮 k(0)
                                        │                  │
                              k(n+1)=HKDF(k(n),"vlp/1 control ratchet"||dir)
                                        │
                          HKDF(k(n),"vlp/1 control frame v1",44B)
                                        │
                              ChaCha20-Poly1305 密钥 + nonce
                              （epoch 0 控制帧，每帧一步）

  应用帧（epoch 1）完全独立于上面的控制链：
     接收方一次性 X25519 私钥  ×  发送方每帧 X25519 临时私钥
                        │
                   X25519 shared secret
                        │
      HKDF-SHA256(salt = transcript_hash || session_id_be,
                  ikm  = shared secret,
                  info = "vlp/1 frame key v1" || direction || epoch ||
                         sequence || key_id || algorithm || sender_public)
                        │
              每帧唯一的 AEAD 密钥 + nonce（用后即弃）
```

(§) `session_id` 由 HKDF 从 PSK + transcript + exporter 派生，**从不提前传输**。

要点：

- **PSK 从不直接作为密码密钥使用**，也不会被直接用于 AEAD。所有用途都经过带独立、带版本的
  `info` 标签的 HKDF。
- **握手 MAC 只依赖 PSK**（以及转录哈希与 exporter），因此它证明"持有 PSK"。
- **控制链根依赖 PSK + exporter**，所以中继两条不同 TLS 会话会产生不同的密钥。
- **每帧密钥只依赖一次性 X25519 交换**，不依赖 PSK、不依赖控制链、不依赖长期身份密钥。这是前向
  保密的结构性来源。

派生标签常量（[`kdf.rs`](../crates/veilink-crypto/src/kdf.rs)）：

| 常量 | 值 |
|------|----|
| `PROTOCOL_LABEL` | `b"VLP/1"` |
| `EXPORTER_LABEL` | `b"EXPORTER-Veilink-VLP1"` |
| `HASH_LEN` | 32 |
| 握手确认 MAC 前缀 | `"VLP/1" || " confirm " || direction_byte` |
| 控制帧材料 | `b"vlp/1 control frame v1"` |
| 控制棘轮 | `b"vlp/1 control ratchet" || direction_byte` |
| 每帧材料 | `b"vlp/1 frame key v1" || direction || epoch || sequence || key_id || algorithm || sender_public` |
| 握手密钥 | `vlp/1 handshake auth c2s` / `vlp/1 handshake auth s2c` / `vlp/1 control root c2s` / `vlp/1 control root s2c` / `vlp/1 session identifier` |

因为会话 ID、方向、epoch、序号、key id、算法与发送方临时公钥都被绑定进 `info`，而它们又都在
AEAD 的 AAD（76 字节头部）中，所以帧无法被改标签、重排、换密钥或重放到别的会话而仍然通过认证。

---

## 3. 自签名证书为何是安全的：channel binding

**问题**：操作者只配置了两件事——服务器地址与一个 PSK。没有 CA、没有域名、没有 pinning 基础设施。
服务端只能出示自签名证书，而标准 TLS 客户端必须拒绝它。

**Veilink 不做的事**：它**没有**关闭证书校验。一个"关闭校验的 TLS"就是未认证信道，
任何能劫持 TCP 的人都能冒充服务端，加密也就保护不了任何东西。Veilink 的
`PskBoundVerifier` 是一个危险的自定义校验器，它**只做结构检查**（证书能解析、能取出用于握手
签名验证的公钥），不做 PKI 校验——但它**仅在 VLP/1 握手存在时才是安全的**。

**真正让连接安全的机制**：

1. 双方交换 `CLIENT_HELLO` / `SERVER_HELLO`，构造转录哈希；
2. 双方从**本次 TLS 会话**导出 32 字节 exporter（标签 `EXPORTER-Veilink-VLP1`）；
3. 双方发送 `HMAC(k_auth, transcript_hash || exporter)`，其中 `k_auth` 来自 PSK。

于是：

- **中继 / 主动 MITM 不可能**：攻击者必须终止客户端的 TLS 会话并另开一条到真实服务端的 TLS
  会话。两条会话的 exporter 不同；真实服务端产生的确认 MAC 覆盖的是**它自己那条会话**的
  exporter，客户端那条会话算不出同样的值，因此验证失败。
- **无 PSK 的攻击者无法产生任何 MAC**。
- **重放已录制的握手不可能**：录制内容携带的是当时那条 TLS 会话的 exporter，新的 TLS 会话
  不会产生该值。
- **无法降级**：不存在"未认证模式"，任何失败都会直接关闭连接。

**TLS exporter 的性质**：它由 TLS 主密钥派生，每个 TLS 会话唯一；同一对端之间两次连接的
exporter 不同（`connector.rs` 的测试 `each_session_has_a_different_exporter` 覆盖了这一点）。

**残余风险（明确说明）**：

- 证书的**签名**仍会对自己的公钥验证（`verify_tls13_signature`），因此对端必须证明它持有其出示
  的公钥。这阻止了"任意字节都算证书"的退化路径，但**不提供身份**。
- 如果客户端 pin 了服务端身份指纹（`fingerprint_matches_pin`，比较的是 `SERVER_HELLO` 中被
  transcript/MAC 覆盖的长期身份公钥），则可以检测出"共享同一 PSK 的另一台服务器替换了原服务器"。
  在客户端 uplink 中，`UplinkConfig::expected_identity` 目前**总是 `None`**（见第 7 节），
  也就是说 pinning 能力已实现但**未接入配置**。

---

## 4. 密钥生命周期

| 密钥 | 生成 | 使用 | 销毁 |
|------|------|------|------|
| PSK | `veilink keygen`，或操作者提供 | 仅作为 HKDF `ikm` | 存在于 `Zeroizing<Vec<u8>>`，进程退出/结构 drop 时擦除；不写日志、`Debug`/`Display` 均为 `<redacted>` |
| `session_id` | 握手派生 | 帧头部标识、帧密钥 salt | 非秘密 |
| `auth_c2s` / `auth_s2c` | 握手派生 | 各一次确认 MAC | `DerivedKey` drop 时 `zeroize` |
| `control_root_*` | 握手派生 | 初始化控制链 | `DerivedKey` drop 时擦除 |
| 控制链 `k(n)` | 棘轮步进 | 保护当前控制帧 | 每次步进替换旧值；旧值被 drop 擦除 |
| 发送方临时密钥 | 每帧 `SenderEphemeral::generate()` | 一次 DH | drop 擦除 |
| 接收方一次性密钥 | `KeyPool::publish` 批量生成 | 一次 DH | `KeyPool::take` 移除后 drop 擦除；会话结束时 `clear()` |
| 每帧 AEAD 密钥/nonce | 每帧 `derive_frame_material` | 一次 seal 或 open | `AeadKey` 持有 `Zeroizing<Vec<u8>>`，drop 擦除 |
| 长期身份私钥 | 首次启动生成，`identity.key`（0600） | 写入 `SERVER_HELLO` 的公钥、生成 TLS 证书 | 持久保存，不参与帧加密 |
| TLS 私钥 | 首次启动生成，`tls_key.pem`（0600） | TLS 1.3 握手 | 持久保存 |

其它擦除细节：

- `AeadKey::open_in_place` 在 tag 校验失败时会**先擦除再报错**，调用者不可能观察到未认证的明文。
- `identity.key` 与 `tls_key.pem` 在加载时检查权限：身份文件对 group/other 可读会直接拒绝
  （`InsecurePermissions`，提示 `chmod 600`）；TLS 私钥可读只记录警告。
- `Psk::parse` 拒绝低熵输入（单字节重复、全零、≤8 字节周期重复、不同字节值过少），但这只是防
  copy-paste 事故的健全性检查，**不是熵估计器**。
- 标识符如 key id 从 1 递增且会话内不复用（回绕时跳过存活 id）。

---

## 5. 前向保密：保证什么、不保证什么

### 5.1 保证

对**应用帧**（epoch 1）：

- 每帧的密钥来自一次全新的 X25519 交换，其中接收方的私钥是**一次性**的：`KeyPool::take` 取出后
  立即从池中移除并擦除。
- 因此**在私钥被实际擦除之后**，任何人事后都无法重算该帧的密钥——包括后来拿到 PSK 的人，也包括
  后来拿到服务端长期身份私钥的人。
- 已有测试覆盖这一点（`crates/veilink-crypto/src/key_pool.rs` 与
  `crates/veilink-protocol/src/codec.rs` 中的重放/跨会话测试）。

控制链（epoch 0）也具有单向性：`k(n+1) = HKDF(k(n))`，知道 `k(n)` 无法反推 `k(n-1)`；每步密钥
用后即弃。

### 5.2 不保证（必须明确）

**软件擦除是尽力而为。** `zeroize` 只能覆盖它控制的内存。以下情形可以在擦除发生**之前**捕获秘密：

- **内存快照 / 崩溃转储 / 调试器附着**：进程内存被复制时，尚未擦除的一次性私钥、PSK、控制链
  状态都可能在快照中。
- **交换分区（swap）与休眠镜像（hibernation）**：被换出到磁盘的页不会因为进程内 `zeroize`
  而消失。操作系统可能把含有密钥的页写进 swap 或休眠文件。
- **被攻陷的主机 / hypervisor**：如果攻击者能在同一台机器上以更高权限运行（root、hypervisor、
  DMA 设备），前向保密不成立——它可以直接读取进程内存。
- **核心转储（core dump）**：默认配置下可能把内存写入磁盘。
- **编译器优化**：理论上优化器可能消除"看起来无用"的擦除操作；`zeroize` 使用内存屏障与
  `volatile` 写入来抑制这一点，但这是库层面的对抗，不是形式化保证。

**结论**：前向保密只在"私钥已被真正擦除，且攻击者没有在擦除前获得内存访问"的前提下成立。
它保护的是**事后**拿到长期密钥（或拿到已录制密文）的攻击者，而不是能实时读取宿主机的攻击者。
用户应自行采取全盘加密、禁用休眠、限制 swap、保护主机等运维措施。

### 5.3 关于已录制流量

- 攻击者录下全部密文后，**仅仅**获得 PSK 或长期身份私钥，**不能**解密已经完成的应用帧。
- 但如果攻击者在录制时就能访问内存（见 5.2），或者会话当时仍存活且其一次性私钥尚未被消费，
  则该帧可能被解密。
- 控制帧（`KEY_OFFER`/`KEY_ACK`/`PING`/`PONG`/`GOAWAY`）的密钥来自 PSK 派生的控制链；攻击者若
  同时拿到 PSK **和** 该会话的 TLS exporter，理论上可以重算控制链并解密控制帧。
  但 exporter 不可从录制流量导出（它来自 TLS 主密钥），且控制帧只含密钥池元数据，不含用户数据。

---

## 6. 长期身份或 PSK 泄露

### 6.1 PSK 泄露

**能做什么**：

- 冒充服务端，对**未来**的会话进行中间人（因为客户端只用 PSK 认证服务端）。
- 冒充客户端连接真实服务端，并使用该服务端的出口（在服务端 egress 策略允许范围内）。
- 与"该会话的 TLS exporter"结合时，可解密该会话的控制帧。

**不能做什么**：

- 不能解密**已录制**的应用帧——那些密钥来自已擦除的一次性交换。
- 不能在没有实时内存访问的情况下恢复过去的用户数据。
- 不能绕过服务端的 egress 策略（私网/元数据地址仍然被拒）。
- 不能在没有 exporter 的情况下重放旧握手（exporter 逐会话唯一）。

因此 PSK 泄露是**严重的认证事件**，但不是"历史流量全部泄露"。处置方式是立即轮换 PSK（客户端与
服务端同时更换），并视为"该 VPS 在泄露窗口内可能被冒充"。

### 6.2 长期身份私钥泄露（服务端 `identity.key`）

`IdentitySecret` **不用于**任何帧加密，也**不派生**任何会话密钥。它只用于：

- 其公钥被写入 `SERVER_HELLO`，并被 transcript / PSK 绑定的 MAC 覆盖，因此客户端知道"这是同一个
  服务端实例"；
- 其公钥被嵌入自签名 TLS 证书，供操作者把证书与日志中的指纹对应起来；
- 客户端可 pin 该指纹以检测服务端被替换（能力已实现，客户端配置尚未接入，见第 7 节）。

**能做什么**：攻击者可以伪造一个"身份相同"的 TLS 证书；如果它同时拥有 PSK，就能完整冒充服务端；
如果只有身份私钥而没有 PSK，它仍会在 VLP/1 握手阶段失败。

**不能做什么**：**不能解密任何已录制或未来的用户数据**。它不参与帧密钥派生。

### 6.3 前向保密与长期密钥的关系

因为每帧密钥与 PSK、长期身份、控制链**完全解耦**，所以：

- 拿到长期密钥（PSK / identity）→ 影响**未来会话的认证**，不影响**过去帧的机密性**；
- 拿到某帧的一次性私钥 → 只影响**那一帧**（且该私钥在该帧被处理后立即被销毁）。

---

## 7. 其它已实现但尚未接入的密码学能力

以下是**代码中已实现、但当前运行时未启用**的能力，不应被当作已生效的保护：

- **服务端身份指纹 pinning**：`veilink_crypto::fingerprint_matches_pin` /
  `parse_fingerprint_pin` 已实现并有测试，`UplinkConfig` 也有 `expected_identity` 字段，但
  `UplinkConfig::from_settings` 把它硬编码为 `None`，`ClientConfig` 中也没有对应的 YAML 字段。
  也就是说：**当前无法通过配置启用 pinning**。
- 服务端会打印身份指纹（`identity` 与 `short` 两个字段），操作者可以据此人工核对，但客户端不会
  自动校验。

---

## 8. 未实现 / 当前限制

- 没有抗量子（post-quantum）密钥协商：X25519 面对未来的量子计算机不提供机密性。
- 没有对 PSK 的密钥派生函数（如 Argon2）：PSK 必须是高熵随机值，而非口令；`Psk::parse` 会拒绝
  看起来像口令的输入。
- 没有硬件安全模块 / TPM 支持：身份私钥与 TLS 私钥以文件形式保存在 `state_dir`。
- 没有内存锁定（`mlock`）：秘密可能被换出到 swap。
- 没有对 exporter 或控制链做周期性 rekey；控制链随每帧步进，但没有"重新握手"机制。
- 没有帧级密钥的显式 `mlock`/`memfd_secret` 等隔离手段。
