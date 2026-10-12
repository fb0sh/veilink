# VLP/1 协议规范

本文档描述 Veilink 的第一版线上协议 **VLP/1**（Veilink Link Protocol, version 1）。所有数值、
偏移量和编码顺序都直接来自代码，来源文件在每一节末尾列出。

- 帧与头部：[`crates/veilink-protocol/src/frame.rs`](../crates/veilink-protocol/src/frame.rs)
- 消息编码：[`crates/veilink-protocol/src/message.rs`](../crates/veilink-protocol/src/message.rs)
- 会话编解码与填充：[`crates/veilink-protocol/src/codec.rs`](../crates/veilink-protocol/src/codec.rs)
- 多路复用、流状态与流控：[`crates/veilink-protocol/src/session.rs`](../crates/veilink-protocol/src/session.rs)
- 握手与密钥调度：[`crates/veilink-crypto/src/handshake.rs`](../crates/veilink-crypto/src/handshake.rs)、[`crates/veilink-crypto/src/kdf.rs`](../crates/veilink-crypto/src/kdf.rs)

> 说明：本文档只描述**当前代码实际实现**的行为。任何尚未实现的部分都在
> [未实现 / 当前限制](#未实现--当前限制) 中显式列出，不做推测性描述。

---

## 1. 概述

VLP/1 运行在一条已经建立的、可靠且有序的双向字节流之上。这条字节流由传输层提供：

| 传输 | 固定 ALPN | 字节流形态 |
|------|-----------|-----------|
| `tls` | `vlp/1` | TLS 1.3 之上直接是 VLP/1 帧流 |
| `h2`（默认） | `h2` | TLS 1.3 + HTTP/2；一个 `POST` 请求/响应 body 对承载 VLP/1 帧流 |

两种传输承载**完全相同**的 VLP/1 帧与密码学；区别仅在外层封装。

传输由配置选择，并且**每种传输把自己的 ALPN 固定为唯一值**：客户端用
`client_config_for(Some(ALPN))`、服务端用 `acceptor_for(identity, ALPN)`，握手后用
`check_alpn(negotiated, Some(required))` 校验。因此客户端与服务端的 `transport` 不一致会得到一个
**明确的握手失败**，而不是两端用不同分帧方式各说各话。ALPN 缺失时，若已指定期望协议则按该协议处理
（`check_alpn(None, Some(wanted))`），若没有任何期望则按裸 `vlp/1` 处理；协商成其它值（例如
`http/1.1`）一律拒绝（`UnexpectedAlpn`）。

协议分两层：

1. **帧层**（frame）：固定头部 + 密文，负责长度界定、方向、序号、算法标识与每帧密钥引用。
2. **消息层**（message）：帧内明文中的类型化消息，负责握手、密钥池维护、流生命周期与数据。

协议在一次连接内提供多路复用：多个逻辑流（stream）共享一条已认证连接。

---

## 2. 帧格式

每个 VLP/1 帧的前两个字节始终明文可见：

```text
offset  size  field
0       1     frame version = 0x56 ('V')
1       1     frame type: 0 = handshake (cleartext), 1 = authenticated
```

`FRAME_VERSION = 0x56`，`FRAME_TYPE_HANDSHAKE = 0`，`FRAME_TYPE_AUTHENTICATED = 1`。
`frame type` 为其它值一律拒绝（`FrameError::BadFrameType`）。

### 2.1 handshake 帧（明文）

握手帧只能在握手完成之前出现：

```text
offset  size  field
0       1     frame version = 0x56
1       1     frame type = 0
2       2     message length (u16, big endian)
4       N     message bytes
```

- `N ≤ MAX_HANDSHAKE_MESSAGE = 8192`；读侧在分配前校验长度，超限即拒绝。
- 握手完成后收到明文帧是协议错误（`FrameError::CleartextAfterHandshake`），会话立即关闭。

### 2.2 authenticated 帧（76 字节认证头）

```text
offset  size  field
0       1     frame version = 0x56
1       1     frame type = 1
2       8     session_id          (u64, big endian)
10      4     epoch               (u32, big endian)
14      1     direction: 0 = client→server, 1 = server→client
15      8     sequence            (u64, big endian)
23      1     algorithm id
24      4     key id              (u32, big endian; 控制帧为 0)
28      4     ciphertext length   (u32, big endian, 含 16 字节 tag)
32      32    sender ephemeral X25519 public key (控制帧全为 0)
64      12    nonce
76      N     ciphertext || tag
```

- `AUTHENTICATED_HEADER_LEN = 76`。
- **AEAD associated data (AAD) 就是这 76 字节头部本身**（`FrameHeader::associated_data()` 返回
  `encode()`）。头部字段全部明文传输，但任何一个字节被改动都会导致 tag 校验失败。
- `ciphertext_len` 取值必须落在 `[16, MAX_CIPHERTEXT]`，其中
  `MAX_CIPHERTEXT = MAX_PAYLOAD + MAX_PADDING + 16 = 65536 + 4096 + 16 = 69648`。
  读侧**先校验长度再从该值分配**，因此对端无法用伪造长度造成无界内存分配。
- `direction` 只能是 0 或 1，其它值拒绝。
- 帧总长 = `76 + ciphertext_len`。

### 2.3 明文内部结构（填充）

AEAD 明文（即 tag 覆盖的明文）布局为：

```text
u16 real length (big endian) | message bytes | padding
```

- 明文总长度由填充策略取整到"桶"（bucket），而不是等于消息长度。
- 协议层默认桶集合（`BucketedPadding`）：`512, 1024, 2048, 4096, 8192` 字节；超过 8192 后按 8192
  的整数倍向上取整，上限 `MAX_PAYLOAD = 65536`。
- 运行时的策略是 `veilink-privacy` 的 `BudgetedPadding`：它先取标准桶，再把填充开销提交给资源预算。
  预算饱和时会**降级到最小桶**（`min(512, MAX_PAYLOAD)` 与 `message_len + 2` 的较大者），而不会
  停止填充。因此线上明文长度仍是一个桶值，只是可能不是"最近的"那个桶。
- 填充字节来自操作系统 CSPRNG；仅当 CSPRNG 失败时退化为 0 填充（此时长度不变，只削弱该帧的
  长度隐藏效果）。
- 接收方**不信任**长度前缀：`declared + 2 > padded.len()` 时为协议错误
  （`CodecError::BadLengthPrefix`），不会发生越界切片。
- 单帧消息上限：`max_message_size() = MAX_PAYLOAD - 2 = 65534` 字节。
- 应用层 `STREAM_DATA` 的净荷进一步被限制为 `MAX_STREAM_DATA = 16384` 字节。

---

## 3. 握手

握手在明文 handshake 帧中完成，不加密；其目的只有一个：在读取任何代理请求之前，确认对方持有
PSK，并且确实是与本 TLS 会话通信（而非中继）。

### 3.1 消息格式

`CLIENT_HELLO`（长度 `CLIENT_HELLO_LEN = 36`）：

```text
offset  size  field
0       1     version = 1
1       32    client_random
33      1     recv_algorithm_mask
34      2     reserved (必须为 0)
```

`SERVER_HELLO`（长度 `SERVER_HELLO_LEN = 70`）：

```text
offset  size  field
0       1     version = 1
1       32    server_random
33      1     recv_algorithm_mask
34      2     reserved (必须为 0)
36      2     key_pool_hint (u16, big endian)
38      32    server long-term identity public key
```

`AUTH_CONFIRM`：定长 `AUTH_CONFIRM_LEN = HASH_LEN = 32` 字节，内容为 HMAC-SHA256（见 3.3）。

`PROTOCOL_VERSION = 1`。双方都必须等于该值，否则 `CryptoError::Handshake`。
`client_random` / `server_random` 不得为全 0，且 `server_random != client_random`；
保留字段必须为 0；`identity` 不得为全 0。

### 3.2 交换顺序

```text
client                                          server
  │ CLIENT_HELLO { version, client_random,        │
  │                recv_algorithm_mask }          │
  ├──────────────────────────────────────────────►│  absorb(CLIENT_HELLO)
  │                                               │  生成 SERVER_HELLO
  │ SERVER_HELLO { version, server_random,        │
  │                recv_algorithm_mask,           │
  │                key_pool_hint, identity }      │
  │◄──────────────────────────────────────────────┤  absorb(SERVER_HELLO)
  │ absorb(SERVER_HELLO)                          │
  │ AUTH_CONFIRM { MAC(k_auth_c2s, …) }           │
  ├──────────────────────────────────────────────►│  先验证客户端
  │ AUTH_CONFIRM { MAC(k_auth_s2c, …) }           │  再回复
  │◄──────────────────────────────────────────────┤
  │ 验证                                          │
```

- 服务端在**验证客户端 AUTH_CONFIRM 之后**才发送自己的 AUTH_CONFIRM，因此没有 PSK 的攻击者
  得不到任何额外信息。
- 任一步失败都会关闭连接，没有"未认证模式"或降级路径。
- 握手受 `SessionConfig::handshake_timeout` 限制（默认 10 秒）。

### 3.3 转录哈希与确认 MAC

**转录哈希（transcript hash）**：`Transcript` 是一个 SHA-256 计算器，初始化时先吸收协议标签
`PROTOCOL_LABEL = b"VLP/1"`，随后每条握手消息以 `u32 big-endian 长度 || 消息字节`
（`absorb_prefixed`）依次吸收。双方对 `CLIENT_HELLO || SERVER_HELLO` 得到相同哈希。

**TLS exporter**：使用 rustls 的 `export_keying_material`，标签
`EXPORTER_LABEL = b"EXPORTER-Veilink-VLP1"`，上下文为空，输出 32 字节。它由 TLS 主密钥派生，
因此每个 TLS 会话都不同。

**会话密钥**：`derive_handshake_keys(psk, transcript_hash, exporter, c2s_algorithms, s2c_algorithms)`
以 HKDF-SHA256 计算，`salt = transcript_hash || exporter || "VLP/1"`，`ikm = PSK`：

| 输出 | info 标签 |
|------|-----------|
| `auth_c2s` | `vlp/1 handshake auth c2s` |
| `auth_s2c` | `vlp/1 handshake auth s2c` |
| `control_root_c2s` | `vlp/1 control root c2s` |
| `control_root_s2c` | `vlp/1 control root s2c` |
| `session_id` 材料 | `vlp/1 session identifier` |

`session_id` 取"session identifier"派生结果的前 8 字节按 big-endian 解释为 `u64`。
**session id 是派生值，从不提前传输。**

**确认 MAC**：

```text
HMAC-SHA256(key, "VLP/1" || " confirm " || direction_byte || transcript_hash || exporter)
```

客户端发送用 `auth_c2s`、`Direction::ClientToServer(0)`；服务端回复用 `auth_s2c`、
`Direction::ServerToClient(1)`。验证使用常量时间比较（`subtle::ConstantTimeEq`）。

因为 MAC 覆盖了 exporter，中继攻击（两段不同 TLS 会话）无法通过：真实服务端产生的 MAC 覆盖的是
它自己那条 TLS 会话的 exporter。

### 3.4 算法协商

`recv_algorithm_mask` 是 1 字节位掩码，表示**发送方愿意接收**的算法集合：

| 算法 | id | 掩码位 |
|------|----|--------|
| AES-256-GCM | 1 | `0x01` |
| ChaCha20-Poly1305 | 2 | `0x02` |
| AES-128-GCM | 3 | `0x04` |

`AlgorithmSet::all() = 0x07`。掩码为 `0x00` 或含未定义位（如 `0x80`）一律拒绝。

`HandshakeKeys` 中：
- `c2s_algorithms` = 客户端愿意接收的集合；
- `s2c_algorithms` = 服务端愿意接收的集合。

发送方从"对端愿意接收"的集合中选算法；接收方只接受"自己曾宣告"的集合中的算法，否则
`CodecError::AlgorithmNotOffered`。

---

## 4. 消息类型表

所有整数为大端；所有变长字段均为 `u16` 长度前缀（除非另注）。类型字节为第一个字节。

| type | 名称 | 类别 | 线上字段顺序 |
|------|------|------|-------------|
| `0x10` | `KEY_OFFER` | control | `u8 type` `u16 count` `count × (u32 key_id, 32B public)` |
| `0x11` | `KEY_ACK` | control | `u8 type` `u32 highest_consumed` `u8 request_more(0/1)` |
| `0x20` | `OPEN_STREAM` | application | `u8 type` `u32 stream_id` `u8 kind` `u16 port` `u32 initial_window` `u16 host_len` `host` |
| `0x21` | `OPEN_RESULT` | application | `u8 type` `u32 stream_id` `u8 status` `u32 initial_window` `u16 detail_len` `detail` |
| `0x22` | `STREAM_DATA` | application | `u8 type` `u32 stream_id` `u32 data_len` `data` |
| `0x23` | `STREAM_FIN` | application | `u8 type` `u32 stream_id` |
| `0x24` | `STREAM_RESET` | application | `u8 type` `u32 stream_id` `u32 code` `u16 reason_len` `reason` |
| `0x25` | `STREAM_WINDOW` | application | `u8 type` `u32 stream_id` `u32 credit` |
| `0x30` | `PING` | control | `u8 type` `u64 nonce` |
| `0x31` | `PONG` | control | `u8 type` `u64 nonce` |
| `0x32` | `COVER_DATA` | application | `u8 type` `u32 payload_len` `payload` |
| `0x40` | `GOAWAY` | control | `u8 type` `u32 code` `u16 reason_len` `reason` |
| `0x7f` | `ERROR` | control | `u8 type` `u32 code` `u16 message_len` `message` |

注意：**线上字段顺序与 Rust 枚举声明顺序不同**。例如 `OPEN_STREAM` 编码顺序是
`stream_id, kind, port, initial_window, host`（`message.rs` 的 `encode`）。

类别决定用哪把钥匙保护该帧：

- **control**（`KEY_OFFER`、`KEY_ACK`、`PING`、`PONG`、`GOAWAY`、`ERROR`）走 epoch 0，由控制链
  密钥保护。它们负责建立与维护一次性密钥池，因此不能依赖一次性密钥。
- **application**（其余）走 epoch 1，由一次性 X25519 交换派生的每帧密钥保护。目标主机名、端口、
  流 ID 与全部净荷都在密文内部。

字段约束（解码时强制）：

| 消息 | 约束 |
|------|------|
| `KEY_OFFER` | `count ≤ MAX_KEY_OFFER = 64`（= `veilink_crypto::MAX_OFFER_BATCH`） |
| `OPEN_STREAM` | `kind` 必须是已知值（当前仅 `0 = Tcp`）；`port != 0`；`host` 非空且 ≤ `MAX_HOST_LEN = 255` 字节、合法 UTF-8 |
| `OPEN_RESULT` | `status` 必须是已知值；`detail` ≤ `MAX_TEXT_LEN = 256` |
| `STREAM_DATA` | `data_len ≤ MAX_PAYLOAD = 65536` |
| `COVER_DATA` | `payload_len ≤ MAX_PAYLOAD = 65536` |
| `GOAWAY` / `ERROR` / `STREAM_RESET` | 文本字段 ≤ `MAX_TEXT_LEN = 256` |

文本字段在**编码**时超长会被截断到 256 字节而不是报错；在**解码**时超长会被
`MessageError::FieldTooLong` 拒绝。解码还拒绝：空输入（`Empty`）、未知类型
（`UnknownType`）、尾随字节（`Trailing`）、截断（`Truncated`）、非 UTF-8（`BadUtf8`）、
非法字段值（`Invalid`）。

**`ERROR` 的当前状态**：该类型可以被解码并会导致会话关闭，但当前代码库**从不发送** `ERROR`
帧；`GOAWAY` 只在优雅关闭时以 `code = 0` 发送。

---

## 5. 序号语义

- 每个方向各有独立的 `SendSequence`，从 0 开始，每密封一帧 +1。
- 发送序号在 `u64::MAX` 处失败而不是回绕（避免序号复用削弱重放保护）。
- **控制帧**：头部 `sequence` 取自控制链的 `step()`（因此也严格递增），但**接收侧不校验控制帧
  的序号**。控制帧的重放由哈希棘轮阻止：只有认证成功的帧才会推进接收链，重放同一帧会因为
  nonce / 链状态不再匹配而失败。
- **应用帧**：接收侧使用 `RecvSequence`，模式为 `SequenceMode::Monotonic`，语义为
  `sequence >= expected`。流程为：
  1. 先 `check(sequence)`（在触碰密钥池之前，因此重放无法消耗一次性密钥）；
  2. 取出一次性密钥、解密、验 tag、解填充、解码消息；
  3. 全部成功后才 `accept(sequence)`，把 `expected` 推进到 `sequence + 1`。
- 结果：重放（序号回退或复用）被拒绝；**应用帧允许序号跳变（gap）**，因为数据帧不驱动密钥链，
  但底层传输本身是有序可靠的，出现跳变只可能是协议违规。`SequenceMode::Exact` 在库里存在但当前
  会话编解码器并未使用它。

---

## 6. epoch 语义

| epoch | 用途 | 密钥来源 | key_id | sender_public | algorithm |
|-------|------|---------|--------|---------------|-----------|
| `0` | 控制帧 | 控制链棘轮 `k(n)` | `0` | 全 0 字节 | 固定 ChaCha20-Poly1305 |
| `1`（`DATA_EPOCH`） | 应用帧 | 每帧一次性 X25519 交换 | 接收方发布的 key id | 发送方本次的临时公钥 | 从对端可接收集合中选择 |

- `validate_header` 只接受这两个 epoch，其它值返回 `CodecError::UnsupportedEpoch`。
- 读循环按 `header.epoch == 0` 选择 `open_control`，否则选择 `open_application`。
- 控制链派生（`ControlChain`）：
  - 帧材料：`HKDF-SHA256(salt=None, ikm=k(n), info="vlp/1 control frame v1", 44 字节)`，
    前 32 字节为 ChaCha20-Poly1305 密钥，后 12 字节为 nonce。头部必须携带**完全相同**的 nonce
    （常量时间比较，`CodecError::NonceMismatch`）。
  - 棘轮步进：`k(n+1) = HKDF-SHA256(salt=None, ikm=k(n), info="vlp/1 control ratchet" || direction_byte)`。
  - 只有认证成功后接收链才 `advance()`。
- 应用帧密钥派生（`derive_frame_material`）：
  - `salt = transcript_hash || session_id_be`
  - `ikm = X25519 shared secret`
  - `info = "vlp/1 frame key v1" || direction || epoch_be || sequence_be || key_id_be || algorithm || sender_public`
  - 输出 `key_len + 12` 字节：前 `key_len` 为密钥，后 12 字节为 nonce；头部 nonce 必须匹配。
- 同方向相邻两帧不会使用相同算法：`select_algorithm` 从"对端可接收集合减去上一帧算法"中随机选取；
  集合只有一个元素时直接返回该元素。这是流量整形策略，不是安全属性。

---

## 7. 一次性密钥池

一对一帧密钥由接收方发布的一次性 X25519 密钥对实现。

```text
receiver                                   sender
  生成密钥对 #N（私钥留在池中）
  发布公钥           ─── KEY_OFFER ───►     记录 (id, public)
                                            选一个未使用的 id
                                            生成新的 sender ephemeral
                          ◄── 帧 ─────────   用派生密钥密封
  按 id 取出私钥
  做 DH、派生、解密
  销毁私钥（从池中移除）
```

- 发布：`KeyPool::publish` 每次最多 `MAX_OFFER_BATCH = 64` 个；池上限 `max_size` 被钳制在
  `[8, 8192]`。默认 `DEFAULT_POOL_SIZE = 256`，默认低水位 `DEFAULT_LOW_WATERMARK = 48`。
- 会话编解码器构造时使用 `SessionConfig::key_pool_size`（默认 `DEFAULT_POOL_SIZE`）与低水位
  `pool_size / 5`。
- 握手完成后双方立即各自发送一次 `KEY_OFFER`（`initial_key_offer`，发布
  `min(max_size - available, 64)` 个）。
- 补货：读任务每处理完一帧后调用 `maybe_offer_keys()`，仅当
  `available <= low_watermark` 时才发布新的一批；也就是说补货由对端流量驱动，没有独立定时器。
- `KEY_ACK { highest_consumed, request_more }`：`request_more` 在本地持有的对端密钥数 `< 16`
  时为 `true`；收到 `request_more = true` 的一方会立刻发布一批新密钥。
- 消费顺序：对端密钥按 id **升序**（先发布的先用）消费。
- `KeyPool::take` 是获得私钥的**唯一**途径，取出即从池中删除，因此"一钥一帧"是结构性保证而
  非约定。未知或已消费的 id 返回 `CryptoError::UnknownKeyId`。
- key id 在会话内不复用：分配器从 1 开始递增，回绕时跳过仍存活的 id。
- 所有零和非贡献（low-order）X25519 公钥都会被拒绝（`CryptoError::NonContributory`）。

`SessionCodec` 的密钥池填满后仍不足以密封时会返回 `CodecError::NoPeerKey`；写任务会发送
`KEY_ACK { request_more: true }` 并等待 `key_wait_timeout`（默认 10 秒），超时以
`SessionError::Protocol` 结束会话。

---

## 8. 流状态机

一个流是一条双向字节管道，由发起方分配 id。id 分配规则：客户端从 1 开始、服务端从 2 开始，
每次 `+2`（`Role::first_stream_id` → `fetch_add(2)`），因此客户端用奇数、服务端用偶数，同一会话
内不会冲突。

状态与迁移（`StreamShared` + `VlpStream`）：

```text
            (client) allocate id, send OPEN_STREAM, credit = 0
                                   │
                    ┌──────────────┴───────────────┐
                    │                              │
        OPEN_RESULT(Ok, window)          OPEN_RESULT(other)
                    │                              │
              ESTABLISHED                     REMOVED（客户端返回 OpenRefused）
              credit = window
                    │
      ┌─────────────┼──────────────┬─────────────────────┐
      │             │              │                     │
  写数据        本地半关        收到 STREAM_FIN       收到 STREAM_RESET
  (STREAM_DATA) (STREAM_FIN)   remote_finished=true  recv.reset=(2,reason)
      │             │          读到缓冲耗尽即 EOF    REMOVED
      │             │
      │        local_finished = true（之后写入返回 BrokenPipe）
      │
  收到 STREAM_WINDOW → credit += credit，唤醒写者
  接收缓冲超过宣告窗口 → 发送 STREAM_RESET(code 3)，REMOVED
  会话关闭 → 所有流 recv.reset=(1, "session closed")，全部 REMOVED
  VlpStream::drop 且未半关且对端未结束 → 发送 STREAM_FIN，REMOVED
```

要点：

- `STREAM_FIN` 是**半关**：只表示"本方向不再发送数据"。收到 `STREAM_FIN` 后仍可以继续向对端
  发送数据（`half_close_is_propagated` 测试覆盖）。
- `STREAM_RESET` 是**双向中止**。
- 客户端收到 `OPEN_STREAM` 属于协议错误，会直接关闭会话（`"client received OPEN_STREAM"`）。
- 服务端注册流时若已达 `max_streams`，回复 `OPEN_RESULT(TooManyStreams)`；主机名为空回复
  `BadRequest`。
- 未知流 id 的 `STREAM_DATA` 被忽略（trace 记录），不会导致会话失败。
- 单条流的失败（reset、被拒绝、对端停止读取）只影响该流；**帧级完整性失败会使整个会话关闭**
  （`reader_task` 中 `inner.close("frame rejected: …")`）。

---

## 9. 流控

双向、基于信用的流控。

| 参数 | 值 | 来源 |
|------|----|------|
| `initial_window`（默认宣告窗口） | `256 KiB` | `DEFAULT_WINDOW = 256 * 1024` |
| 最小窗口 | `16 KiB` | `MIN_WINDOW = 16 * 1024` |
| 单帧最大流数据 | `16 KiB` | `MAX_STREAM_DATA = 16 * 1024` |

规则：

1. `OPEN_STREAM.initial_window` = 发起方愿意为**接收**缓冲的字节数
   （`max(config.initial_window, MIN_WINDOW)`）。
2. `OPEN_RESULT.initial_window` = 服务端愿意接收的字节数；仅当 `status == Ok` 时非 0（否则为 0）。
3. 发送方初始信用：
   - 客户端发起流时信用为 0，直到收到 `OPEN_RESULT(Ok)` 才被设置为服务端宣告的窗口；
   - 服务端收到 `OPEN_STREAM` 时把该流的发送信用设为客户端宣告的窗口。
4. 发送：`VlpStream::poll_write` 每次最多发送
   `min(buf.len(), credit, MAX_STREAM_DATA)`，并扣减信用。信用为 0 时返回 `Poll::Pending`，
   由 `STREAM_WINDOW` 唤醒。
5. 接收：收到 `STREAM_DATA` 时 `buffered += len`；若 `buffered > window` 视为对端超发，发送
   `STREAM_RESET(code = 3, reason = "flow control window exceeded")`，移除该流，但**不关闭会话**。
6. 归还信用：读侧应用消费后，当 `delivered_since_grant * 2 >= window`（约半个窗口）时发送
   `STREAM_WINDOW { credit = delivered_since_grant }`。该消息用非阻塞 `try_send` 入队；若队列已满
   则不扣减计数，下次读取时再试。
7. 出站队列上界：`SessionConfig::outbound_queue`（默认 512）。队列满时 `poll_write` 返回
   `Poll::Pending`，由写任务腾出空间后唤醒。这是"慢读者不会导致对端内存无界增长"的机制。

---

## 10. 错误与状态码表

### 10.1 `OPEN_RESULT` 的 status

| 值 | 名称 | 含义 |
|----|------|------|
| 0 | `Ok` | 到目标的连接已建立，可以开始发送数据 |
| 1 | `PolicyDenied` | 被服务端 egress 策略拒绝 |
| 2 | `ResolveFailed` | 远端 DNS 解析失败（无 A 记录或查询失败） |
| 3 | `ConnectFailed` | 目标拒绝连接或不可达 |
| 4 | `TooManyStreams` | 服务端达到流数上限 |
| 5 | `BadRequest` | 请求格式错误（如 host 为空、端口为 0、未知 kind） |
| 6 | `ShuttingDown` | 服务端正在关闭 |
| 7 | `Unsupported` | 本版本不支持的目标（例如仅 IPv6） |

未知 status 值在解码时被拒绝（`MessageError::Invalid`）。
客户端 API `Session::open_stream` 在非 `Ok` 时返回 `SessionError::OpenRefused { status }`；
注意 `OPEN_RESULT.detail` 字段虽然在线路上存在并被解码，但客户端 API 目前把它置为空串丢弃。

### 10.2 `STREAM_RESET` 的 code

`code` 是自由格式的 `u32`。接收方在派发 `STREAM_RESET` 时**忽略 code 字段**，只把 `reason`
文本呈现给上层（`recv.reset = Some((2, reason))`）。当前代码实际发出的值：

| 值 | 发出方 | 场景 |
|----|--------|------|
| 1 | 服务端 runtime | 目标侧 I/O 错误导致 splice 失败（`reset_stream(stream_id, 1, …)`） |
| 2 | 接收方本地记录 | 收到对端的 `STREAM_RESET` 时本地标记（不经过线路） |
| 3 | 任一方 | 对端超出流控窗口 |

`VlpStream::reset(code, reason)` 允许调用方传入任意 code。

### 10.3 `GOAWAY` 的 code

当前实现只在 `Session::close(reason)` 时发送 `GOAWAY { code: 0, reason }`。其它值保留未用；
收到 `GOAWAY` 的一方会以 `"peer sent GOAWAY (code): reason"` 关闭会话。

### 10.4 `ERROR` 的 code

类型已定义、可解码、收到即关闭会话；但当前代码库不发送 `ERROR`。具体 code 取值**未定义**。

### 10.5 帧/编解码层错误

| 错误 | 触发条件 |
|------|---------|
| `FrameError::BadVersion` | 首字节不是 `0x56` |
| `FrameError::BadFrameType` | 类型字节不是 0 或 1 |
| `FrameError::BadDirection` | direction ∉ {0,1} |
| `FrameError::LengthOutOfRange` | `ciphertext_len ∉ [16, 69648]` |
| `FrameError::TruncatedHeader` | 头部不足 76 字节 |
| `FrameError::HandshakeTooLarge` | 握手消息 > 8192 字节 |
| `FrameError::CleartextAfterHandshake` | 已建立会话后收到明文帧 |
| `CodecError::WrongSession` | `session_id` 不匹配 |
| `CodecError::WrongDirection` | 方向不是对端方向 |
| `CodecError::UnsupportedEpoch` | epoch 不是 0 或 1 |
| `CodecError::AlgorithmNotOffered` | 使用了本端未宣告可接收的算法 |
| `CodecError::NonceMismatch` | 头部 nonce 与派生 nonce 不符 |
| `CodecError::BadLengthPrefix` | 明文长度前缀越界 |
| `CodecError::NoPeerKey` | 对端未发布可用的一次性密钥 |
| `CryptoError::UnknownKeyId` | key id 未知或已被消费 |
| `CryptoError::AuthenticationFailed` | tag 校验失败（篡改、伪造或跨会话） |
| `CryptoError::NonContributory` | 对端公钥为低阶点 |
| `CryptoError::Replay` | 序号回退或复用 |

`CryptoError` 的变体刻意保持粗粒度：调用者无法区分"密钥错误"与"密文被篡改"，避免错误处理成为
预言机。

---

## 11. 未实现 / 当前限制

以下内容**未实现**或**实现但不生效**，文档中不得当作已实现的能力：

- **发送节奏整形已生效，但没有对抗性评估**。`SendScheduler`
  （`protocol/scheduler.rs`）与 `PrivacyScheduler`（`veilink-privacy`）两端都会安装；
  **批量合并**（`max_batch` / `max_batch_bytes`）与**节奏整形**都实际起作用：`delay()` 只在
  `queued_behind > 0` 时返回非零值，`writer_task` 拿到非零值即睡眠，并受
  `schedule_max_delay`（50 ms）硬上限约束，`oldest_wait` 超限时立即发送。仍然**未做**的是：
  恒定速率发送，以及任何形式的检测率 / 抗指纹评估。
- **没有应用层 keepalive 循环**。`Session::ping()` 与 `PING`/`PONG` 已实现，但生产路径不周期性
  调用；空闲会话由 `idle_timeout`（默认 300 秒，运行时下限 60 秒）关闭。
- **cover traffic 的调度是"空闲突发后停止"，不是恒定速率**。`CoverEngine` 默认在会话空闲
  750 ms 后开始，每 1.5 秒一个突发、每突发最多 3 帧（64–4096 随机字节），最多 40 个突发后停止，
  并受 4 KiB/s 与每会话 256 MiB 的预算约束（详见 `docs/privacy.md`）。
- **没有流优先级、权重或抢占**。
- **`ERROR`（`0x7f`）从不发送**。
- **`SequenceMode::Exact` 未被会话编解码器使用**（控制帧不做序号检查，见第 5 节）。
- **`OPEN_RESULT.detail` 不会到达客户端 API**（被置空）。
- **IPv6 不支持**：流目标是 IPv4 字面量或域名；IPv6 字面量在规则解析、目标解析与远端解析三处
  都被显式拒绝。
