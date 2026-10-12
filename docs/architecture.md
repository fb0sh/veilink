# 架构

本文档说明 Veilink 的 crate 划分、一次被代理请求的完整数据流、`CONNECT` 隧道的交接方式，以及
为什么客户端是一个**字节级**代理而不是基于 HTTP 库实现。

---

## 1. Crate 划分与依赖方向

```text
                         veilink-cli (二进制 `veilink`)
                                    │
              ┌──────────────┬──────┴───────┬────────────────┐
              │              │              │                │
     veilink-client   veilink-server  veilink-config   veilink-crypto
              │              │              │                │
              │              │              └──────┬─────────┘
              │              │                     │
     veilink-protocol ───────┴──────────────► veilink-rules
              │
     veilink-crypto
```

依赖方向严格单向，没有环：

| crate | 职责 | 依赖 |
|-------|------|------|
| `veilink-crypto` | 原语封装、PSK、握手、密钥调度、一次性密钥池、长期身份、RNG | 仅第三方密码库 |
| `veilink-rules` | 白名单规则解析与匹配、域名规范化、IP/CIDR、通配符 | 无内部依赖 |
| `veilink-config` | `client.yaml` / `server.yaml` 的加载与两阶段校验 | `veilink-crypto`、`veilink-rules` |
| `veilink-protocol` | VLP/1：帧、消息、会话编解码、多路复用、流控、`duplex` 管道、统计计数器 | `veilink-crypto` |
| `veilink-transport` | TLS 1.3 配置与自签名身份、exporter、连接器、HTTP/2 承载 | `veilink-config`、`veilink-crypto`、`veilink-protocol` |
| `veilink-client` | 本地 HTTP 代理监听、路由决策、DIRECT/PROXY、uplink 与会话监管 | 上述全部 |
| `veilink-server` | 认证中继、远端 DNS、egress 策略、流中继 | 上述全部 |
| `veilink-cli` | `veilink client/server/keygen/check` 四个子命令、日志、配置热重载 | `veilink-config`、`veilink-crypto`、`veilink-rules`（并通过 client/server 间接使用其余） |
| `veilink-tests`（`tests/`） | 集成测试与共享 testkit（真实 TCP/TLS 源站、curl 驱动） | client、server、config、protocol、crypto |
| `veilink-benches`（`benches/`） | Criterion 基准：原语、完整帧、隐私机制开销 | `veilink-crypto`、`veilink-protocol` |

### 1.1 各 crate 内部模块

**`veilink-crypto`**

| 模块 | 职责 |
|------|------|
| `rng` | 唯一的随机源；失败即失败（fail closed） |
| `psk` | PSK 解析/生成与用途绑定派生 |
| `aead` | 三种 AEAD 的统一常量时间接口 |
| `x25519` | 发送方临时密钥、接收方一次性密钥、长期身份 |
| `kdf` | 转录绑定密钥调度与控制链棘轮 |
| `epoch` | 方向、序号与重放拒绝 |
| `key_pool` | 接收方一次性密钥池 |
| `handshake` | PSK 绑定、channel binding 的认证握手 |
| `identity` | 服务端持久化长期身份 |

**`veilink-protocol`**

| 模块 | 职责 |
|------|------|
| `frame` | 76 字节认证头、帧读写、长度边界 |
| `message` | 位置化的消息编码与解码 |
| `codec` | 会话编解码：填充策略、控制链、一次性密钥池 |
| `session` | 多路复用、流状态机、流控、读写任务 |
| `duplex` | 带缓冲的双向流、头部读取、字节记账转发、全双工 splice |
| `stats` | 客户端与服务端共用的原子计数器 |

**`veilink-client`**：`http`（HTTP/1.1 解析与改写）、`routing`（authority 解析与 DIRECT/PROXY
选择）、`tunnel`（`Tunnel` 抽象与 fail-closed 路由）、`proxy`（每连接请求循环）、`runtime`
（监听器、限额、共享上下文）、`uplink`（会话建立、隧道、重连退避）。

**`veilink-server`**：`resolver`（仅 IPv4 的 DNS + TTL 缓存）、`policy`（特殊用途地址与端口拒绝）、
`egress`（解析→授权→连接→splice）、`runtime`（accept 循环、限速、每连接认证与会话、流中继）。

---

## 2. 一次被代理请求的数据流

### 2.1 总览

```text
Browser/curl
    │  HTTP 代理请求（明文 HTTP/1.1 或 CONNECT）
    ▼
┌────────────────────────── veilink client ──────────────────────────┐
│ ClientRuntime::run  accept 循环（Semaphore: max_connections）        │
│        │                                                           │
│        ▼                                                           │
│ proxy::serve（每连接一个任务）                                       │
│   1. BufStream::read_head(max_header_bytes)   ← 有界头部预算         │
│   2. http::parse_request_head（httparse，≤128 头，target ≤8 KiB）    │
│   3. head.is_connect() ? handle_connect : handle_forward            │
│   4. head.authority() → RouteTarget::new（域名规范化 / IPv4 字面量）  │
│   5. RuleEngine::decide(&target)  →  Decision::Proxy / Decision::Direct │
│        │                        │                                   │
│        │ DIRECT                 │ PROXY                             │
│        ▼                        ▼                                   │
│   DirectTunnel::open        VlpTunnel::open                         │
│   tokio TcpStream::connect  Session::open_stream(host, port)        │
│   （本地系统 resolver）      （域名原样进入加密帧，客户端不解析）        │
└────────┬─────────────────────────────────┬─────────────────────────┘
         │                                 │  VLP/1 session（TLS 1.3 / h2）
         │                                 ▼
         │                    ┌──────── veilink server ────────┐
         │                    │ ServerRuntime::run accept 循环  │
         │                    │  ├ 每源地址限速                  │
         │                    │  └ Semaphore: max_connections   │
         │                    │ serve_connection                │
         │                    │  ├ TLS/h2 握手 → exporter        │
         │                    │  ├ VLP/1 握手（PSK + exporter）  │
         │                    │  └ relay_streams → serve_stream │
         │                    │ serve_stream                    │
         │                    │  ├ Egress::connect(host, port)  │
         │                    │  │   ├ policy.check_port        │
         │                    │  │   ├ Resolver::resolve_ipv4   │
         │                    │  │   ├ policy.filter_addresses  │
         │                    │  │   └ TcpStream::connect(已校验地址) │
         │                    │  ├ Session::respond_open(Ok)    │
         │                    │  └ duplex::splice(隧道流, 目标)  │
         │                    └────────────────────────────────┘
         ▼
    Target（HTTP origin / TLS 源站）
```

### 2.2 明文 HTTP 请求（`handle_forward`）

1. `proxy::serve` 用 `BufStream::with_limit(socket, max_header_bytes + 64 KiB)` 包裹客户端连接，
   读头部受 `limits.max_header_bytes`（默认 65536）限制，读等待受 `limits.idle_timeout_ms`
   （默认 300000）限制。
2. `http::parse_request_head` 用 `httparse` 解析：
   - 最多 `MAX_HEADERS = 128` 个头；
   - request target ≤ `MAX_TARGET_BYTES = 8192`；
   - 只接受 HTTP/1.0 与 HTTP/1.1（`version > 1` 返回 505）。
3. `RequestHead::authority()` 解析目标：
   - `CONNECT` 用 authority-form，默认端口 443；
   - absolute-form（`http://host[:port]/path`，也接受 `https`）默认端口 80/443；
   - 其它情况（origin-form、`OPTIONS *`）用 `Host` 头，默认端口 80。
   - `routing::split_host_port` 不进行任何 DNS 解析，并拒绝 IPv6 字面量、端口 0、控制字符。
4. `RouteTarget::new`：IPv4 字面量 → `Target::Ipv4`；域名 → `HostName::parse` 规范化
   （小写、去尾点、IDNA A-label），已是域名则保留规范化形式供远端解析。
5. 路由：取 `ctx.rules.snapshot()`（`ArcSwap` 快照，保证在途请求的路由决定稳定），
   `RuleSet::decide` 返回第一个匹配规则（OR 语义），得到 `RouteSelection::Proxy { rule }` 或
   `Direct`。空白名单 = 全部 DIRECT。
6. 在触碰网络之前先校验请求帧格式（`body_framing()`），因此畸形请求不会产生外连。
7. `Expect: 100-continue` **在本地应答**（直接回 `HTTP/1.1 100 Continue\r\n\r\n`），避免与源站
   互相等待造成死锁；转发给源站的头部会移除 `Expect`。其它 expectation 返回 417。
8. 上游连接复用：以 `UpstreamKey { host, port, route }` 为键缓存一条上游连接；只有目标与路由都
   相同且未被"污染"时才复用。`poisoned` 在以下情况置位：请求体以 EOF 定界、响应体以 EOF 定界、
   响应头解析失败。
9. `Router::open(selection, host, port)` 获得字节管道（见 2.3）。
10. 序列化请求头发往上游：
    - 目标改写为 origin-form（path + query）；
    - 丢弃 hop-by-hop 头（`Connection`、`Proxy-Connection`、`Keep-Alive`、
      `Proxy-Authenticate`、`Proxy-Authorization`，以及 `Connection` 中列出的扩展头）；
    - **例外**：检测到协议升级（`Connection: upgrade` + `Upgrade`）时保留
      `Connection`/`Upgrade`，否则源站无法回 `101`；
    - `Host` 头按原字节保留；缺失时用 authority 合成 `Host: host:port`。
11. 请求体按 `BodyFraming` 转发：
    - `None`：无体；
    - `Length(n)`：`forward_exact` 精确转发 n 字节；
    - `Chunked`：`forward_chunked` 逐块转发，包括 trailer，原样不改写；
    - `UntilEof`：`forward_until_eof` 直到客户端关闭（之后上游连接不可复用）。
12. 读上游响应头：1xx（`101` 除外）立即转发给客户端并继续读；其它状态码跳出循环。
13. `101 Switching Protocols` 且原请求是升级请求 → 转 `splice`（见第 3 节）。
14. 响应体按 framing 转发；`serialize_for_client` 丢弃 `Proxy-Authenticate` 与
    `Proxy-Connection`。
15. keep-alive：只有上游与客户端双方都允许时才继续下一轮；否则关闭连接。

### 2.3 DIRECT 与 PROXY 的打开方式

`Router::open`（[`tunnel.rs`](../crates/veilink-client/src/tunnel.rs)）是唯一的"如何拿到字节管道"
的决策点：

- **DIRECT**：`DirectTunnel::open` 用 `tokio::net::TcpStream::connect((host, port))`，由 Tokio 在
  阻塞线程池上调用**系统 resolver**，受 `limits.connect_timeout_ms`（默认 10000）限制。
- **PROXY**：
  - 若没有远端隧道（`self.remote == None`）或隧道 `is_ready()` 为假，返回
    `RouteError::TunnelUnavailable`，**绝不回退到 DIRECT**；
  - 否则 `VlpTunnel::open(host, port)` → `Session::open_stream(host, port)`：
    分配流 id（客户端奇数、步长 2），发送 `OPEN_STREAM { host, port, kind: Tcp, initial_window }`；
    等待 `OPEN_RESULT`，超时 `SessionConfig::open_timeout`（默认 30 秒）；
    收到 `Ok` 后返回带信用额度的 `VlpStream`（外层包 `CountedStream` 做字节统计）。
- **关键隐私点**：PROXY 路径把 `RouteTarget::transmit_host()`（规范化后的域名）**原样**放进加密
  帧，客户端**不做 DNS 查询**。因此本地 resolver 不会看到该域名。

### 2.4 服务端侧（PROXY 的落地）

1. `ServerRuntime::run`：accept 循环带两层限制——按源 IP 的每秒连接速率
   （`limits.accept_rate_per_second`，默认 64）与并发连接数
   （`Semaphore(max_connections)`，默认 1024）。
2. `serve_connection` 依配置选择传输（不猜测、不静默降级）：`tls` 或 `h2`；两者都得到 TLS
   exporter。
3. VLP/1 握手（`start_session(Role::Server, …, ctx.identity.public_bytes(), …)`）。失败只记录
   debug 日志并关闭连接，错误信息不区分"PSK 接近正确"等细节。
4. `relay_streams`：从 `incoming_streams()` 接收 `IncomingStream { stream, host, port }`，
   每条流一个任务；会话关闭时停止接收并给在途任务 5 秒收尾。
5. `serve_stream`：
   - `Egress::connect(&host, port)`：先 `policy.check_port`，再 `Resolver::resolve_ipv4`，
     再对**每个**解析结果 `policy.filter_addresses`，最后连接**已校验的地址**
     （从不把域名交给 socket API，也从不重新解析）；
   - 失败时把错误映射为 `OpenStatus`（`Denied → PolicyDenied`、
     `Resolve/NoAddress → ResolveFailed`、`Connect/Unreachable → ConnectFailed`）并回复
     `OPEN_RESULT`，同时递增 `egress_denied`；
   - 成功时先 `respond_open(Ok)`（客户端 `open_stream` 以该消息为"目标连接已建立"的承诺），
     再 `duplex::splice` 在隧道流与目标 socket 之间双向搬运。

### 2.5 会话内部的任务结构

`veilink-protocol` 的 `Session` 由三部分组成：

- 一个**写任务**：拥有发送半连接，从有界队列取出消息、密封并写线。密封放在写任务里（而不是调用
  方）是为了让帧序号顺序与上线顺序一致，接收方的重放检查依赖这一点。
- 一个**读任务**：拥有接收半连接，认证每帧、派发消息、按需补发一次性密钥，空闲超过 `idle_timeout`
  时关闭会话。
- 共享状态 `SessionInner`：编解码器（`Mutex<SessionCodec>`）、流表、开流等待者、ping 等待者、
  入站流信道、关闭标志与统计。

出站消息通过 `mpsc` 有界队列（默认 512）交付；队列满时 `poll_write` 让出（`Poll::Pending`），
因此慢读者只会反压，不会造成无界缓冲。

---

## 3. CONNECT 隧道的交接

`CONNECT` 的处理与其他请求**完全分开**，因为从这里开始 HTTP 语义就结束了：

```text
client（浏览器）                       veilink client                     目标 TLS 源站
      │ CONNECT github.com:443 HTTP/1.1      │                                │
      ├──────────────────────────────────────►│                                │
      │                                       │ 1. parse_request_head          │
      │                                       │ 2. authority()（默认端口 443）  │
      │                                       │ 3. RouteTarget::new            │
      │                                       │ 4. rules.decide()              │
      │                                       │ 5. Router::open()              │
      │                                       │      ├ DIRECT: TcpStream       │
      │                                       │      └ PROXY: OPEN_STREAM ─────┼──► 服务端 egress
      │                                       │                                │
      │                                       │ 6. 成功：写 200 并开始 splice   │
      │  HTTP/1.1 200 Connection Established  │                                │
      │◄──────────────────────────────────────┤                                │
      │                                                                        │
      │  ====== 从此为原始字节拼接（splice），不再解析任何 HTTP ======            │
      │  TLS ClientHello ─────────────────────────────────────────────────────►│
      │  ◄────────────────────────────────────────── TLS ServerHello / 证书 ────│
      │  （Veilink 不终止 TLS，不查看、不修改任何 TLS 或 HTTPS 明文）             │
```

实现细节（[`proxy::handle_connect`](../crates/veilink-client/src/proxy.rs)）：

- **缓冲不会被丢掉**：`BufStream` 保留了头部之后已经读入的字节（例如客户端在同一批量里
  pipelined 的 TLS ClientHello）。`duplex::splice` 在切换到原始复制之前会先把两侧的已缓冲字节各
  自冲出去，并把它们计入统计。
- **成功响应固定为** `HTTP/1.1 200 Connection Established\r\n\r\n`（不含其它头部）。
- **失败时 fail closed**：无法建立连接（含隧道不可用）返回 `502 Bad Gateway` 并关闭；绝不改为
  直连。这与白名单的语义一致：用户要求"这条流量走 VPS"，就不能从本地地址去访问它。
- **半关语义**：`splice` 在每个方向的复制结束时对目标调用 `shutdown()`（`copy_one_way`），因此
  先结束发送的一方仍能收到对方之后发送的数据。`shutdown()` 即使在复制报错时也会执行，避免另一方
  永久等待 FIN 而死锁。
- **字节记账**：`SpliceOutcome { a_to_b, b_to_a }` 分别累加到 `bytes_up` / `bytes_down`。
- **`Upgrade`（WebSocket）走同一路径**：收到 `101` 且原请求是升级请求时，客户端先转发 `101`
  响应头，然后 `upstream.take()` 并 `splice(client, upstream)`，进入 `ForwardOutcome::Hijacked`。
  也就是说 101 之后的连接与 CONNECT 一样是裸字节拼接。
- **不会发生的事**：Veilink 不终止 TLS、不生成证书、不做 MITM、不解密 HTTPS、不重写 URL。

---

## 4. 为什么是字节级代理，而不是用 HTTP 库

Veilink 的客户端只解析"保持连接帧同步所必需的最小内容"，其余字节原样转发。这不是实现上的偷懒，
而是几个不可替代的行为要求的直接结果：

1. **`CONNECT` 与 `Upgrade` 之后必须完全停止解释 HTTP。** 一旦返回 `200 Connection Established`
   或 `101`，对端开始发送 TLS 记录或 WebSocket 帧。任何"HTTP 中间件"式实现都可能尝试继续解析、
   规范化或重新分帧，从而破坏这些字节。字节级管道从结构上排除了这种可能。
2. **必须精确保留已缓冲的字节。** 头部读取会一次读入超过头部的数据（因为 TCP 是流）。
   `duplex.rs` 明确说明它没有包一层 `tokio::io::BufReader`，而是自己维护 `start`/`end` 窗口，
   因为这些缓冲必须在"解析头部"切换到"字节拼接"时存活下来，否则 CONNECT 的 TLS 握手会丢字节。
   `tests/websocket.rs` 的 `bytes_pipelined_with_the_upgrade_request_are_not_lost` 覆盖了这一点。
3. **必须做精确的字节记账与定界。** `Content-Length`、`chunked`、`UntilEOF` 三种体定界，
   以及 `HEAD` / `204` / `304` / 1xx 无体规则，都需要按 RFC 处理；`forward_exact` /
   `forward_chunked` / `forward_until_eof` 都以"精确字节数"为单位，保证下一个请求的起始位置正确。
4. **必须支持流式与长连接而不整体缓冲。** 流式响应（SSE）、无界下载、慢源站都必须边读边写；
   把整个 body 收进内存的库式做法会破坏 SSE 语义并造成内存放大。
   `tests/streaming.rs` 的 `large_streams_are_not_buffered_entirely` 与
   `a_slow_origin_does_not_block_other_connections` 覆盖了这一点。
5. **必须能容忍真实世界的头部写法。** `read_head` 接受 `\r\n\r\n`，也接受 `\n\n` 与 `\n\r\n`
   作为头部结束（严格化只会给本身正常的客户端制造 400）。
6. **必须能作为纯字节管道送进加密隧道。** 客户端与隧道之间交换的是 `BoxStream`（`dyn Duplex`），
   所以同一套转发逻辑无论对端是本地 `TcpStream` 还是多路复用的 `VlpStream` 都成立；这也是
   `veilink-protocol::duplex` 被客户端复用的原因。

代价是：解析由 `httparse` 承担最基本的语法检查，代理自身不实现任何 HTTP 语义（不做缓存、不做
重写、不做内容编码协商、不维护 cookie）。这是有意的取舍——代理越"薄"，它越不可能改变或泄露
被保护流量。

---

## 5. 配置热重载与线程/任务模型

- 每个被接受连接一个 Tokio 任务；客户端 accept 循环用 `Semaphore` 限制并发，服务端额外有按源 IP
  的速率限制。
- 白名单通过 `arc_swap::ArcSwap<RuleSet>` 热替换：在途请求持有旧快照，因此路由决定不会中途改变。
- 客户端 `reload` 模块观察配置文件的**父目录**（编辑器常用"写临时文件再改名"的保存方式），
  对新配置先完整解析与校验，失败则保留旧规则并记录错误。变更分类（`ClientConfigChange`）：
  - `WhitelistOnly`：原子替换规则；
  - `Session`：停止 uplink 并重建会话（服务端地址、传输、SNI 或 PSK 变化）；
  - `Listen`：仅告警，需要重启；
  - `None`：无变化。
- uplink 使用带抖动的指数退避重连（初始 500 ms、上限 60 s，成功后重置）。会话断开时立即
  `clear_remote_tunnel()`，使白名单请求立刻 fail closed 而不是排队等待。
- 会话本身没有应用层 keepalive 循环：空闲由 `idle_timeout` 关闭（见 `docs/privacy.md` 与
  `docs/protocol.md` 的"未实现"小节）。
