# 测试

本文档说明如何运行 Veilink 的测试、每个测试文件覆盖什么、如何复现验收检查，以及如何做
真实网络（GitHub）的人工验收。

---

## 1. 快速开始

前置条件：

- Rust stable（仓库含 `rust-toolchain.toml`，`rust-version = 1.83`）；
- **`curl` 可执行文件**：`tests/` 下的集成测试用真实 `curl` 通过真实代理访问真实源站；
- 可用的回环网络与临时端口（测试都在 `127.0.0.1` 上自建源站/代理/服务端）。

```bash
cd /path/to/Veilink

# 全部测试（单元 + 集成 + CLI）
cargo test --workspace

# 只跑单元测试（不依赖 curl）
cargo test --workspace --lib

# 只跑某个集成测试文件
cargo test -p veilink-tests --test end_to_end

# 按名字过滤
cargo test --workspace replay
cargo test -p veilink-tests --test dns_leak a_whitelisted_domain

# CLI 测试
cargo test -p veilink-cli

# 编译测试与基准但不运行
cargo test --workspace --no-run
cargo bench --no-run -p veilink-benches

# 基准（会真实运行，耗时较长）
cargo bench -p veilink-benches
cargo bench -p veilink-benches -- --test      # 每个基准只跑一次，用于冒烟验证
```

> 在受限环境（例如沙箱阻止写入 `~/.cargo`）中，先设置工作区内的 `CARGO_HOME`：
> `export CARGO_HOME=$PWD/.cargo-home`。本仓库的 `.gitignore` 已忽略 `/.cargo-home`。

当前工作树中的测试数量（`cargo test --workspace --no-fail-fast` 的结果，32 个测试目标）：

| 层次 | 数量 |
|------|------|
| 单元测试（`crates/**` 各 lib/bin 目标，含 `veilink-transport` 18、`veilink-protocol` 78、`veilink-crypto` 76） | 299 |
| CLI 集成测试（`crates/veilink-cli/tests/cli.rs`） | 10 |
| 端到端集成测试（`tests/*.rs`） | 67 |
| doc-test | 2 |
| **合计** | **378 通过 / 0 失败 / 0 ignored** |

各目标分布：`veilink` 2、`veilink-client` 32、`veilink-config` 21、`veilink-crypto` 76、
`veilink-privacy` 20、`veilink-protocol` 78、`veilink-rules` 34、`veilink-server` 16、
`veilink-testkit` 2、`veilink-transport` 18、`cli.rs` 10；集成测试 67（见 3.1 表）；
doc-test 2（`veilink-config` 与 `veilink-rules` 各 1）。

（测试数量随代码变化；以 `cargo test --workspace` 的输出为准。）

---

## 2. 测试层次

1. **单元测试**：每个 crate 内部测试自己的模块——密码学原语与密钥调度、帧编解码、消息编解码、
   会话/流控、`duplex` 管道、规则匹配、配置校验、出口策略、DNS 解析器、TLS/HTTP2/连接器、
   HTTP 解析、路由、隧道、隐私层（预算、调度、cover、填充）。
2. **CLI 集成测试**：真实调用编译出的 `veilink` 二进制，验证 `--version`/`--help`、`keygen`
   （编码、权限、多密钥、拒绝覆盖）、`check`（有效配置、逐条规则报错、未知字段、schema 探测、
   显式 `--type`、缺失文件）。
3. **端到端集成测试**：在测试进程内启动真实的 Veilink 客户端/服务端与真实源站，用真实 `curl`
   驱动完整路径（含加密隧道、DNS stub、重连与 fail-closed）。

所有集成测试**不访问互联网**：源站、DNS 与两端都是测试自建的。这也意味着它们可以在离线 CI 中
运行（只需要 `curl` 二进制）。

---

## 3. 每个测试文件覆盖什么

### 3.1 `tests/`（端到端与一致性）

| 文件 | 测试数 | 覆盖内容 |
|------|--------|---------|
| `http_proxy.rs` | 9 | HTTP 正向代理一致性：简单 GET、方法与头部/状态透传、POST body、大文件下载/上传完整性、keep-alive 连接复用、origin-form 请求、畸形请求返回 400、源站不可达返回 502（空白名单，全部走 DIRECT） |
| `https_connect.rs` | 4 | `CONNECT` 隧道：对真实 TLS 1.3 源站端到端握手（客户端不终止 TLS）、同一隧道内的多个 TLS 请求、目标端口关闭时 fail-closed、CONNECT 目标的严格解析 |
| `websocket.rs` | 3 | `Upgrade`：双向字节回显、与升级请求一起 pipelined 的字节不丢失、非升级请求不会被误当升级 |
| `streaming.rs` | 7 | 流式与分块：chunked 重组、SSE 增量到达、以连接关闭定界的响应、下载中途取消、连续多次下载一致、慢源站不阻塞其它连接、大流不会被整体缓冲 |
| `whitelist.rs` | 6 | 路由边界：未命中走 DIRECT、命中且隧道不可用时**绝不回退直连**、CONNECT 同理、空白名单全部 DIRECT、热重载只影响新请求、不同规则类型独立生效 |
| `concurrency.rs` | 6 | 并发与生命周期：并发请求、交错流不串数据、客户端异常断开不影响他人、连接上限拒绝超额连接、超大头部被拒、统计计数跟踪流量 |
| `end_to_end.rs` | 8 | **完整 PROXY 路径**：HTTP 经加密隧道、HTTP/2 承载、HTTPS CONNECT 经隧道、大文件经隧道、多流共享一个会话、错误 PSK 被拒且请求 fail-closed、**设置了 `server_identity_pin` 时身份被强制校验**、隧道与 DIRECT 并存 |
| `dns_leak.rs` | 3 | **DNS 本地性证明**（用 `DnsStub` 记录查询）：白名单域名由服务端解析、DIRECT 请求不使用服务端解析器、白名单域名解析失败时不回退直连 |
| `crypto_roundtrip.rs` | 4 | 跨 crate 密码学往返：握手一致性与 PSK 区分、帧只在线路上出现、真实 socket 上的会话承载流、帧读取器拒绝垃圾字节 |
| `forward_secrecy.rs` | 5 | **以攻击尝试形式**验证前向保密：仅凭 PSK 无法打开录制的帧、换了其它一次性密钥无法打开、会话标识绑定进每帧密钥、接收方每帧后销毁一次性密钥、仅有录制到的发送方公钥不够 |
| `replay.rs` | 9 | 会话级重放/篡改/协议混淆：重放数据帧、重放控制帧、跨流/跨序号搬运、密文截断或加长、跨会话帧、把帧发回给发送方、不支持的 epoch、从未发布的 key id、认证失败时关闭会话 |
| `recovery.rs` | 3 | 恢复行为：服务端下线期间请求 fail-closed、服务端恢复后客户端重连、不可达服务端按退避重试 |

### 3.2 `tests/src/`（共享 testkit）

| 文件 | 提供 |
|------|------|
| `lib.rs` | 导出 `TestServer`、`TestTlsServer`、`DnsStub`、`RunningServer`、`RunningTunnelClient`、`curl`、`settings` |
| `server.rs` | 真实 TCP HTTP/1.1 源站（keep-alive、chunked、流式、大上传、WebSocket 升级路由）与真实 TLS 1.3 源站（自签证书），供 CONNECT 测试使用 |
| `dns.rs` | 最小 DNS stub：对所有 A 查询返回配置地址，并**记录被查询的名字**——这是区分"客户端解析"与"服务端解析"的关键 |
| `settings.rs` | 构造合法配置的辅助函数（`TEST_KEY`/`TEST_KEY_OTHER`、空闲端口）、`RunningClient`（后台运行客户端并可 `stop()`） |
| `veilink.rs` | `RunningServer`（可指定 transport 与可选 DNS 服务器）与 `RunningTunnelClient`（启动客户端 + uplink 并等待 `wait_ready()`），用于完整 PROXY 路径 |
| `curl.rs` | `curl` 封装：`get_via_proxy`、`get_via_proxy_with_status`、`get_via_proxy_with_host`、`post_via_proxy`、`upload_from_stdin`、`download_to_file`、`connect_via_proxy`、`connect_tls_via_proxy`，以及 `CurlResult`/`expect_ok` |

### 3.3 各 crate 的单元测试重点

| crate | 重点 |
|-------|------|
| `veilink-crypto` | AEAD 三算法封/开与篡改检测、密钥长度、X25519 协商与低阶点拒绝、HKDF 标签分离、控制棘轮单向性、一次性密钥池并发与耗尽/补货、身份文件格式与权限、PSK 解析与低熵拒绝、RNG 边界 |
| `veilink-protocol` | 76 字节头往返与非法字段、超大声明长度在分配前拒绝、握手帧与认证帧读写、13 种消息往返与边界、填充桶、控制链与序号、每帧密钥唯一性与跨会话拒绝、流控/半关/reset/多路复用、`duplex` head 读取与 splice |
| `veilink-rules` | 各规则类型匹配、label 边界后缀、IDNA、通配符单 label、重复检测、解析错误信息、热替换快照 |
| `veilink-config` | 最小/完整配置校验、未知字段拒绝、白名单错误**一次性全部报告**、密钥格式、DNS/端口校验、变更分类、Debug 脱敏 |
| `veilink-transport` | 自签身份生成/加载与文件权限、PEM 往返、ALPN 校验（含"要求特定协议"）、exporter 逐会话唯一、HTTP/2 承载与第二条流被拒 |
| `veilink-server` | 出口策略全部拒绝网段（含元数据地址）与允许网段、端口白名单、公私混合解析整体拒绝、DNS 缓存 TTL/淘汰、解析器字面量短路 |
| `veilink-client` | HTTP 解析（absolute/origin/CONNECT、hop-by-hop 剥离、Content-Length 冲突、chunked 转发、错误响应）、authority 解析与 IPv6 拒绝、路由决策、隧道 fail-closed、上游缓存键、代理错误状态映射 |
| `veilink-privacy` | 预算速率窗口与生命周期额度、部分授予、padding/cover 独立窗口、填充降级、调度延迟有界/有抖动/不饥饿、cover 突发上限与空闲判定 |
| `veilink-cli` | 配置探测、热重载 |

---

## 4. 复现验收检查

以下是手工验收清单（与 `tests/` 自动化测试互为补充，覆盖"本地环境真实行为"）：

**A. 客户端代理本身（不需要 VPS）**

```bash
# 终端 1：一个本地源站
python3 -m http.server 8000

# 终端 2：空白名单的客户端（全部 DIRECT）
cat > /tmp/veilink-direct.yaml <<'EOF'
server: "127.0.0.1:9"
key: "$(veilink keygen --quiet)"
EOF
veilink client --config /tmp/veilink-direct.yaml

# 终端 3
curl -x http://127.0.0.1:7890 http://127.0.0.1:8000/ -o /dev/null -w '%{http_code}\n'   # 期望 200
```

**B. 完整 PROXY 路径（需要 VPS 或本机自建服务端）**

```bash
# 服务端（本机测试用 allow_private_targets，仅测试！）
veilink server --config examples/server.yaml --listen 127.0.0.1:8443 --log-level debug
# 客户端把 server 指向它，whitelist 填 "*"
veilink client --config /tmp/veilink-proxy.yaml --log-level debug

curl -x http://127.0.0.1:7890 https://github.com/ -o /dev/null -w '%{http_code}\n'
# 客户端日志应出现 route=PROXY；服务端日志应出现 stream opened
```

**C. fail-closed（最重要的一条）**

1. 让白名单命中某个目标（例如 `DOMAIN,github.com`）；
2. 把 `server` 指向一个不可达地址（或停掉 VPS）；
3. 请求该目标：**必须失败（502）**，而不是成功直连；
4. 客户端日志应出现 `refusing to fall back to DIRECT` / `no secure tunnel is available`。

**D. DNS 本地性**

- 用 `DnsStub`（见 `tests/src/dns.rs`）或自建 DNS：让服务端指向它，请求一个白名单域名；
- stub 应记录到该域名（证明**服务端**在解析）；
- 本地 resolver（`dig`/`tcpdump` port 53）**不应**出现该域名。

**E. 前向保密**

- `cargo test -p veilink-tests --test forward_secrecy`：这些测试是一组**显式的攻击尝试**，
  每个测试都说明它证明了什么、又不证明什么；
- 它们**不能**证明"内存里没有残留"——见 `docs/cryptography.md` 第 5.2 节。

---

## 5. 真实网络（GitHub）验收

**现状：仓库中没有自动化的真实网络测试。** 所有 `#[ignore]` 标记与类似的网络门控测试都不存在
（可用 `grep -rn '#\[ignore' tests/ --include='*.rs'` 核对，当前无匹配）。`http_proxy.rs` 的模块注释提到
`end_to_end.rs` 覆盖 PROXY 路径，而 PROXY 路径的端到端测试现在确实存在（见上表），但它们使用的是
测试内自建的源站，而不是 GitHub。

因此"真实网络 GitHub 测试"目前只能**人工执行**。步骤如下（这也是对协议、TLS 与 DNS 行为最贴近
现实的验收）：

```bash
# 1. 生成密钥并部署服务端（见 docs/deployment.md），确认它在监听
veilink check --config /etc/veilink/server.yaml --verbose

# 2. 客户端配置：把 GitHub 相关域名加入白名单
cat > client.yaml <<'EOF'
server: "<你的 VPS IP>:443"
key: "<与服务端相同的 key>"
whitelist:
  - "DOMAIN,github.com"
  - "DOMAIN-SUFFIX,githubusercontent.com"
  - "DOMAIN-SUFFIX,githubassets.com"
  - "DOMAIN-SUFFIX,github.io"
EOF

veilink check --config client.yaml --verbose
veilink client --config client.yaml        # 观察日志中的 route=PROXY

# 3. 基本连通性与路径确认
curl -x http://127.0.0.1:7890 -v https://github.com/ -o /dev/null -w '%{http_code}\n' 2>&1 \
  | grep -E 'CONNECT|200 Connection|HTTP/'

# 4. 真实内容完整性（大文件走隧道）
URL=https://raw.githubusercontent.com/rust-lang/rust/master/README.md
curl -x http://127.0.0.1:7890 "$URL" -o via-proxy.txt
curl                         "$URL" -o direct.txt
sha256sum via-proxy.txt direct.txt        # 两者必须相同

# 5. 真实 Git 操作
git -c http.proxy=http://127.0.0.1:7890 clone --depth 1 https://github.com/rust-lang/example.git /tmp/example

# 6. 在 VPS 上确认流量确实来自它（另开一个终端）
sudo tcpdump -ni any 'tcp port 443 and host github.com' -c 5
```

**如果要把这类检查自动化**（本仓库尚未提供），建议的形式是：用一个默认 `#[ignore]` 的测试，
显式读取环境变量（例如 `VEILINK_E2E_SERVER`、`VEILINK_E2E_KEY`）后才运行，并通过
`cargo test -- --ignored` 触发；这样 CI 与离线环境不会被真实网络影响。请注意本仓库当前
**没有**这样的测试，不要把它当成已存在的能力。

---

## 6. 基准

`benches/` 是一个独立的、`publish = false` 的包（`veilink-benches`），使用 Criterion，三个目标：

| 文件 | 内容 |
|------|------|
| `benches/crypto.rs` | 三种 AEAD 的 seal/open（64 B、4 KiB、16 KiB，含吞吐量）、X25519 keygen/encapsulate/decapsulate/完整协商、密钥调度（`derive_handshake_keys`、完整内存握手、`derive_frame_material`） |
| `benches/throughput.rs` | 通过真实 `SessionCodec` 的完整帧 seal/open/seal+open（64 B、1 KiB、16 KiB）、控制帧（`PING`、64 键 `KEY_OFFER`）、消息编解码（`STREAM_DATA`、`KEY_OFFER`、`OPEN_STREAM`） |
| `benches/privacy.rs` | 填充策略本身（`padded_len`、`cover_len`）、**填充开销**（同一消息"带填充 vs 不带填充"的 AEAD 成本对比）、cover 帧的每帧密码学成本 |

```bash
cargo bench -p veilink-benches                 # 全部
cargo bench -p veilink-benches -- aead_seal    # 过滤
cargo bench -p veilink-benches -- --test       # 只跑一次，冒烟
```

基准使用**真实 API**（`AeadKey`、`SenderEphemeral`、`OneTimeKeyPair`、`derive_frame_material`、
`SessionCodec`、`BucketedPadding`），没有为了测量而重写任何原语。一次性密钥池在基准的
（不计时的）准备阶段自动补货，因此 `iter_batched` 的测量区域只包含被测操作。

注意：`benches/privacy.rs` 测的是**成本**，不是隐私效果；它不支持任何关于检测率的结论。

---

## 7. 已知限制

- **集成测试依赖 `curl`**：没有 `curl` 时 `tests/` 会失败（单元测试仍可运行）。
- **测试全部在回环上自建**：不访问互联网；因此它们不验证真实网络下的 MTU、丢包、NAT 或中间盒行为。
- **没有真实网络自动化测试**（见第 5 节），也没有性能回归门限（基准只测量，不做阈值比较）。
- **没有属性测试/fuzzing 目标**：边界由显式用例覆盖，但仓库中没有 `cargo-fuzz` 目标或模糊测试
  （`.gitignore` 中预留了 `/fuzz/`，但目录不存在）。
- **没有覆盖率统计配置**（无 `tarpaulin`/`llvm-cov` 配置或阈值）。
- **时间相关测试**：少量测试使用真实 `sleep`（空闲/退避/cancelled download），在极慢或极繁忙的
  CI 机器上可能变慢或有轻微抖动；超时值已按此设置为数秒级。测试 harness 已经处理了两类已知的
  竞态：`tests/src/settings.rs::bind_client_with_retry` 在探测端口被占用时换一个端口重试，
  `tests/end_to_end.rs` 在断言语义前轮询等待周期性统计 reporter（1 秒节拍）折入会话计数器。
- **测试用的 PSK 是固定值**（`tests/src/settings.rs` 的 `TEST_KEY`），它只保护测试流量，不保护
  任何真实数据。
- 服务端测试若需要访问 `127.0.0.1` 目标，必须打开 `allow_private_targets: true`——这是**测试专用**
  开关，生产环境保持 `false`。
