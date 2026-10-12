# Veilink

> **重要提示（必读）**
>
> Veilink 是一个**显式 HTTP 代理**：它只能处理**被明确发给它**的流量。任何绕开代理的连接，以及
> 代理之外的名称解析，都不受 Veilink 保护。具体来说，以下行为**必须由你自己逐项核对**：
>
> - **浏览器/操作系统的直连**：不把代理配置写全（例如只配了 HTTP 没配 HTTPS、填了"不使用代理"
>   列表、或应用忽略系统代理）时，流量会直接出去。
> - **DNS 预解析（prefetch / preconnect）与 DoH/DoT**：浏览器可能直接在本地查询域名，或把查询发给
>   DoH 服务商，这些查询完全绕过代理。PROXY 路径下 Veilink 客户端不做本地解析，但无法阻止浏览器
>   自己解析。
> - **UDP / QUIC（HTTP/3）**：Veilink **只承载 TCP**。浏览器启用 QUIC 时，HTTP/3 流量是 UDP，会
>   绕过代理直连；请确认浏览器的 QUIC/HTTP3 行为，必要时关闭它。
> - **非 HTTP 协议**：SSH、SMTP、BitTorrent 等不是 HTTP 代理流量，不会经过 Veilink（SSH-over-CONNECT
>   见"Git 代理配置"）。
>
> 结论：**"装了 Veilink"不等于"所有流量都被保护"**。请用日志中的 `route=DIRECT` / `route=PROXY`
> 以及网络抓包/浏览器开发者工具核对实际路径。

---

## 项目简介

Veilink 是一个面向隐私的**加密 HTTP/HTTPS 代理**。它由两部分组成：

- **客户端**：在本机监听一个普通 HTTP 代理端口（默认 `127.0.0.1:7890`），逐请求决定这条流量是
  **直连（DIRECT）** 还是**通过你的 VPS 转发（PROXY）**；
- **服务端**：运行在你的 VPS 上，认证客户端、**远端解析域名**、按出口策略连接目标，并在加密隧道
  与目标 socket 之间双向搬运字节。

两者之间的流量走 **VLP/1** 协议：一条经过 PSK 认证、绑定到具体 TLS 会话的连接，内部多路复用多个
流，并且**每一帧都使用由一次性 X25519 交换派生的独立密钥**（具备前向保密）。外层默认是
TLS 1.3 + HTTP/2，看起来像普通 HTTP/2 会话；也可以选择裸 TLS 帧流。

核心动机：让"目标域名"和"流量内容"对本地网络与中间网络不可见，同时**不把 VPS 变成进入它自己
内网或云元数据的跳板**（服务端默认拒绝 loopback / 私网 / link-local 等特殊用途地址）。

诚实说明：Veilink **不能**让你匿名、**不能**对抗流量分析或网站指纹、**不能**隐藏"你在使用 Veilink"。
完整的能力边界见 [安全模型](#安全模型) 与 [docs/privacy.md](docs/privacy.md)、
[docs/threat-model.md](docs/threat-model.md)。

---

## 功能列表

**协议与密码学**

- `VLP/1` 帧协议：`0x56` 版本字节、76 字节认证头（头部整体作为 AEAD associated data）、明文握手帧。
- 每帧前向保密：接收方一次性 X25519 密钥池（默认 256，批量发布 64/次，用完即毁），发送方每帧
  新建临时密钥。
- 背压式补货：由对端流量驱动 `KEY_OFFER` / `KEY_ACK`，没有独立定时器。
- 三种 AEAD 逐帧轮换：AES-256-GCM、ChaCha20-Poly1305、AES-128-GCM（接收方宣告集合内选择）。
- 控制通道哈希棘轮，认证成功后才推进。
- 重放/篡改/改标签/跨会话搬运拒绝；序号在 `u64::MAX` 处失败而不是回绕。
- 低阶与全零 X25519 公钥拒绝；tag 校验失败先擦除明文缓冲区。
- `zeroize` 擦除密钥；`Debug`/`Display` 全部脱敏；随机源失败即失败（无降级路径）。

**传输**

- TLS 1.3（rustls + ring），ALPN `h2` / `vlp/1`；`transport: h2`（默认）或 `tls`。
- HTTP/2 作为**承载**：一个长连接 `POST` + 流式响应体，VLP/1 负责真正的多路复用。
- 自签名证书 + TLS exporter 通道绑定：**认证靠 PSK，不靠 CA**；中继/重放握手无法通过。
- 服务端身份指纹（现仅记录在日志中，客户端 pinning 能力已实现但尚未接入配置）。

**客户端**

- HTTP/1.1 正向代理：absolute-form、origin-form、`CONNECT`、`Upgrade`（WebSocket）、chunked 与
  流式响应、keep-alive、上游连接复用。
- **字节级**实现：`CONNECT`/`101` 之后是裸字节拼接，不终止 TLS、不改写 URL、不缓存。
- 本地应答 `Expect: 100-continue`；剥离 hop-by-hop 头；保留/合成 `Host`。
- 白名单路由（`DOMAIN` / `DOMAIN-SUFFIX` / `IP` / `CIDR` / `*`），域名规范化（小写、去尾点、IDNA）。
- **fail closed**：命中白名单但隧道不可用时请求失败（502），**绝不回退直连**。
- PROXY 路径**不做本地 DNS 解析**，域名原样进入加密帧。
- 配置热重载（白名单原子替换；服务端/密钥/传输变化时重建会话）。
- 带抖动的指数退避重连（500 ms → 60 s）；断线期间白名单请求立即失败而不排队。

**服务端**

- **认证强制**：读取任何代理请求之前必须完成 VLP/1 握手；没有未认证模式，失败不提供预言机。
- 仅 IPv4 的远端 DNS（A 记录）+ 有界 TTL 缓存（默认 512 条）+ 超时/重试；不缓存否定结果。
- 出口策略默认拒绝 IANA 特殊用途 IPv4 网段：loopback、RFC 1918、link-local（含云元数据
  `169.254.169.254`）、CGNAT、benchmarking、documentation、组播与保留地址。
- `0.0.0.0/8`、`224.0.0.0/4`、`240.0.0.0/4`、`255.255.255.255/32`、`192.0.0.0/24` 即使打开
  `allow_private_targets` 也**始终拒绝**。
- 防 DNS rebinding：策略作用于**解析后的地址**，连接**已校验的地址**，公私混合解析结果整体拒绝。
- 可选目标端口白名单（`allowed_ports`，在解析前检查）。
- 每源 IP 连接速率限制、连接数上限、流数上限、头部/帧长度上限、空闲超时；周期统计日志。

**隐私（Strict Privacy 层，默认开启，不可配置）**

- 固定桶填充：`512/1024/2048/4096/8192` 与 8192 的倍数（上限 64 KiB），填充在 AEAD 内部；
  受预算约束时**降级到最小桶**而不是关闭。
- 发送批量合并：最多 16 帧 / 64 KiB 合并为一次写入。
- 空闲期 cover traffic：真实 VLP/1 应用帧，使用相同的每帧密码学；空闲 750 ms 后开始，
  每 1.5 s 一个突发、每突发最多 3 帧（64–4096 字节），最多 40 个突发后停止。
- 硬预算：cover 4 KiB/s 且每会话 256 MiB；padding 4 MiB/s（独立窗口）。
- `log.log_domains` 默认 `false`，目标打印为 `domain:<redacted>`；统计计数器不含域名或 URL。

**工程**

- 两套 YAML 配置，`deny_unknown_fields`，两阶段校验并**一次报告全部问题**。
- CLI：`veilink client` / `server` / `keygen` / `check`。
- 单元测试 + 集成测试（真实 `curl`、真实 TCP/TLS 源站、DNS stub、端到端隧道）+ Criterion 基准。
- GitHub Actions：fmt、clippy（`-D warnings`）、测试、release 构建、五平台交叉编译矩阵、
  非阻塞 `cargo audit`；`v*` 标签触发发布流程与 `SHA256SUMS`。

---

## 架构示意

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
                       DIRECT（本地 TCP，        │        │  PROXY（VLP/1 隧道，
                       系统 resolver）           │        │  域名原样加密，远端解析）
                                                ▼        ▼
                                        ┌──────────┐  ┌────────────────────────────┐
                                        │  Target  │  │ Secure Tunnel (TLS1.3/h2)  │
                                        └──────────┘  │  PSK 认证 + exporter 绑定   │
                                                      │  多路复用 + 每帧一次性密钥  │
                                                      └──────────────┬─────────────┘
                                                                     ▼
                                                        ┌──────────────────────────┐
                                                        │ VPS: veilink server      │
                                                        │  ├ 认证（无 PSK 即断开）  │
                                                        │  ├ 远端 DNS (A only)      │
                                                        │  ├ Egress Policy (拒私网) │
                                                        │  └ splice(隧道流, 目标)   │
                                                        └────────────┬─────────────┘
                                                                     ▼
                                                                  Target
```

一次明文 HTTP 请求在客户端内的顺序：读头部（有界）→ 解析 → 取 authority → 规范化目标 → 白名单
决策 → 打开字节管道（DIRECT 或 PROXY）→ 转发头部与 body（按定界精确转发）→ 读响应头（转发 1xx）→
转发响应 body → 决定是否 keep-alive。`CONNECT` 走单独路径：消费请求头 → 打开管道 → 回
`HTTP/1.1 200 Connection Established` → 裸字节拼接。详见 [docs/architecture.md](docs/architecture.md)。

---

## 系统要求

| 项目 | 要求 |
|------|------|
| Rust | 1.83 或更高（`rust-version = 1.83`），stable 工具链（仓库含 `rust-toolchain.toml`） |
| 平台 | Linux / macOS / Windows 均可编译；**服务端建议 Linux** |
| 系统库 | 不需要 OpenSSL：TLS 由 rustls + ring 提供（ring 会编译少量 C，需要可用的 C 工具链） |
| 网络 | 客户端与服务端之间需要 TCP 可达（默认 443）；服务端需要能出站访问任意公网 IPv4 与 UDP 53（DNS） |
| 特权 | 服务端监听 443 需要 root 或 `CAP_NET_BIND_SERVICE`（见 [Server 部署](#server-部署)） |
| 测试 | 集成测试需要 `curl` 可执行文件 |
| 不支持的 | IPv6 出口、UDP/QUIC 中继 |

---

## 编译方式

```bash
git clone https://github.com/veilink/veilink.git
cd veilink

# 发布构建（产物：target/release/veilink）
cargo build --release

./target/release/veilink --version
./target/release/veilink --help

# 校验两个示例配置（不启动任何东西）
./target/release/veilink check --config examples/client.yaml
./target/release/veilink check --config examples/server.yaml

# 测试（集成测试需要 curl）
cargo test --workspace

# 基准（可选，需要 criterion；只编译不运行用 --no-run）
cargo bench -p veilink-benches
cargo bench --no-run -p veilink-benches
```

发布构建使用 `lto = "thin"`、`codegen-units = 1`、`panic = "abort"`、剥离符号。二进制名固定为
`veilink`（Windows 上为 `veilink.exe`）。

---

## Server 部署

> 完整版（含备份、升级、防火墙细节、放在中间层后面的注意事项）见
> [docs/deployment.md](docs/deployment.md)。以下是可直接执行的最小步骤。

**1. 创建用户与目录（不要用 root 运行服务端）**

```bash
sudo useradd --system --home /var/lib/veilink --shell /usr/sbin/nologin veilink
sudo install -d -o veilink -g veilink -m 0700 /var/lib/veilink
sudo install -d -o root -g veilink -m 0750 /etc/veilink
sudo install -m 0755 target/release/veilink /usr/local/bin/veilink
```

**2. 生成认证密钥（只需一次，两侧相同）**

```bash
veilink keygen          # 默认 Base64URL；--encoding hex 输出十六进制
veilink keygen --output /etc/veilink/psk.txt   # 写入 0600 文件且拒绝覆盖
```

**3. 写配置**

```bash
sudo install -o root -g veilink -m 0640 examples/server.yaml /etc/veilink/server.yaml
sudoedit /etc/veilink/server.yaml
```

```yaml
listen: "0.0.0.0:443"
key: "<veilink keygen 的输出>"
state_dir: "/var/lib/veilink"
# 推荐：限制客户端可访问的目标端口
allowed_ports: [80, 443]
```

首次启动会在 `state_dir` 生成 `identity.key`（0600）、`tls_cert.pem`、`tls_key.pem`（0600）。

**4. systemd 单元**（关键部分；完整加固版见 deployment 文档）

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

# 监听 443 所需的最小权限：root 或其他方式见下
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# 加固
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

**为什么 443 需要特权**：Linux 默认只允许 `CAP_NET_BIND_SERVICE`（历史上仅 root）绑定 1024 以下
端口。除了上面的 systemd capability，还可以：设置
`net.ipv4.ip_unprivileged_port_start=443`，或监听高端口 + 防火墙 REDIRECT。
**不要以 root 直接运行服务端。**

**防火墙**：只放行入站 443（保留你的 SSH 规则），出站按需放行。示例（nftables）：

```nft
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif "lo" accept
    ct state established,related accept
    tcp dport 22 accept      # 按需修改
    tcp dport 443 accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output priority 0; policy accept; }
}
```

**状态目录与备份**：`state_dir` 只包含 `identity.key`、`tls_cert.pem`、`tls_key.pem`。
**要保留相同服务器指纹就必须备份 `identity.key`**；删除它会生成全新身份。备份文件含私钥，必须
按机密对待（并注意服务端会拒绝加载对 group/other 可读的 `identity.key`）。

**放在中间层后面**：**只支持 L4（TCP/SNI）透传**。VLP/1 认证绑定在外层 TLS 会话的 exporter 上，
只有终止 TLS 的端点能算出它；nginx `proxy_pass` / HAProxy `mode http` 这类**终止式 TLS 卸载不支持**。
详见 [docs/deployment.md](docs/deployment.md) 第 8 节。

---

## Client 部署

**1. 拿到二进制**：解压发布归档，或 `cargo build --release` 后使用 `target/release/veilink`。

**2. 配置**

```bash
cp examples/client.yaml client.yaml
$EDITOR client.yaml
```

```yaml
server: "203.0.113.10:443"      # 你的 VPS 地址（域名或 IPv4 字面量）
key: "<与服务端完全相同的 key>"
whitelist:
  - "DOMAIN,github.com"
  - "DOMAIN-SUFFIX,githubusercontent.com"
  - "CIDR,140.82.112.0/24"
# 可选：
# listen: "127.0.0.1:7890"
# transport: h2                 # 或 tls，必须与服务端一致
```

**3. 校验并运行**

```bash
veilink check --config client.yaml --verbose

# 前台运行（Ctrl-C 退出）
veilink client --config client.yaml

# 或作为用户服务（systemd --user）
# veilink client --config ~/.config/veilink/client.yaml --no-reload
```

启动日志会打印：监听地址、远端地址、白名单规则数，以及
`configure your application to use http://127.0.0.1:7890 as its HTTP and HTTPS proxy`。
随后每个请求会打印一行 `route=DIRECT` 或 `route=PROXY`（开启 `log_domains` 时才含域名）。

**安全提醒**：`listen` 默认绑定 `127.0.0.1`，**不要**改成 `0.0.0.0`——那会把你的代理开放给整个
局域网/公网（Veilink 的本地代理不做客户端认证）。

---

## 认证密钥生成

```bash
veilink keygen
# 34Xv...（Unpadded Base64URL，43+ 字符，解码后 32 字节 = 256 bit）

veilink keygen --encoding hex          # 64 个十六进制字符
veilink keygen --count 3               # 一次 3 个（1–64）
veilink keygen --output key.txt        # 写入文件，Unix 上权限 0600；已存在则拒绝，--force 覆盖
veilink keygen --quiet                 # 只输出密钥
```

要求与注意事项：

- 密钥必须是**高熵随机值**，不是口令。`Psk::parse` 会拒绝长度不足、单字节重复、全零、
  ≤8 字节周期重复、以及不同字节值过少的输入，并提示你运行 `veilink keygen`。
- 客户端与服务端必须使用**完全相同**的 `key`。
- 密钥是**对称共享秘密**：任何持有它的人都能使用你的服务器，也能冒充它。泄露后必须**两侧同时**
  更换（当前没有平滑轮换机制）。
- 服务端日志中的身份指纹可以人工核对；客户端 pinning 能力已实现但**尚未接入配置**。

---

## YAML 白名单示例

```yaml
whitelist:
  # 精确匹配：只有 github.com 本身
  - "DOMAIN,github.com"
  # 域名及其全部子域（按 DNS label 边界，不会匹配 fakegithub.com）
  - "DOMAIN-SUFFIX,githubusercontent.com"
  # 单 label 通配：匹配 api.dev.example.com，不匹配 api.example.com
  - "DOMAIN,api.*.example.com"
  # 仅匹配 IPv4 字面量目标
  - "IP,1.1.1.1"
  # IPv4 网段（主机位会被规范化）
  - "CIDR,140.82.112.0/24"
  # 兜底：所有流量都走服务端（按需启用）
  # - "*"
```

规则语义要点：

- 规则**按顺序**求值，**第一个匹配者胜出**；`whitelist` 为空表示**全部 DIRECT**。
- 域名目标只与 `DOMAIN`、`DOMAIN-SUFFIX`、`*` 比较；IPv4 字面量只与 `IP`、`CIDR`、`*` 比较。
  因此 `IP`/`CIDR` **不会**为了匹配而触发本地 DNS 解析。
- 匹配前统一规范化：去空白、去一个尾点、转小写、非 ASCII label 转 IDNA A-label。
- 重复规则（按规范化标识）会被拒绝。
- 完整语法、错误信息与全部配置字段见 [docs/configuration.md](docs/configuration.md)。

---

## curl 测试

确保客户端在运行，且 `whitelist` 覆盖你要测试的目标。

```bash
# 1) 基本连通性（DIRECT 或 PROXY 取决于白名单）
curl -x http://127.0.0.1:7890 http://example.com/ -o /dev/null -w '%{http_code}\n'

# 2) HTTPS（CONNECT 隧道；Veilink 不终止 TLS）
curl -x http://127.0.0.1:7890 https://github.com/ -o /dev/null -w '%{http_code}\n'

# 3) 确认走了哪条路径：客户端日志会打印 route=PROXY / route=DIRECT
curl -x http://127.0.0.1:7890 -v https://github.com/ 2>&1 | grep -E 'CONNECT|200 Connection'

# 4) 大文件完整性（对比直连与走代理的 sha256）
curl -x http://127.0.0.1:7890 https://raw.githubusercontent.com/.../file.bin -o via-proxy.bin
curl                       https://raw.githubusercontent.com/.../file.bin -o direct.bin
sha256sum via-proxy.bin direct.bin

# 5) 上传与流式响应
curl -x http://127.0.0.1:7890 -X POST --data-binary @some-file.txt http://example.com/upload

# 6) 确认 fail-closed：把 server 指向一个不可达地址（或停掉 VPS），
#    白名单命中的请求应当失败（502），而不是直连成功
curl -x http://127.0.0.1:7890 https://github.com/ -o /dev/null -w '%{http_code}\n'
```

**核对清单**（比"能打开网页"更重要）：

1. 日志里出现的是 `route=PROXY`，而不是 `route=DIRECT`；
2. 在 VPS 上抓包/看日志，确认目标连接确实由 VPS 发起；
3. 把 VPS 停掉后，白名单请求**失败**（证明没有回退直连）；
4. 用 `dig`/`tcpdump` 确认本地 resolver 没有出现被代理的域名；
5. 关掉浏览器的 QUIC/HTTP3，确认没有绕过代理的 UDP 流量。

---

## 浏览器代理配置

**Firefox**

1. 设置 → 网络设置 → 手动配置代理；
2. HTTP 代理填 `127.0.0.1` 端口 `7890`；**同时勾选 "也将此代理用于 HTTPS"**；
3. "不使用代理"列表**留空**（填入的域名会绕过 Veilink）；
4. 建议在 `about:config` 中确认 `network.proxy.allow_hijacking_localhost` 等设置符合预期；
5. `about:config` 中可把 `network.http.http3.enable` 设为 `false` 以避免 QUIC 绕过。

**Chrome / Edge / Chromium**

- 使用系统代理（见下），或启动参数：
  ```bash
  google-chrome --proxy-server="http://127.0.0.1:7890"
  ```
- `chrome://flags/#enable-quic` 设为 `Disabled`，避免 HTTP/3 走 UDP 绕过代理。

**macOS**：系统设置 → 网络 → 详细信息 → 代理 → 勾选 **网页代理 (HTTP)** 与
**安全网页代理 (HTTPS)**，服务器 `127.0.0.1`、端口 `7890`，并清空"忽略这些主机与域名的代理设置"。

**Windows**：设置 → 网络和 Internet → 代理 → 手动设置代理 → 地址 `127.0.0.1`、端口 `7890`，
"对于本地地址不使用代理服务器"按需取消。

**务必核对**：只配 HTTP 不配 HTTPS 是常见错误，会让所有 HTTPS 直连；填了绕过列表同理。
请用浏览器开发者工具或抓包确认连接确实到了 `127.0.0.1:7890`。

---

## Git 代理配置

**HTTPS 远端（`https://github.com/...`）**

```bash
# 全局
git config --global http.proxy  http://127.0.0.1:7890
git config --global https.proxy http://127.0.0.1:7890

# 只对某个仓库/域名
git config --global http.https://github.com/.proxy http://127.0.0.1:7890

# 取消
git config --global --unset http.proxy
git config --global --unset https.proxy

# 测试
GIT_CURL_VERBOSE=1 git ls-remote https://github.com/veilink/veilink.git | head
```

请确认 `whitelist` 覆盖 `github.com` 与 `githubusercontent.com`
（`DOMAIN,github.com` + `DOMAIN-SUFFIX,githubusercontent.com` + `DOMAIN-SUFFIX,githubassets.com`）。

**SSH 远端（`git@github.com:...`）**：Git 的 HTTP 代理配置**不影响 SSH**。有两种做法：

1. 改用 HTTPS 远端（推荐；同时受白名单与代理覆盖）：
   ```bash
   git remote set-url origin https://github.com/veilink/veilink.git
   ```
2. 让 SSH 走 CONNECT（需要 `netcat` 支持 `-X connect`），在 `~/.ssh/config` 中：
   ```
   Host github.com
     ProxyCommand nc -X connect -x 127.0.0.1:7890 %h %p
   ```
   注意：此时白名单要能匹配 `github.com`，且服务端的 `allowed_ports` 必须允许 **22** 端口
   （默认空表示允许全部；若你限制为 `[80,443]`，这条会失败）。

---

## 常见问题

**Q：某个网站没有走代理。**
A：先看客户端日志的 `route=`。`route=DIRECT` 表示白名单没有命中——检查规则类型
（`DOMAIN` 只匹配精确主机；子域要用 `DOMAIN-SUFFIX`）与域名规范化（IDNA/尾点/大小写）。
浏览器预解析、DoH、QUIC、绕过列表也可能造成"看起来没走代理"。

**Q：浏览器报"代理服务器拒绝连接"。**
A：客户端没在运行、`listen` 与浏览器配置不一致，或端口被占用。

**Q：白名单命中的请求返回 502。**
A：这是**设计行为（fail closed）**：隧道不可用、服务端拒绝出口策略、或远端解析失败都会返回 502，
而不是回退直连。查看客户端与服务端日志中的具体原因（`egress policy denied` / `remote DNS
resolution failed` / `cannot establish a secure session`）。

**Q：支持 IPv6 吗？**
A：**不支持**。IPv6 字面量在规则解析、请求目标解析与远端解析三处都被显式拒绝；服务端只有 IPv4
出口。

**Q：支持 UDP / HTTP3 / QUIC 吗？**
A：**不支持**。Veilink 只承载 TCP。浏览器启用 QUIC 时 HTTP/3 会绕过代理，请关闭它。

**Q：为什么连接大约 5 分钟就断？**
A：空闲超时（`limits.idle_timeout_ms` 默认 300000）。当前**没有**定时 keepalive，空闲会话会被关闭；
重新自动建立即可。

**Q：为什么空闲时也有流量？**
A：Strict Privacy 层的 cover traffic（空闲 750 ms 后开始、最多约 60 秒、有速率与总额双预算），
用于削弱"完全静默"这一信号。它不影响你的目标域名或内容。

**Q：多个客户端能用同一个 key 吗？**
A：可以，但它们是等价的：服务端**没有按客户端的身份、配额或吊销**。要移除某个客户端只能轮换
PSK（会影响所有客户端）。

**Q：服务端能看到我访问什么吗？**
A：能。服务端是出口，会看到所有 **PROXY** 目标的域名与端口（它负责远端解析），也能看到明文 HTTP
的内容。DIRECT 流量与服务端无关；HTTPS 内容由你与目标端到端加密，服务端看不到。

**Q：`veilink check` 报错怎么办？**
A：它会一次列出**所有**问题，格式为 `字段: 原因`（例如 `whitelist[2]`、`key`、`dns.servers[0]`）。
逐条修正即可；`--verbose` 可以打印生效设置（密钥永不打印）。

**Q：能承受多少并发？**
A：默认 `max_connections: 1024`、`max_streams_per_session: 512`、单帧最大 64 KiB 净荷、
单流单帧 16 KiB。这些上限是有意保守的，可按需调整（见 configuration 文档）。

---

## DNS 隐私边界

| 场景 | 谁解析 | 本地 resolver 是否看到域名 |
|------|--------|--------------------------|
| 白名单命中的域名（PROXY） | **服务端**（仅 A 记录） | **否** |
| 白名单命中的 IPv4 字面量 | 无需解析 | 否 |
| 未命中白名单的域名（DIRECT） | 客户端系统 resolver | **是** |
| 白名单命中但隧道不可用 | 不解析，直接失败 | 否 |
| 客户端到服务端的连接（`server` 写域名时） | 客户端系统 resolver | 是（看到 VPS 域名） |

必须自己核对的泄露路径：

- 浏览器/操作系统的 **DNS 预解析**可能直接查询本地 resolver；
- 浏览器启用 **DoH/DoT** 时，查询由浏览器直接发往 DoH 服务商，完全不经代理；
- 应用忽略代理设置，或使用非 HTTP 协议；
- **DIRECT 路径**的域名与明文内容对本地 resolver、ISP 与网络观察者可见（这就是"直连"的定义）；
- 服务端侧域名对 VPS 运营者可见（它本来就需要知道）。

服务端解析器只查 A 记录（无 IPv6），TTL 钳制在 5 秒–1 小时，默认超时 5 秒、尝试 2 次，不缓存
否定结果。详见 [docs/privacy.md](docs/privacy.md)。

---

## 安全模型

**受保护的（在代码中可核对）**

- 内容机密性与完整性：正文、方法、URL、头部、Cookie、目标域名与端口都在 AEAD 密文内；
  76 字节头部整体作为 AAD，任一字段被改动都会失败。
- 对端认证：PSK 绑定的握手 + TLS exporter 通道绑定。无 PSK 无法完成握手；中继、透明代理、重放
  录制握手都会失败；没有降级路径。
- 每帧前向保密：每帧来自一次性 X25519 交换，接收方私钥用后即毁。事后拿到 PSK 或服务端长期身份
  私钥**不能**解密已录制的应用帧。
- 重放与协议混淆拒绝：序号 + 一次性密钥（应用帧）、哈希棘轮（控制帧）、AAD 绑定（改标签/跨会话）。
- 目标域名的本地隐藏：PROXY 路径客户端不做本地解析。
- 出口约束：默认拒绝 loopback/私网/link-local/云元数据等特殊用途地址；连接已校验的地址；
  公私混合解析结果整体拒绝；可选端口白名单；资源上限。
- fail closed 路由：白名单命中而隧道不可用时请求失败，绝不回退直连。
- 密钥卫生：日志/Debug 脱敏、私钥文件 0600、不安全的 `identity.key` 拒绝启动、
  tag 失败先擦除缓冲区。

**明确不保护的（必须向用户说明）**

- **元数据**：服务端 IP/端口、TLS 握手（含自签名证书与 SNI）、连接时序、帧数、桶化长度、
  方向与序号，以及**"正在使用 Veilink"这一事实**。
- **可见性识别**：帧头（`0x56`）、ALPN、`veilink.invalid`、自签名证书都是强特征。
  **不声称零检测率**。
- **流量关联与网站指纹**：填充只粗化长度；cover 只覆盖空闲期（约 60 秒后停止）；
  节奏整形**当前不生效**。仓库中**没有任何**检测率评估。**不声称不可指纹化**。
- **匿名性**：服务端知道你的 IP，网络观察者知道你与它的关系。**不声称绝对匿名或不可追踪**。
- **端点安全**：客户端主机或 VPS 被入侵后一切失效；软件擦除无法对抗内存快照、swap、休眠镜像或
  hypervisor。
- **服务端作恶**：它能看 PROXY 目标域名与明文 HTTP 内容，能篡改/丢弃流量。
- **认证以外的授权**：PSK 持有者完全等价；没有按客户端配额或吊销。
- **抗审查可用性**：没有域前置/流量伪装保证；被阻断时没有后备通道。
- **抗量子**：X25519 不抗量子，没有 PQ 混合。

**软件擦除的现实边界**：`zeroize` 只能覆盖它控制的内存。内存快照、交换分区、休眠镜像、核心转储、
被攻陷的主机或 hypervisor 都可以在擦除**之前**捕获秘密。前向保密只在"私钥确实已被擦除，且攻击者
没有在擦除前获得内存访问"的前提下成立。建议：全盘加密、禁用休眠、限制/加密 swap、保护主机。

完整分析见 [docs/cryptography.md](docs/cryptography.md)、[docs/privacy.md](docs/privacy.md)、
[docs/threat-model.md](docs/threat-model.md) 与 [SECURITY.md](SECURITY.md)。

---

## 未实现 / 当前限制

- **IPv6 不支持**（无 IPv6 出口；IPv6 字面量被显式拒绝）。
- **UDP / QUIC / HTTP3 不支持**（只有 TCP）。
- **没有终止式 TLS 卸载支持**：中间层只能做 L4（TCP/SNI）透传。
- **没有按客户端的身份、配额或吊销**；PSK 轮换不平滑（需两侧同时更换）。
- **服务端身份 pinning 未接入客户端配置**（能力已实现，`expected_identity` 恒为 `None`）。
- **发送节奏整形当前不生效**：批量合并生效，但调度器的 `delay()` 不会被 writer 应用
  （睡眠条件与策略返回值互斥，见 [docs/privacy.md](docs/privacy.md) 第 3.2 节）。
- **cover traffic 只覆盖空闲期**且最多约 60 个突发后停止；不是恒定速率生成器。
- **没有定时 keepalive**：空闲会话由 `idle_timeout` 关闭。
- **没有内建指标端点 / 管理接口**（只有周期统计日志）。
- **`ERROR`（`0x7f`）消息从不发送**；`SequenceMode::Exact` 未被会话编解码器使用。
- **没有抗流量分类/指纹评估**，也没有真实网络下的检测率数据。
- 集成测试依赖 `curl`；当前仓库**没有**自动化的真实网络（如 GitHub）测试（见
  [docs/testing.md](docs/testing.md)）。

---

## 许可证

MIT License。详见 [LICENSE](LICENSE)。

Copyright (c) 2026 The Veilink Contributors.
