# 配置参考

Veilink 有两个配置文件，字段极少，其余全部是协议的一部分并且始终生效。

- 客户端示例：[`examples/client.yaml`](../examples/client.yaml)
- 服务端示例：[`examples/server.yaml`](../examples/server.yaml)
- 解析与校验实现：[`crates/veilink-config/src/client.rs`](../crates/veilink-config/src/client.rs)、
  [`server.rs`](../crates/veilink-config/src/server.rs)、
  [`common.rs`](../crates/veilink-config/src/common.rs)、
  [`validate.rs`](../crates/veilink-config/src/validate.rs)

**关于未知字段**：两个配置结构的顶层与每个嵌套节（`log`、`limits`、`dns`）都使用
`#[serde(deny_unknown_fields)]`。拼错的字段名会导致加载失败，而不是被静默忽略。

**关于校验的两个阶段**：`load`/`from_yaml` 只做 YAML 解码（含未知字段拒绝）；`validate` 才检查
每个取值，并且**一次报告全部问题**（`Diagnostics`），这正是 `veilink check` 的输出。

---

## 1. `client.yaml`

### 1.1 必填字段

| 字段 | 类型 | 默认 | 含义 |
|------|------|------|------|
| `server` | string | **必填** | VPS 地址，写作 `HOST:PORT`。`HOST` 可以是 IPv4 字面量或域名。**不接受 IPv6**（`[...]` 或含 `::` 一律拒绝）；端口不能为 0。 |
| `key` | string | **必填** | 认证密钥，必须与服务端完全相同。接受 64+ 个十六进制字符（偶数长度）或标准 Base64URL（RFC 4648 §5，无填充，≥43 字符），解码后至少 32 字节（256 bit）。此外会做低熵健全性检查：拒绝单字节重复、全零、≤8 字节周期重复、以及不同字节值过少的输入。用 `veilink keygen` 生成。 |

### 1.2 路由

| 字段 | 类型 | 默认 | 含义 |
|------|------|------|------|
| `whitelist` | list of string | `[]` | 白名单规则（见第 3 节）。命中任一规则的请求走服务端（`PROXY`），其余直连（`DIRECT`）。**空列表意味着所有请求都直连**，此时不会有任何流量使用服务端。规则在启动时编译一次，热重载时原子替换。 |

### 1.3 可选字段

| 字段 | 类型 | 默认 | 含义 |
|------|------|------|------|
| `listen` | string | `"127.0.0.1:7890"` | 本地代理监听地址。必须是 `IP:PORT`（`parse_listen` 用 `SocketAddr` 解析），因此 `localhost:7890` 会被拒绝——请写 `127.0.0.1:7890`。默认只监听回环，不对局域网开放。 |
| `transport` | `h2` \| `tls` | `h2` | 外层承载方式。两者运行完全相同的 VLP/1；`h2` 让外层看起来像普通 HTTP/2 会话，`tls` 是更低开销的直连帧流。**必须与服务端一致**（服务端按配置选择，不做自动降级）。 |
| `server_name` | string | `server` 的域名；若 `server` 是 IPv4 字面量则为 `"veilink.local"` | TLS SNI / 证书名。非空；若为域名则按 `HostName` 规范化（IDNA、小写、去尾点），若为 IP 字面量则原样接受。 |
| `server_identity_pin` | string \| 缺省 | 缺省（不 pin） | 固定服务端长期身份指纹。接受 64 位十六进制完整指纹，或较短前缀（`aabbccdd`、`aa:bb:cc:dd`，至少 4 字节）。指纹取自 `veilink server` 启动日志的 `identity=` 字段（也接受 `short=` 形式的前缀）。**设置后，若服务端出示的身份不匹配，连接在任何流量转发之前被拒绝**（`UplinkError::IdentityMismatch`），把"VPS 被换掉"从静默事件变成可见故障。解析失败会在 `veilink check` 中报 `server_identity_pin` 诊断。 |
| `state_dir` | path | 平台状态目录（见下） | 客户端配置中的状态目录。**当前客户端不向其中写入任何文件**：`veilink-client` 的代码从不读取或创建它，只有 `veilink check --verbose` 会打印它。该字段是为将来的会话缓存保留的。 |
| `log` | mapping | 见 1.4 | 日志配置。 |
| `limits` | mapping | 见 1.5 | 资源上限。 |

`state_dir` 默认值解析顺序（`default_state_dir()`）：
`$VEILINK_STATE_DIR` → （Windows）`%APPDATA%\veilink` → （macOS）`~/Library/Application Support/veilink`
→ （其它 Unix）`$XDG_STATE_HOME/veilink` → `~/.local/state/veilink` → `./state`。

### 1.4 `log`（客户端与服务端相同）

| 字段 | 类型 | 默认 | 含义 |
|------|------|------|------|
| `level` | string \| 缺省 | 缺省 | 日志级别过滤，等价于 `RUST_LOG`。解析优先级：`RUST_LOG` 环境变量 > `log.level` > 内置默认 `info`（`veilink check` 的默认是 `warn`）。 |
| `format` | `text` \| `json` | `text` | 输出格式。`json` 输出按行 JSON（不含 span 列表）。 |
| `log_domains` | bool | `false` | 为 `true` 时把目标**域名**写入日志；默认 `false`，此时目标打印为 `domain:<redacted>`（IP 字面量仍会打印，因为它不是域名）。**头部与正文内容在任何情况下都不会被记录。** |

### 1.5 `limits`（客户端与服务端共用同一结构）

| 字段 | 类型 | 默认 | 含义 |
|------|------|------|------|
| `max_connections` | integer | `1024` | 同时接受的连接数上限（客户端为本地连接；服务端为外层连接）。超限直接拒绝。 |
| `max_streams_per_session` | integer | `512` | 单个会话内并发流上限（用作 `SessionConfig::max_streams`，也是入站流信道容量）。 |
| `connect_timeout_ms` | integer | `10000` | 出站 TCP 连接超时（客户端直连与 uplink；服务端 egress）。 |
| `idle_timeout_ms` | integer | `300000` | 空闲超时。客户端用于等待下一个请求头；会话读任务用它关闭空闲会话，且运行时把它抬到至少 60000 ms。 |
| `max_header_bytes` | integer | `65536` | 单个 HTTP 请求/响应头的最大重装字节数。超限返回错误并关闭连接。 |
| `accept_rate_per_second` | integer | `64` | **服务端专用**：每个源 IP 每秒允许的新外层连接数（窗口 1 秒，在服务端 runtime 中实现）。客户端接受该字段但**不使用**它。 |

---

## 2. `server.yaml`

### 2.1 必填字段

| 字段 | 类型 | 默认 | 含义 |
|------|------|------|------|
| `key` | string | **必填** | 与客户端完全相同的认证密钥（解析规则同 1.1）。 |

### 2.2 可选字段

| 字段 | 类型 | 默认 | 含义 |
|------|------|------|------|
| `listen` | string | `"0.0.0.0:443"` | 监听地址，`IP:PORT`（`SocketAddr` 解析）。端口 0 被拒绝。绑定 443 需要特权或 `CAP_NET_BIND_SERVICE`（见 `docs/deployment.md`）。 |
| `transport` | `h2` \| `tls` | `h2` | 外层承载方式，必须与客户端一致。 |
| `state_dir` | path | 平台状态目录（同 1.3） | 存放长期身份与 TLS 证书/私钥的目录。 |
| `allow_private_targets` | bool | `false` | 为 `true` 时允许连接 loopback、RFC 1918 私网、link-local 等特殊用途地址。**仅供本地集成测试**；启动时会打印警告。即使为 `true`，`0.0.0.0/8`、`224.0.0.0/4`、`240.0.0.0/4`、`255.255.255.255/32`、`192.0.0.0/24` 仍然被拒绝。 |
| `allowed_ports` | list of integer | `[]` | 允许客户端连接的目标端口。**空列表表示允许全部端口**。非空时只有列表中的端口可通过；端口 0 与重复项在校验阶段报错。端口检查在 DNS 解析之前执行。 |
| `dns` | mapping | 见 2.3 | 远端解析器配置。 |
| `limits` | mapping | 见 1.5 | 资源上限（服务端使用其中全部字段，含 `accept_rate_per_second`）。 |
| `log` | mapping | 见 1.4 | 日志配置。 |

### 2.3 `dns`

| 字段 | 类型 | 默认 | 含义 |
|------|------|------|------|
| `servers` | list of string | `[]` | 上游 DNS 服务器，写作 `IP` 或 `IP:PORT`（缺省端口 53）。**空列表表示使用系统 resolver**（读取 `/etc/resolv.conf` 等）。条目必须是合法 IP，不能用 unspecified 地址，端口不能为 0。仅使用 **UDP** 查询。 |
| `cache_size` | integer | `512` | TTL 缓存条目上限（LRU 淘汰）。必须 > 0。 |
| `timeout_ms` | integer | `5000` | 单次查询超时。必须 > 0。 |
| `attempts` | integer | `2` | 单次解析的尝试次数。至少为 1。 |

解析器只查询 **A 记录**（IPv4），因为本版本没有 IPv6 出口；TTL 被钳制在 5 秒到 1 小时之间；
**不缓存否定结果**。

---

## 3. 白名单规则语法

规则是字符串，写在 `whitelist:` 列表中。规则种类不区分大小写（`DOMAIN`/`domain` 等价），
值在匹配前会被规范化。

### 3.1 规则类型

| 写法 | 语义 | 示例 |
|------|------|------|
| `DOMAIN,<host>` | **精确**匹配该主机名。允许 `*` 作为**整个** DNS label 出现（可多次），`*` 恰好匹配一个 label。 | `DOMAIN,github.com`、`DOMAIN,api.*.example.com` |
| `DOMAIN-SUFFIX,<domain>` | 匹配该域名**及其所有子域**，按 DNS label 边界（不是字符串后缀）。不允许 `*`。 | `DOMAIN-SUFFIX,github.com` 匹配 `github.com`、`api.github.com`，不匹配 `fakegithub.com` |
| `IP,<ipv4>` | 精确匹配 **IPv4 字面量**目标。不允许 `/`。 | `IP,1.1.1.1` |
| `CIDR,<ipv4>/<0-32>` | 匹配 IPv4 网段。必须带 `/`。主机位会被规范化（`140.82.112.5/24` 等同 `140.82.112.0/24`）。 | `CIDR,140.82.112.0/24` |
| `*` | 兜底规则：**全部**流量走服务端。 | `*` |

（`*,*` 在解析上等价于 `*`，二者的规范化标识相同，因此同时出现会报"重复规则"。）

### 3.2 匹配语义

1. 规则按声明顺序求值，**第一个匹配者胜出**（OR 语义），其索引会出现在日志/决策中。
2. **目标形式决定参与比较的规则类型**，避免为了评估规则而做 DNS 解析：
   - 域名目标只与 `DOMAIN`、`DOMAIN-SUFFIX`、`*` 比较；
   - IPv4 字面量目标只与 `IP`、`CIDR`、`*` 比较。
   因此 `IP,1.1.1.1` **不会**匹配域名 `1.1.1.1.example.com`，域名也不会被预先解析。
3. **空白名单 = 全部 DIRECT**。
4. **重复规则被拒绝**：按规范化标识判重，因此 `DOMAIN,GitHub.com` 与 `domain,github.com.` 被视为
   同一条规则（会报错并给出两个位置）。不同类型不算重复。
5. **fail closed**：命中白名单但隧道不可用时请求失败，**绝不回退直连**。

### 3.3 规范化（匹配前统一进行）

1. 去掉首尾 ASCII 空白；
2. 去掉**一个**结尾根点（`example.com.` ≡ `example.com`；`..` 报错）；
3. 转小写（DNS 大小写不敏感，RFC 4343）；
4. 每个非 ASCII label 转成 IDNA A-label（punycode，RFC 5890 / UTS #46）：
   `bücher.example` ≡ `xn--bcher-kva.example`；
5. label 只允许 ASCII 字母数字、`-`、`_`；label 长度 ≤ 63 字节；完整域名长度 ≤ 253 字节；
   不允许空 label（`a..b`、`.example.com` 报错）。

`DOMAIN-SUFFIX` 使用 label 边界比较（`HostName::is_subdomain_of`），因此
`github.com.attacker.example` 与 `evilgithub.com` 都不会匹配 `DOMAIN-SUFFIX,github.com`。

### 3.4 常见解析错误

| 输入 | 错误信息要点 |
|------|-------------|
| ``（空） | `rule is empty` |
| `github.com` | 必须写成 `TYPE,VALUE` 或裸 `*` |
| `DOMAIN,` | `rule type 'DOMAIN' is missing a value` |
| `BOGUS,x` | `unknown rule type`（列出允许的类型） |
| `DOMAIN-SUFFIX,*.github.com` | `DOMAIN-SUFFIX does not support wildcards` |
| `IP,140.82.112.0/24` | `use CIDR for network ranges` |
| `CIDR,1.1.1.1` | `use IP for a single address` |
| `DOMAIN,::1` / `CIDR,2001:db8::/32` | `IPv6 target ... is not supported by this release` |
| `DOMAIN,a..b` | `domain contains an empty label` |
| `DOMAIN,a*b.com` | `* must occupy a whole DNS label` |
| `DOMAIN,a,b` | `too many fields` |

### 3.5 示例

```yaml
whitelist:
  # 只要 github.com 本身（不含子域）
  - "DOMAIN,github.com"
  # github.com 及其全部子域（label 边界）
  - "DOMAIN-SUFFIX,githubusercontent.com"
  # 单 label 通配：匹配 api.dev.example.com，不匹配 api.example.com
  - "DOMAIN,api.*.example.com"
  # 仅 IPv4 字面量
  - "IP,1.1.1.1"
  # IPv4 网段
  - "CIDR,140.82.112.0/24"
  # 全部走服务端（按需取消注释）
  # - "*"
```

---

## 4. `veilink check` 的行为

```text
veilink check --config FILE [--type auto|client|server] [--verbose]
```

| 参数 | 默认 | 含义 |
|------|------|------|
| `--config`, `-c FILE` | 必填 | 要校验的配置文件。 |
| `--type` | `auto` | 强制 schema。`auto` 用内容探测：忽略注释与空行后，若存在以 `server:` 或 `whitelist:` 开头的行则按 **client** 校验，否则按 **server** 校验（`client.yaml` 必须有 `server`，而 `server.yaml` 会把 `server` 当作未知字段拒绝，因此两者不会混淆）。 |
| `--verbose` | 关 | 校验通过后打印生效设置（`server`、`server_name`、`listen`、`transport`、`state_dir`、**`identity pin`**、规则数量与每条规则；服务端打印 egress 策略、允许端口、DNS、连接/流上限）。`identity pin` 一行会明确显示已 pin 的指纹，未设置时显示 `(not set: only the PSK is trusted)`——因为"是否 pin 了服务端身份"是安全相关设置，不应该只能靠人眼在 YAML 里找。**密钥永远不会被打印。** |

行为：

- 只读取并校验，不启动任何监听、不建立任何连接、不创建 `state_dir`。
- 先做 YAML 解码（未知字段、类型错误在这里失败），再做字段级校验。
- **一次报告所有问题**，每条形如 `字段: 原因`，例如：
  ```
  error: `client.yaml` is not valid:
    3 configuration problems:
    - whitelist[0]: rule `BOGUS,a`: unknown rule type `BOGUS`; expected one of DOMAIN, DOMAIN-SUFFIX, IP, CIDR or `*`
    - whitelist[1]: rule `DOMAIN,a..b`: domain contains an empty label
    - key: authentication key is only 6 bytes after decoding, but at least 32 bytes (256 bits) are required; run `veilink keygen` to create a suitable key
  ```
- 成功时输出：`OK: `FILE` is a valid Veilink client configuration.`（或 `server`）。
- 退出码：有效为 `0`；文件无法读取、YAML 无效或校验失败为非 0。
- 日志：`check` 以默认级别 `warn` 初始化日志，因此正常校验不会产生日志噪声。

### 4.1 被校验的内容

**client.yaml**：`server`（格式与 IPv6 拒绝）、`listen`、`key`、`whitelist[i]`（逐条）、
`whitelist`（重复规则）、`server_name`。

**server.yaml**：`listen`（含端口 0）、`key`、`allowed_ports[i]`（端口 0、重复）、
`dns.servers[i]`（必须是合法 IP、不能 unspecified、端口非 0）、`dns.timeout_ms > 0`、
`dns.attempts ≥ 1`、`dns.cache_size > 0`、`limits.max_connections > 0`、
`limits.max_streams_per_session > 0`、`limits.connect_timeout_ms > 0`。

> 注意：服务端校验**没有**检查 `limits.idle_timeout_ms`、`limits.max_header_bytes`、
> `limits.accept_rate_per_second` 是否为 0。`accept_rate_per_second = 0` 在运行时的含义是
> **不限制**（`RateLimiter::allow` 在 `limit == 0` 时直接返回 `true`）；
> `idle_timeout_ms` 与 `max_header_bytes` 为 0 时行为未定义，请不要这样配置。

---

## 5. 什么不能通过配置修改

以下内容**没有配置项**（要么是协议的一部分，要么是内部常量）：

- **填充**：桶固定为 512/1024/2048/4096/8192 与 8192 的倍数，上限 65536；运行时的填充预算固定为
  每秒 4 MiB，预算饱和时降级到最小桶而不是关闭填充。详见 [`docs/privacy.md`](privacy.md)。
- **发送批量与节奏**：`PrivacyScheduler::strict()` 由两端自动安装（最多合并 16 帧 / 64 KiB；基础间隔
  200 µs、抖动 ≤ 2 ms、上限 50 ms）。这些参数不是配置项。注意：**节奏整形（间隔）当前不会生效**，
  只有批量合并生效（原因见 `docs/privacy.md` 第 3.2 节）。
- **cover traffic**：默认开启且不可配置（空闲 750 ms 后开始，每 1.5 秒一个突发、每突发 3 帧、
  64–4096 字节、最多 40 个突发；预算 4 KiB/s、每会话 256 MiB）。
- **算法列表与轮换策略**：固定为 AES-256-GCM / ChaCha20-Poly1305 / AES-128-GCM，逐帧轮换。
- **一次性密钥池大小**：`SessionConfig` 默认 256，非配置项。
- **服务端身份指纹 pinning**：**已接入配置**（`server_identity_pin`，见 1.3）。未设置时不做 pin，
  只信任 PSK；建议在生产环境设置。
- **客户端出站规则**：客户端只有白名单；egress 约束完全在服务端。
- **IPv6**：任何位置都不支持 IPv6 出口。
- **keepalive 周期**：没有定时 PING；空闲由 `idle_timeout_ms` 关闭。
