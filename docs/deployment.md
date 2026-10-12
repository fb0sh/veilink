# 部署

本文档说明如何在 Linux VPS 上部署 Veilink 服务端，以及权限、systemd、状态目录、备份、升级和
放在中间层后面的注意事项。客户端部署见根目录的 [README](../README.md)。

所有命令以 `root`（或 `sudo`）在 Debian/Ubuntu 风格的系统上为例；其它发行版按需调整包名。

---

## 1. 前置条件

| 项目 | 要求 |
|------|------|
| 操作系统 | Linux（服务端仅在 Linux 上验证；其它平台未测试） |
| 架构 | x86_64 或 aarch64 |
| 监听端口 | 默认 `0.0.0.0:443`，需要 root 或 `CAP_NET_BIND_SERVICE`（见第 4 节） |
| 网络出口 | 需要对**任意公网 IPv4 地址**发起 TCP 连接（这是代理的用途） |
| DNS | 使用系统 resolver 时需要 `/etc/resolv.conf` 可用；也可以配置 `dns.servers` |
| 内层协议 | **仅 IPv4**：没有 IPv6 出口 |
| 传输协议 | 仅 TCP：没有 UDP 中继 / QUIC / UDP ASSOCIATE |

服务端**不需要**域名或 CA 证书：它自己生成自签名证书，认证由 PSK 完成。

---

## 2. 安装

### 2.1 获取二进制

从 GitHub Release 下载对应平台的归档（`veilink-linux-x86_64.tar.gz` 或
`veilink-linux-aarch64.tar.gz`），或从源码编译：

```bash
cd /path/to/Veilink
cargo build --release --locked -p veilink-cli
```

### 2.2 创建用户与目录

服务端**不应以 root 运行**。绑定 443 只需要一个 capability（见第 4 节）。

```bash
sudo useradd --system --home /var/lib/veilink --shell /usr/sbin/nologin veilink
sudo install -d -o veilink -g veilink -m 0700 /var/lib/veilink
sudo install -d -o root -g veilink -m 0750 /etc/veilink
sudo install -m 0755 veilink /usr/local/bin/veilink
/usr/local/bin/veilink --version
```

### 2.3 生成认证密钥

**在客户端或服务端任一侧生成一次**，两侧使用同一个值：

```bash
# 打印到标准输出（默认 Base64URL）
veilink keygen

# 或写入文件（0600，拒绝覆盖已有文件）
veilink keygen --output /etc/veilink/psk.txt
```

- 默认 32 字节（256 bit）来自操作系统 CSPRNG。
- `--count N` 一次生成多个（1–64）；`--encoding hex` 输出十六进制；`--quiet` 只输出密钥。
- **把密钥当作密码对待**：任何持有它的人都能使用你的服务器（并能冒充它）。

### 2.4 配置文件

```bash
sudo install -o root -g veilink -m 0640 server.yaml /etc/veilink/server.yaml
sudoedit /etc/veilink/server.yaml
```

最小配置（完整字段见 [`docs/configuration.md`](configuration.md)）：

```yaml
listen: "0.0.0.0:443"
key: "<veilink keygen 的输出>"
state_dir: "/var/lib/veilink"

# 可选但强烈推荐：限制客户端可以访问的端口
allowed_ports: [80, 443]
```

校验后启动：

```bash
sudo -u veilink /usr/local/bin/veilink check --config /etc/veilink/server.yaml --verbose
```

> `veilink check` 只做校验，不监听、不连接、不创建 `state_dir`。

---

## 3. 状态目录

`state_dir` 默认是平台状态目录（对 root 通常是 `/root/.local/state/veilink`）。**在 systemd 下务必
显式设置为 `/var/lib/veilink`**，否则 systemd 的加固选项（`ProtectHome=true`）会让默认路径不可写。

首次启动时服务端会创建：

| 文件 | 权限 | 内容 | 丢失的后果 |
|------|------|------|-----------|
| `identity.key` | `0600` | 长期 X25519 身份，文本格式：首行 `VEILINK-IDENTITY-1`，次行 64 个十六进制字符 | 生成新身份；指纹改变；任何 pin 了旧指纹的客户端会拒绝连接 |
| `tls_cert.pem` | `0644` | 自签名 TLS 1.3 证书（PEM），CommonName `Veilink server`，SAN 含 `veilink.local` 与监听 IP | 与 `tls_key.pem` 一起重新生成 |
| `tls_key.pem` | `0600` | 对应私钥（PKCS#8 PEM） | 同上 |

权限强制：

- **`identity.key` 若对 group/other 可读，服务端会拒绝启动**并提示
  `chmod 600 /var/lib/veilink/identity.key`（`IdentityError::InsecurePermissions`）。
- `tls_key.pem` 可读只记录一条警告（提示 `chmod 600`）。
- 文件创建时即以目标权限打开（不是先创建再 chmod），避免短暂的泄露窗口。

### 3.1 备份

```bash
# 备份整个状态目录（含两个私钥，务必加密保存）
sudo tar -czf /root/veilink-state-$(date +%F).tar.gz -C /var/lib/veilink .
sudo chmod 600 /root/veilink-state-*.tar.gz
```

- **要保留同一身份/指纹就必须备份 `identity.key`**（以及证书与私钥，避免指纹变化）。
- 备份介质必须视为机密：`identity.key` 与 `tls_key.pem` 是私钥。
- 恢复：把文件复制回 `state_dir`，`chown veilink:veilink`、`chmod 600`（证书 644），再启动服务。
- 不需要备份任何其它内容：没有会话缓存、没有数据库、没有日志文件（日志走 stdout/journald）。

### 3.2 删除与轮换

- 删除 `tls_cert.pem` 与 `tls_key.pem` 会在下次启动时重新生成证书（**指纹改变**，身份不变）。
- 删除 `identity.key` 会生成**全新的服务端身份**（指纹改变）。
- 当前**没有**平滑轮换机制；更换 PSK 需要同时修改客户端与服务端并重启双方。

---

## 4. 为什么监听 `0.0.0.0:443` 需要权限

在 Linux 上，绑定 1024 以下的端口默认只允许 `CAP_NET_BIND_SERVICE`（历史上是"仅 root"）。
以非 root 用户监听 443 而不授权限时会失败，报错形如：

```text
error: cannot start the server
  caused by: cannot bind 0.0.0.0:443: Permission denied
```

三种处理方式，推荐第一种：

1. **给 systemd 单元授予 capability**（不需要 root 运行，权限最小）：

   ```ini
   AmbientCapabilities=CAP_NET_BIND_SERVICE
   CapabilityBoundingSet=CAP_NET_BIND_SERVICE
   ```

   systemd 以该 capability 启动进程后，进程仍以 `veilink` 用户运行。`CapabilityBoundingSet`
   保证进程不会持有其它 capability。

2. **降低内核的未授权端口下限**（全局生效，影响系统上所有进程）：

   ```bash
   echo 'net.ipv4.ip_unprivileged_port_start=443' | sudo tee /etc/sysctl.d/99-veilink.conf
   sudo sysctl --system
   ```

3. **改用高端口 + 防火墙重定向**：服务端监听 `0.0.0.0:8443`，再用
   `iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443`
   把 443 重定向过去。注意：这要求防火墙规则在连接跟踪之前生效，并且服务端看到的源地址可能
   被改写（会影响按源 IP 的速率限制）。

**不要以 root 直接运行服务端**：TLS 解析、HTTP 解析、DNS 都在这个进程里，最小权限原则更重要。

---

## 5. systemd 单元

`/etc/systemd/system/veilink.service`：

```ini
[Unit]
Description=Veilink encrypted proxy server
Documentation=https://github.com/veilink/veilink
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=veilink
Group=veilink
# StateDirectory 会创建 /var/lib/veilink 并赋予正确的属主与权限
StateDirectory=veilink
StateDirectoryMode=0700

ExecStart=/usr/local/bin/veilink server --config /etc/veilink/server.yaml
Restart=on-failure
RestartSec=2s
# 发布版使用 panic = "abort"，崩溃即退出，由 systemd 重启
TimeoutStopSec=10s

# --- 绑定 443 的最小权限 ---
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# --- 加固 ---
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
UMask=0077

[Install]
WantedBy=multi-user.target
```

说明与注意事项：

- `StateDirectory=veilink` 使 `/var/lib/veilink` 可写；配合 `ProtectSystem=strict` 后，文件系统
  其余部分只读。配置里的 `state_dir` 必须与之匹配。
- `RestrictAddressFamilies=AF_INET AF_INET6` 已足够（Veilink 只用 TCP/UDP socket 与 DNS）。
- `MemoryDenyWriteExecute=true` 在 `ring`/RustCrypto 上通常可用。**如果启动失败并报可执行内存相关
  错误，请删除这一行**，其余加固保持不变。
- `SystemCallFilter=@system-service` 在常见内核上足够。若出现 `EPERM`，临时去掉该行定位原因。
- 服务端把日志写 stderr，由 journald 收集；没有自己的日志文件，因此不需要额外写权限。

启用与查看：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now veilink
sudo systemctl status veilink
sudo journalctl -u veilink -f
```

启动时应看到（示例）：

```text
veilink server starting
egress policy: loopback, private, link-local and other special-use IPv4 destinations are denied
listening on 0.0.0.0:443
server identity identity=<64 位十六进制> short=<aa:bb:cc:dd>
authentication is mandatory: unauthenticated connections are closed before any request is read
```

**记下 `identity`（完整指纹）**：客户端将来若启用身份 pinning 需要它；也是判断"服务端是否被替换"
的依据。

---

## 6. 防火墙

只暴露需要的端口，其余默认拒绝。以下为 nftables 示例（**保留你自己的 SSH 规则**）：

```nft
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    iif "lo" accept
    ct state established,related accept
    ct state invalid drop

    # SSH（按需修改）
    tcp dport 22 accept
    # Veilink
    tcp dport 443 accept
    icmp type echo-request accept
  }

  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output priority 0; policy accept; }
}
```

关于**出站**：

- 默认应允许出站：代理的意义就是去连接任意的公网目标。
- 如果你的 `allowed_ports` 是 `[80, 443]`，可以在 output 链里镜像同样的限制（纵深防御；注意
  不要把自己的 DNS/SSH 流量也挡掉）。
- 若配置了 `dns.servers`，需要放行到这些地址的 UDP 53（以及你选择的端口）。
- **不要**为了"安全"把出站限制到固定 IP 列表——那会让代理无法工作。

关于 **443 之外**：把服务端放在 443 上是为了混在常规 HTTPS 流量里；换成其它端口也可行，但要同步
修改客户端的 `server` 字段。

---

## 7. 升级

状态目录与配置与二进制解耦，升级只替换可执行文件：

```bash
# 1. 先校验新二进制
install -m 0755 veilink-new /usr/local/bin/veilink.new
/usr/local/bin/veilink.new --version

# 2. 用新二进制校验现有配置（避免升级后才发现配置不兼容）
/usr/local/bin/veilink.new check --config /etc/veilink/server.yaml

# 3. 原子替换并重启
sudo systemctl stop veilink
sudo mv /usr/local/bin/veilink.new /usr/local/bin/veilink
sudo systemctl start veilink
sudo journalctl -u veilink -n 20 --no-pager
```

升级检查清单：

- 重启后日志中的 `identity=<指纹>` 与升级前**一致**（说明 `identity.key` 未被替换/丢失）。
- 客户端能重新建立会话（客户端日志出现 `secure session established`）。
- 若升级跨过协议变更（`VLP/1` 版本字节 `0x56` 未变则兼容），需要**同时**升级客户端与服务端。

回滚：重新安装旧二进制并重启即可；状态目录向后兼容（身份文件格式为
`VEILINK-IDENTITY-1`）。

---

## 8. 放在 TLS 终结器 / 反向代理后面

**结论：只支持 L4（TCP/SNI）透传，不支持终止式 TLS 卸载。**

原因：VLP/1 的认证绑定在**外层 TLS 会话的 exporter** 上（rustls 的
`export_keying_material("EXPORTER-Veilink-VLP1")`）。这个值只有**终止 TLS 的那个端点**能计算。
当前服务端代码路径（`veilink_transport::accept` / `http2::accept`）**总是自己完成 TLS 握手并读取
自己的 exporter**；它没有明文监听模式。因此：

- ✅ **支持**：nginx `stream` / HAProxy `mode tcp` / 云 L4 负载均衡做的 **TCP 透传**（按 SNI 或端口
  转发），TLS 会话端到端保持，exporter 由 Veilink 自己计算。
- ❌ **不支持**：nginx `proxy_pass` / HAProxy `mode http` / CDN 之类的 **TLS 终止**后以明文转发。
  此时 Veilink 收到的是明文 TCP，TLS 握手会失败；即使强行"转发"，VLP/1 也无法获得 exporter，
  认证必然失败。

配置 L4 透传示例（nginx，仅转发不终止）：

```nginx
stream {
    upstream veilink {
        server 127.0.0.1:8443;
    }
    server {
        listen 443;
        proxy_pass veilink;
        proxy_timeout 1h;
        proxy_connect_timeout 5s;
    }
}
```

注意点：

- 必须转发**原始 TCP**，不要插入 `PROXY protocol`（除非上游明确支持；当前 Veilink 不支持
  PROXY protocol，注入的前缀字节会破坏帧解析）。
- 客户端与服务端必须配置相同的 `transport`（`h2` 或 `tls`）。
- `h2` 传输要求路径上的每个组件都能正确处理 HTTP/2，且**不能**改写或缓冲 body；任何会重写
  HTTP/2 的中间盒都会破坏隧道。若不确定，改用 `transport: tls`。
- ALPN：客户端与服务端都宣告 `h2`（优先）与 `vlp/1`。若某段链路丢掉了 ALPN，服务端会按裸 VLP
  帧处理（`check_alpn(None) == Ok(ALPN_VLP)`）；这处理的是"没有 ALPN"，而**不是** TLS 卸载。
  若 ALPN 协商成其它值（例如 `http/1.1`），连接会被拒绝（`UnexpectedAlpn`）。

---

## 9. 监控与运维

- 日志：stderr → journald。级别由 `RUST_LOG`（优先）或 `log.level` 控制，默认 `info`。
- 服务端每 60 秒输出一行统计（`spawn_stats_reporter`），字段包括：
  `connections_active`、`connections_total`、`connections_rejected`、`streams_active`、
  `streams_total`、`dns_queries`、`dns_failures`、`egress_denied`、`auth_failures`。
- 统计中**不含域名或 URL**。要记录域名必须显式设置 `log.log_domains: true`，请先确认这符合你的
  隐私承诺。
- **没有** Prometheus/OpenMetrics 端点、没有健康检查 HTTP 端点、没有管理接口。健康检查可用
  `ss -ltnp | grep :443` 或一次 TLS 连接（会因缺少 PSK 而在握手阶段失败，属预期）。
- `auth_failures` 持续增长通常意味着有人在扫描该端口；`egress_denied` 增长意味着客户端在尝试访问
  被策略拒绝的目标（可能是配置问题，也可能是被滥用的迹象）。

---

## 10. 故障排查

| 症状 | 可能原因 | 处理 |
|------|---------|------|
| `cannot bind 0.0.0.0:443: Permission denied` | 没有绑定特权端口的能力 | 第 4 节 |
| `identity file ... is readable by other users (mode 644)` | 状态目录权限被改过 | `chmod 600 identity.key` |
| 客户端 `session handshake rejected` | 两侧 PSK 不一致；或中间有 TLS 终止/改写 | 核对 `key`；确认是 L4 透传 |
| 客户端 `the peer negotiated 'http/1.1', which this build does not use` | 中间盒改写了 ALPN | 移除/改正中间层，或改用 `transport: tls` |
| 客户端反复重连并打印 `cannot establish a secure session` | 防火墙未放行；服务端未运行；PSK 不匹配 | 检查 `ss -ltn`、防火墙、两侧配置 |
| 请求返回 502 `egress policy denied` | 目标是私网/特殊用途地址，或端口不在 `allowed_ports` | 确认目标合法；必要时调整 `allowed_ports`（不要开 `allow_private_targets`） |
| 请求返回 502 `remote DNS resolution failed` | 服务端解析器不可用 | 检查 `/etc/resolv.conf` 或配置 `dns.servers` |
| 会话每 5 分钟断开一次 | 空闲超时（默认 300 秒） | 这是预期行为；当前没有 keepalive 循环 |

---

## 11. 未实现 / 当前限制

- **仅 IPv4 出口**，没有 IPv6。
- **仅 TCP**：没有 UDP 中继、没有 QUIC、没有 UDP ASSOCIATE。
- **没有终止式 TLS 卸载支持**（见第 8 节）。
- **没有平滑 PSK 轮换**（无双密钥过渡、无按客户端密钥）。
- **没有 cover traffic 调度器**：不会有额外填充流量来掩盖时序（见 `docs/privacy.md`）。
- **没有 keepalive 定时器**：空闲会话由 `idle_timeout` 关闭，而没有 PING 保活。
- **没有内建指标端点 / 管理接口**。
- **没有随附 seccomp/AppArmor 之外的强制访问控制配置**：第 5 节的 systemd 加固是推荐做法，不是
  代码强制。
- **本机未提供 Docker/Podman 镜像或安装脚本**：仅提供二进制归档。
