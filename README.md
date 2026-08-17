# K-UI Local Multi-Exit

`kui-local-multi-exit` 在一台 Linux VPS 上以 Docker Compose 运行本地管理面板、SQLite、OpenVPN 出口调度器和 Docker 内的 XTLS-Reality 网关。公网入口只有一个 Reality TCP 端口；每个出口使用独立 UUID，经同一入口路由到对应的内部 SOCKS5/OpenVPN 槽位。

## 工作方式

- 每个 active 槽位有独立 OpenVPN 隧道、策略路由和内部 SOCKS5 listener（从 `7920` 开始）。这些 SOCKS5 端口**不发布到宿主机**。
- `kui-reality-gateway` 使用一个 VLESS + XTLS-Reality inbound。认证到不同 UUID 后，sing-box 按 `auth_user` 将流量送到对应 `exit-XX` 的内部 SOCKS5 端口。
- 订阅只发布状态为 `ready` 且 listener 已就绪的槽位；节点名称来自实际出口信息。
- 旧数据库中的未受管槽位不会删除，但低配档位不会启动、暴露或接受对它们的操作。
- 公共 VPN/OpenVPN 节点本身会离线、限流或不通过探针；槽位不足不能靠伪造 ready 状态解决。

## 低配 VPS 运行档位

默认 `KUI_SLOT_COUNT=auto`。主容器从 cgroup 内存限制（优先）或 `/proc/meminfo` 选择保守档位：

| 容器可见内存 | 槽位数 | 并发拨号/桥接测速 | 全局 SOCKS 连接上限 |
| --- | ---: | ---: | ---: |
| `<= 1.5 GiB` | 2 | 1 | 32 |
| `<= 2.5 GiB` | 4 | 2 | 64 |
| `<= 4 GiB` | 8 | 2 | 128 |
| `> 4 GiB` | 24 | 4 | 256 |
| 无法检测 | 4 | 2 | 64 |

因此 1–2 GiB VPS 默认只启动 2–4 个出口，而不是尝试同时运行 24 条 OpenVPN。需要满配时可显式设置 `KUI_SLOT_COUNT=24`。

三个覆盖项均在启动时校验：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `KUI_SLOT_COUNT` | `auto` | `1`–`24` 或 `auto`。受管槽位数。 |
| `KUI_DIAL_WORKERS` | 档位默认值 | 同时拨号数，也限制桥接订阅的测速并发；范围为 `1` 到当前槽位数。 |
| `PROXY_MAX_CONNECTIONS` | 档位默认值 | 所有槽位共享的 SOCKS 连接总数，不是每个槽位各自的上限。 |

## 前提

- Linux 提供 `/dev/net/tun`。
- Docker Engine 和 Docker Compose v2 可用（镜像支持 `linux/amd64` 和 `linux/arm64`）。
- 当前用户有 Docker 权限。
- VPS 可访问外部 HTTPS 与 OpenVPN 节点。
- 公开入口需放行管理端口和一个 Reality TCP 端口。

```bash
test -c /dev/net/tun && echo 'TUN OK'
docker version
docker compose version
```

## 部署

```bash
git clone https://github.com/kim1232aa/kui-local-multi-exit.git
cd kui-local-multi-exit

cat > .env <<'EOF'
KUI_MANAGEMENT_USER=admin
KUI_MANAGEMENT_PASSWORD=replace-with-a-password
KUI_MANAGEMENT_PORT=8080
KUI_REALITY_PORT=8443
KUI_PUBLIC_HOST=YOUR_PUBLIC_IP_OR_DOMAIN
EOF
chmod 600 .env

docker compose up -d --build
docker compose ps
```

`KUI_PUBLIC_HOST` 建议显式设置为客户端可访问的公网 IP 或域名；未设置时网关会尝试自动查询公网 IP。

常用变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `KUI_MANAGEMENT_USER` | `admin` | 面板生成本地 SOCKS5 验证时使用的用户名。 |
| `KUI_MANAGEMENT_PASSWORD` | 必填 | 管理页生成的内部 SOCKS5 验证密码；不是面板登录密码。 |
| `KUI_MANAGEMENT_PORT` | `8080` | 宿主机管理 API 映射端口。 |
| `KUI_REALITY_PORT` | `8443` | 唯一发布到宿主机的 Reality TCP 端口。 |
| `KUI_PUBLIC_HOST` | 自动发现 | VLESS 链接使用的公网地址。 |
| `KUI_SOCKS5_PUBLIC_HOST` | Reality 清单地址 | 纯 SOCKS5 链接使用的公网地址；若 DNS 下载域名经过 Cloudflare 代理，建议显式设置为直连 IP/域名。 |
| `KUI_REALITY_SNI` | `addons.mozilla.org` | Reality 回落握手域名。 |
| `KUI_FETCH_PROXY` | 空 | 拉取 VPN 数据时使用的显式 HTTP/HTTPS/SOCKS5 代理。 |
| `KUI_OPENVPN_SOCKS_PROXY` | 空 | OpenVPN TCP 握手使用的 SOCKS5 上游代理。 |
| `KUI_ENABLE_VPNBOOK` | `1` | 是否导入 VPNBook TCP 配置。 |
| `KUI_ALLOW_NON_RESIDENTIAL` | `1` | 允许已明确识别的机房出口回退；节点名称会标注 `机房IP`。设为 `0` 恢复严格住宅过滤。 |
| `KUI_VPN_HISTORY_DAYS` | `30` | OpenVPN 历史节点保留天数。 |

网关和主服务不共用管理密码。主服务会在 `kui-local-data` volume 中自动生成权限 `0600` 的 `internal_proxy.json`，网关以只读方式使用这组内部凭据。通常不要设置 `KUI_INTERNAL_PROXY_USER` / `KUI_INTERNAL_PROXY_PASSWORD`；如设置，两个变量必须同时设置。修改 `KUI_MANAGEMENT_PASSWORD` 不会改变网关内部凭据。

## 端口、Reality 和证书

Compose 只发布：

```text
TCP 8080（或 KUI_MANAGEMENT_PORT）  管理面板/API
TCP 8443（或 KUI_REALITY_PORT）     唯一 XTLS-Reality 入口
```

内部 SOCKS5 `7920+` 仅在 `kui-local-multi-exit` 容器和 Compose 网络可达。不能把 `socks5://...@VPS_IP:7920` 当成公网地址。

## 纯 SOCKS5 订阅（可选）

启用 Reality 网关后，默认订阅只发布 VLESS 节点。需要纯 SOCKS5 链接时（例如只认标准节点的客户端），使用：

```text
/api/sub?user=<用户>&token=<token>&format=socks5
```

返回 base64 编码的链接列表：每个 ready 槽位一条 `socks5://`，第三方节点中仅保留 SOCKS5 条目。链接凭据与面板管理用户一致，端口为槽位内部端口（`7920+`）。这些端口默认不发布到宿主机；需要外部可达时运行桥接 sidecar：

也可以直接使用域名路径（同样需要用户和 token）：

```text
https://YOUR_DOMAIN/socks5.txt?user=<用户>&token=<token>
https://YOUR_DOMAIN/socks5-b64.txt?user=<用户>&token=<token>
```

未携带 `user`/`token` 时返回 404，这是为了避免把带认证信息的 SOCKS5 地址公开。SOCKS5 链接主机优先使用 `KUI_SOCKS5_PUBLIC_HOST`，未设置时从 Reality 节点清单取公网地址；因此不要把经过 Cloudflare 代理的订阅下载域名当作 SOCKS5 端口主机。

```bash
vps/socks5-bridge.sh            # 管理密码取自 .env，也可作为第一个参数传入
```

脚本在 Compose 网络上运行一个 sing-box 容器，把每个 ready 槽位以管理凭据认证发布到宿主机同名端口，另发布一个自动选路入口（默认 `1080`，可用 `AUTO_PORT` 覆盖）。注意：发布后任何可达者都能触达这些端口，SOCKS5 认证为明文握手，且主动探测可能导致端口被封；请按需用防火墙限制来源。

所有订阅节点共享同一个 Reality 地址和端口，但 UUID 各不相同：

```text
VLESS UUID for exit-01 ─┐
VLESS UUID for exit-02 ─┼─ YOUR_PUBLIC_HOST:8443 ─ Reality gateway ─ internal SOCKS5 ─ OpenVPN exit
VLESS UUID for exit-03 ─┘
```

Reality 使用其伪装站点握手，不使用也不需要本机 HTTPS 证书。默认监听 `8443`，不会占用宿主机 `443`，也不会修改 OpenResty、TLS 证书或防火墙规则。

从旧的每槽位端口模式升级时，原 `8444`–`8466` 链接不再存在。刷新订阅并重新导入节点；新订阅中的所有节点都应指向同一 `KUI_REALITY_PORT`。

检查网关配置：

```bash
docker compose exec -T kui-reality-gateway \
  kui-sing-box check -c /var/lib/kui-reality/config.json
```

## 管理与验证

面板：`http://YOUR_VPS_IP:8080/`。

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/api/local/status
curl -fsS http://127.0.0.1:8080/api/local/exits
```

验证内部 `exit-01` 的真实出口必须在主容器内运行：

```bash
docker compose exec -T kui-local-multi-exit sh -lc \
  'curl --fail --silent --show-error --socks5-hostname "$KUI_MANAGEMENT_USER:$KUI_MANAGEMENT_PASSWORD@127.0.0.1:7920" https://api.ipify.org'
```

`/api/local/status` 的 `total` 是当前受管槽位数量，`ready` 是可发布数量。`/api/proxy/proxies` 仍描述内部 SOCKS5 槽位，不能作为公网订阅；公网客户端使用 `/api/sub` 生成的 VLESS + Reality 订阅。

## 节点来源和桥接

自动节点来源：VPNGate、VPNBook、历史池与 `providers/` 中的手工 `.ovpn`。公共节点不可用时，选择其他候选或等待刷新；不要将失败槽位标记为 ready。

可选桥接订阅：

```env
KUI_BRIDGE_NODES=hysteria2://password@host:8443?sni=example.com#bridge
KUI_BRIDGE_SUB_URLS=https://example.com/subscription
KUI_BRIDGE_REFRESH_INTERVAL=300
KUI_BRIDGE_SPEED_TEST=0
KUI_BRIDGE_TOP_N=16
```

桥接订阅只在配置 `KUI_BRIDGE_SUB_URLS` 时后台刷新。测试并发继承 `KUI_DIAL_WORKERS`，以免低配机器同时启动过多 curl 或 sing-box 进程。

## 日常检查

```bash
docker compose ps
docker compose logs --tail=200 kui-local-multi-exit
docker compose logs --tail=200 kui-reality-gateway
docker stats kui-local-multi-exit kui-reality-gateway
```

重建或升级不会删除 `kui-local-data` 和 `kui-reality-data` volumes：

```bash
docker compose up -d --build
docker compose ps
```

修改 `.env`（例如 `KUI_SLOT_COUNT`）后同样执行 `docker compose up -d`，Compose 会按配置变化重建对应容器；仅 `restart` 不会应用新的环境变量。

## 开发验证

```bash
PYTHONWARNINGS='error::ResourceWarning' python3 -m unittest discover -s tests -v
python3 -m compileall -q vps tests
KUI_MANAGEMENT_PASSWORD=your-test-password docker compose config --quiet
git diff --check
```

针对已启动的 Docker Compose 实例运行真实内部 SOCKS5 检查：

```bash
KUI_INTEGRATION=1 \
KUI_BASE_URL=http://127.0.0.1:8080 \
KUI_PROXY_CONTAINER=kui-local-multi-exit \
KUI_PROXY_USER=admin \
KUI_PROXY_PASSWORD='your-actual-password' \
KUI_EXPECT_READY_SLOTS='expected-ready-count' \
python3 -m unittest discover -s tests/integration -v
```

如需验证非 Docker 或已显式发布的测试代理，可设置 `KUI_PROXY_HOST`，集成测试将直接连接该地址而非执行 `docker exec`。
