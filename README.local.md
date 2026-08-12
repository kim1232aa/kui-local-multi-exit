# K-UI Local Multi-Exit：本地 Docker 模式

本地模式将控制面、OpenVPN 多出口和 Reality 网关都放在 Docker Compose 中运行。公网客户端不直接连接 SOCKS5；它们通过一个 VLESS + XTLS-Reality 端口进入，再按 UUID 转发到不同 OpenVPN 出口。

完整部署说明见 [README.md](README.md)。

## 资源自适应

默认 `KUI_SLOT_COUNT=auto` 按容器可见内存启用槽位：

| 内存 | 槽位 | 拨号/桥接测速并发 | SOCKS 总连接数 |
| --- | ---: | ---: | ---: |
| `<= 1.5 GiB` | 2 | 1 | 32 |
| `<= 2.5 GiB` | 4 | 2 | 64 |
| `<= 4 GiB` | 8 | 2 | 128 |
| `> 4 GiB` | 24 | 4 | 256 |

无可用内存信息时使用 `4 / 2 / 64` 的保守档位。显式覆盖：

```env
KUI_SLOT_COUNT=4
KUI_DIAL_WORKERS=2
PROXY_MAX_CONNECTIONS=64
```

`KUI_SLOT_COUNT` 可设为 `1`–`24` 或 `auto`。已有数据库保留所有历史槽位，但只有前 N 个为当前运行档位管理、展示和订阅。

## 启动

```bash
export KUI_MANAGEMENT_PASSWORD='replace-with-a-password'
export KUI_PUBLIC_HOST='YOUR_PUBLIC_IP_OR_DOMAIN'
docker compose up -d --build
docker compose ps
```

需要宿主 Linux 提供 `/dev/net/tun`，并允许 Docker 使用 `NET_ADMIN`。镜像支持 `linux/amd64` 和 `linux/arm64`。

## 网络边界

Compose 只向宿主机发布：

```text
KUI_MANAGEMENT_PORT（默认 8080/TCP）
KUI_REALITY_PORT（默认 8443/TCP）
```

`exit-01` 起的 SOCKS5 端口仍是 `7920+`，但只存在于主容器和 Compose 网络中。网关使用一个公共 Reality 端口，按 UUID 路由：

```text
exit-01 UUID ─┐
exit-02 UUID ─┼─ KUI_PUBLIC_HOST:KUI_REALITY_PORT ─ gateway ─ internal SOCKS5 ─ OpenVPN
exit-03 UUID ─┘
```

不要从宿主机或公网直连 `7920`。验证时在容器内运行：

```bash
docker compose exec -T kui-local-multi-exit sh -lc \
  'curl --fail --silent --show-error --socks5-hostname "$KUI_MANAGEMENT_USER:$KUI_MANAGEMENT_PASSWORD@127.0.0.1:7920" https://api.ipify.org'
```

Reality 不使用本机 HTTPS 证书，默认端口为 `8443`，不占用 `443`，也不改 OpenResty。旧版 `8444`–`8466` 每槽位链接已失效，升级后刷新订阅。

## 凭据

`KUI_MANAGEMENT_USER` 和 `KUI_MANAGEMENT_PASSWORD` 保持本地 SOCKS5/订阅兼容。主服务首次启动时会在 `kui-local-data` volume 自动生成一组 gateway 专用 SOCKS 凭据，网关只读使用它。默认不配置：

```env
KUI_INTERNAL_PROXY_USER=
KUI_INTERNAL_PROXY_PASSWORD=
```

如需要显式固定内部凭据，必须同时设置两个变量。修改 `KUI_MANAGEMENT_PASSWORD` 不会让 Reality 网关失去对内部 SOCKS 的访问。

## 面板与状态

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/api/local/status
docker compose exec -T kui-reality-gateway \
  kui-sing-box check -c /var/lib/kui-reality/config.json
```

`/api/local/status.total` 是当前受管槽位数；`ready` 是可出现在订阅中的槽位数。只有隧道、策略路由、SOCKS listener、出口检测和目标探针都通过的槽位才会发布。

## 桥接节点

可选桥接节点会作为客户端侧第一跳，路径为：

```text
客户端 -> bridge node -> Reality gateway -> OpenVPN exit -> 目标站
```

```env
KUI_BRIDGE_NODES=hysteria2://password@host:8443?sni=example.com#bridge
KUI_BRIDGE_SUB_URLS=https://example.com/subscription
KUI_BRIDGE_REFRESH_INTERVAL=300
KUI_BRIDGE_SPEED_TEST=0
KUI_BRIDGE_TOP_N=16
```

手工节点直接加入订阅。订阅节点会先做连通性测试；后台刷新并发受 `KUI_DIAL_WORKERS` 限制，避免 1–2 GiB VPS 产生过多子进程。

## 低配排查

```bash
docker compose ps
docker compose logs --tail=200 kui-local-multi-exit
docker compose logs --tail=200 kui-reality-gateway
docker stats kui-local-multi-exit kui-reality-gateway
```

公共 VPN 节点会暂时不可用。应查看槽位事件、换候选或降低 `KUI_SLOT_COUNT`；不要为了填满面板启动超过机器资源承受能力的并发隧道。
