# K-UI Local Multi-Exit

`kui-local-multi-exit` 是一个面向单台 Linux VPS 的本地多出口代理控制器。它在一个 Docker 容器中运行管理面板、本地 SQLite、VPNGate/OpenVPN 调度器和 12 个独立 SOCKS5 出口，不依赖 Cloudflare 或外部控制中心。公网客户端可通过原版 K-UI 同款 sing-box 加密入口接入，避免直接暴露裸 SOCKS5 协议。

## 功能与边界

- 固定 12 个出口槽位：`exit-01` 至 `exit-12`。
- 默认代理端口：TCP `7920-7931`，每个槽位一个独立 TUN、策略路由和 SOCKS5 listener。
- 每个槽位可修改国家、选择候选节点、换 IP、停用、启用。
- 管理页/API 免登录；12 个 SOCKS5 出口共用一组用户名和密码。
- 本地 SQLite 和运行状态保存在 Docker volume `kui-local-data`。
- 只有隧道、策略路由、真实 listener、住宅属性和全部目标探针均通过的槽位才会发布到订阅。
- OpenVPN 节点池支持 VPNGate、VPNBook、30 天滚动历史池和 `providers/` 手工配置；PublicVPNList 用于国家覆盖元数据。**免费公共节点仍不保证 12 个槽位始终同时可用**。
- `scripts/install-reality-gateway.sh` 可部署单节点 XTLS-Reality 加密入口，并把流量固定交给指定 OpenVPN 出口槽位。

## 部署前提

建议使用 Debian 12 或 Ubuntu 22.04/24.04 VPS，并满足：

- Linux 内核提供 `/dev/net/tun`。
- Docker Engine 与 Docker Compose v2 可用。
- root 用户，或当前用户有 Docker 权限。
- VPS 可以访问外部 HTTPS 和 VPNGate/OpenVPN 节点。
- 至少开放 TCP `8080` 和 `7920-7931`，或在云安全组/防火墙中只允许可信来源访问。

先检查：

```bash
test -c /dev/net/tun && echo "TUN OK"
docker version
docker compose version
```

如尚未安装 Docker，请按 Docker 官方对应发行版文档安装 Docker Engine 和 Compose plugin。不要使用过时的独立 `docker-compose` v1。

## 安全提醒

管理面板默认免登录。不要把 `8080` 无限制暴露到不可信网络；请至少使用 VPS 防火墙限制来源 IP，或放在带访问控制的反向代理后面。

`KUI_MANAGEMENT_PASSWORD` 是所有 SOCKS5 出口的共用密码。请使用随机强密码，并且不要把真实密码提交到 Git。仓库已经忽略 `.env`，可在 VPS 项目目录创建本地 `.env` 保存配置。

## 首次部署

### 1. 克隆仓库

```bash
git clone https://github.com/YOUR_USERNAME/kui-local-multi-exit.git
cd kui-local-multi-exit
```

### 2. 创建本地配置

推荐使用 `.env`：

```bash
cat > .env <<'EOF'
KUI_MANAGEMENT_USER=admin
KUI_MANAGEMENT_PASSWORD=请替换为随机强密码
KUI_MANAGEMENT_PORT=8080
KUI_FETCH_PROXY=
KUI_OPENVPN_SOCKS_PROXY=
EOF
chmod 600 .env
```

变量说明：

| 变量 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `KUI_MANAGEMENT_USER` | 否 | `admin` | 12 个 SOCKS5 出口共用用户名 |
| `KUI_MANAGEMENT_PASSWORD` | 是 | 无 | 12 个 SOCKS5 出口共用密码；不是面板登录密码 |
| `KUI_MANAGEMENT_PORT` | 否 | `8080` | 面板映射到宿主机的 TCP 端口 |
| `KUI_FETCH_PROXY` | 否 | 空 | 拉取 VPNGate 数据时使用的显式 HTTP/HTTPS/SOCKS5 代理 |
| `KUI_OPENVPN_SOCKS_PROXY` | 否 | 空 | OpenVPN 握手使用的 SOCKS5 上游代理 |
| `KUI_ENABLE_VPNBOOK` | 否 | `1` | 自动导入 VPNBook 的 US/CA/GB/DE/FR TCP 443 配置和当前动态密码 |
| `KUI_VPN_HISTORY_DAYS` | 否 | `30` | 历史 OpenVPN 节点滚动保留天数 |

也可以只为当前 shell 导出必填变量：

```bash
export KUI_MANAGEMENT_PASSWORD='请替换为随机强密码'
```

### 3. 启动

```bash
docker compose up -d --build
```

检查容器：

```bash
docker compose ps
docker inspect --format '{{.State.Health.Status}}' kui-local-multi-exit
docker compose logs --tail=100 kui-local-multi-exit
```

容器状态最终应为 `healthy`。首次启动会拉取 VPNGate 节点并拨号，槽位状态可能需要一段时间才能稳定。

## XTLS-Reality 多出口入口

`7920-7931` 是本机 OpenVPN 出口选择器，不适合作为中国大陆客户端的裸公网入口。按原版 K-UI 的 sing-box 结构部署 12 个 XTLS-Reality 入站，并一一映射到 12 个 OpenVPN 出口：

```bash
sudo KUI_REALITY_PORT=8443 \
  KUI_REALITY_EXIT_PORT=7920 \
  KUI_REALITY_SNI=addons.mozilla.org \
  KUI_PUBLIC_HOST=YOUR_VPS_IP \
  ./scripts/install-reality-gateway.sh

docker compose up -d --build
```

默认映射：

```text
8443/TCP → exit-01 → 127.0.0.1:7920
8444/TCP → exit-02 → 127.0.0.1:7921
...
8454/TCP → exit-12 → 127.0.0.1:7931
```

脚本沿用原版 sing-box `1.13.14` 和 XTLS-Reality 配置，生成文件保存在：

```text
/etc/kui-reality-gateway/client.txt         # 12 条 VLESS 导入链接
/etc/kui-reality-gateway/mihomo.yaml        # Mihomo/Clash Meta 节点片段
/etc/kui-reality-gateway/config.json        # 服务端配置
/etc/kui-reality-gateway/nodes-private.json # UUID 和 Reality 私钥，权限 0600
runtime/reality/public-nodes.json            # 订阅服务读取的公开参数
```

检查服务：

```bash
systemctl status kui-reality-gateway --no-pager
/usr/local/bin/kui-sing-box check -c /etc/kui-reality-gateway/config.json
ss -ltnp | grep -E ':(8443|8454)'
```

Clash/Mihomo 使用面板生成的 `format=clash` 订阅。订阅只下发当前真正 ready 的槽位，节点类型为 `VLESS + XTLS-Reality`，名称按实际出口动态生成：

```text
JP-日本 | KDDI | 59.136.199.164 | exit-01
KR-韩国 | KT | 211.199.34.191 | exit-09
```

国家取当前 OpenVPN 节点而不是槽位目标，因此 `ANY` 不会出现在节点名中。可获得城市时名称会自动加入城市；换出口 IP 后，刷新 Clash 订阅即可更新名称。重新执行安装脚本会保留已有 Reality UUID 和密钥。

## 防火墙

默认端口：

- TCP `8080`：管理面板和 API。
- TCP `8443-8454`：12 个 XTLS-Reality 加密入口。
- TCP/UDP `7920-7931`：只绑定宿主机 `127.0.0.1` 的内部 SOCKS5 出口选择器。

使用 UFW 且只允许一个管理来源时，可按实际来源 IP 调整：

```bash
ufw allow from YOUR_TRUSTED_IP to any port 8080 proto tcp
ufw allow 8443:8454/tcp
ufw status
```

云厂商安全组也必须配置相同规则。不要因为 SOCKS5 有密码就默认向整个互联网开放端口。

## OpenVPN 多源节点池

当前自动源：

- VPNGate：当前实时 CSV 配置。
- VPNBook：US、CA、GB、DE、FR 官方免费 TCP 443 配置，自动读取当前账号密码。
- 历史池：节点快照按 IP 合并，默认滚动保留 30 天，临时消失的配置仍可重新尝试。
- PublicVPNList：只保存各国在线数量和数据集状态，用于发现覆盖，不抓取其短时签名配置。
- Proton/其他供应商：把账号下载的 `.ovpn` 和凭据放到 `providers/`，参见 `providers/README.md`。

不同来源可以使用不同 OpenVPN 用户名和密码。VPNBook、Proton 等机房型 VPN 仍需通过本项目的住宅属性和目标探针，未通过的节点不会发布。

## 网络受限时使用上游代理

普通 VPS 直连可用时，保持以下变量为空。只有 VPS 宿主确实运行了可用的 SOCKS5 服务时才配置：

```bash
cat >> .env <<'EOF'
KUI_FETCH_PROXY=socks5://YOUR_UPSTREAM_HOST:PORT
KUI_OPENVPN_SOCKS_PROXY=socks5://YOUR_UPSTREAM_HOST:PORT
EOF
docker compose up -d --build
```

注意：

- 替换 `YOUR_UPSTREAM_HOST:PORT` 为实际可用的 SOCKS5 代理地址。
- Compose 已把 `host.docker.internal` 映射到宿主网关；如宿主本身有代理服务，可使用 `host.docker.internal:端口`。
- OpenVPN 通过 SOCKS5 上游时只支持 TCP OpenVPN 节点，UDP 节点会被跳过。
- 不要给容器设置全局 `HTTP_PROXY`、`HTTPS_PROXY` 或 `ALL_PROXY`；出口路由由每个槽位的 mark 和策略路由控制。

## 访问和代理地址

面板：

```text
http://YOUR_VPS_IP:8080/
```

如果设置了其他 `KUI_MANAGEMENT_PORT`，使用对应宿主端口。

SOCKS5：

```text
socks5://admin:YOUR_PASSWORD@YOUR_VPS_IP:7920  # exit-01
socks5://admin:YOUR_PASSWORD@YOUR_VPS_IP:7921  # exit-02
...
socks5://admin:YOUR_PASSWORD@YOUR_VPS_IP:7931  # exit-12
```

用户名以 `KUI_MANAGEMENT_USER` 为准。

在“住宅 IP 代理”页可以：

- 查看 12 个槽位的出口、listener、住宅分类和逐目标探针结果。
- 修改两位国家代码或 `ANY`，然后保存。
- 从候选下拉框选择指定节点并连接。
- 单独换 IP、启用或停用一个槽位。
- 查看本地出口事件日志。

连续三次失败后槽位会暂时停用；节点池刷新后，只有当前存在对应国家（或 `ANY`）可用候选的槽位才会自动恢复。也可以手动点击“启用”或选择候选重新连接。接受重拨请求只代表任务开始，不代表隧道已经 ready。

## 可发布条件

槽位只有同时满足以下条件才会发布到 `/api/proxy/proxies` 和订阅：

1. `enabled=true`。
2. OpenVPN 进程和 TUN 正常。
3. 槽位策略路由表包含指向对应 TUN 的默认路由。
4. SOCKS5 listener 已真实绑定。
5. 实际出口 IP 可读取且被 TestISP 判定为住宅。
6. 默认探针 `https://www.gstatic.com/generate_204` 精确返回 `204`。
7. Google、ChatGPT、TradingView、Claude 四个自定义目标全部得到可接受响应。

自定义目标接受最终 `2xx`，以及目标站明确返回且非 `407` 的 `4xx`；拒绝最终 `3xx`、`5xx`、`407` 和网络超时。

## 部署后验证

### 面板和 API

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/api/local/exits
curl -fsS http://127.0.0.1:8080/api/proxy/proxies
```

如果修改了 `KUI_MANAGEMENT_PORT`，把以上 `8080` 替换为实际端口。

### 逐端口验证真实出口

使用 `.env` 时先将密码加载到 shell，避免在命令历史中重复写明文：

```bash
set -a
. ./.env
set +a

curl --fail --silent --show-error \
  --socks5-hostname "$KUI_MANAGEMENT_USER:$KUI_MANAGEMENT_PASSWORD@127.0.0.1:7920" \
  https://api.ipify.org
```

验证全部已发布端口：

```bash
for port in $(seq 7920 7931); do
  printf '%s -> ' "$port"
  curl --fail --silent --show-error --max-time 20 \
    --socks5-hostname "$KUI_MANAGEMENT_USER:$KUI_MANAGEMENT_PASSWORD@127.0.0.1:$port" \
    https://api.ipify.org || echo 'not ready'
  echo
done
```

API 显示的 `egress_ip` 必须与对应 SOCKS5 端口实测值一致。不可用槽位不应出现在代理订阅中。

## 日常运维

### 查看状态和日志

```bash
docker compose ps
docker compose logs -f --tail=200 kui-local-multi-exit
docker stats kui-local-multi-exit
```

### 重启

```bash
docker compose restart kui-local-multi-exit
```

### 更新

更新不会删除 `kui-local-data`：

```bash
git pull --ff-only
docker compose up -d --build
docker compose ps
```

更新后重新检查 health、面板和实际 SOCKS5 出口。

## 备份与恢复

数据保存在命名 volume `kui-local-data` 的 `/opt/kui-local`。先确认实际 volume 名称：

```bash
docker volume ls | grep kui-local-data
```

Compose 常会给 volume 加项目名前缀，例如 `kui-local-multi-exit_kui-local-data`。下面先自动读取 Compose 使用的实际名称。

### 备份

```bash
mkdir -p backups
VOLUME_NAME=$(docker inspect kui-local-multi-exit --format '{{range .Mounts}}{{if eq .Destination "/opt/kui-local"}}{{.Name}}{{end}}{{end}}')
test -n "$VOLUME_NAME"
docker run --rm \
  -v "$VOLUME_NAME:/data:ro" \
  -v "$PWD/backups:/backup" \
  alpine sh -c 'tar czf /backup/kui-local-data.tar.gz -C /data .'
```

### 恢复

恢复会覆盖当前持久化数据。先停止容器并确认备份文件正确：

```bash
docker compose down
VOLUME_NAME=$(docker volume ls --format '{{.Name}}' | grep 'kui-local-data$' | head -n 1)
test -n "$VOLUME_NAME"
test -f backups/kui-local-data.tar.gz
docker run --rm \
  -v "$VOLUME_NAME:/data" \
  -v "$PWD/backups:/backup:ro" \
  alpine sh -c 'rm -rf /data/* /data/.[!.]* /data/..?* 2>/dev/null || true; tar xzf /backup/kui-local-data.tar.gz -C /data'
docker compose up -d --build
```

恢复后检查容器 health 和槽位状态。

## 停止与卸载

停止并保留数据：

```bash
docker compose down
```

再次启动：

```bash
docker compose up -d --build
```

永久删除容器和 `kui-local-data`：

```bash
docker compose down -v
```

`down -v` 会不可恢复地删除 SQLite、槽位配置和历史记录。只有确认已有备份且确实不再需要数据时才执行。

## 常见问题

### `/dev/net/tun` 不存在

```bash
ls -l /dev/net/tun
modprobe tun
```

部分 VPS 虚拟化方案需要在服务商面板启用 TUN/TAP。容器还必须保留 Compose 中的 `/dev/net/tun` device 和 `NET_ADMIN` capability。

### 容器不健康

```bash
docker compose ps
docker compose logs --tail=200 kui-local-multi-exit
curl -v http://127.0.0.1:8080/healthz
```

检查面板端口是否被占用、密码变量是否已设置，以及容器是否能写入 volume。

### 没有可用节点或槽位被停用

VPNGate 节点随时可能离线、认证失败或无法通过目标探针。可以：

- 刷新候选列表后手动选择其他节点。
- 将目标国家改为当前候选较多的国家或 `ANY`。
- 点击“启用”重新检测。
- 查看卡片错误和 `docker compose logs`。

不要为了凑够 12 个而把失败槽位标记为 ready。

### 出口被判定为机房或未知

项目采用 fail-closed：TestISP 未明确判定住宅时不会发布。更换 VPNGate 节点，不要绕过住宅门禁。

### SOCKS5 返回 VPS 原生出口

通过 API 与 `api.ipify.org` 对照。当前版本会检测策略路由消失并撤下槽位；如果仍出现不一致，先更新到最新版，再查看该槽位事件日志和路由：

```bash
docker exec kui-local-multi-exit ip rule show
docker exec kui-local-multi-exit ip route show table 200
```

`exit-01` 使用表 `200`，后续槽位依次到 `211`。

### 临时上游代理不可达

如果 VPS 没有宿主 SOCKS5 服务，清空：

```bash
sed -i 's|^KUI_FETCH_PROXY=.*|KUI_FETCH_PROXY=|' .env
sed -i 's|^KUI_OPENVPN_SOCKS_PROXY=.*|KUI_OPENVPN_SOCKS_PROXY=|' .env
docker compose up -d --build
```

### Docker 或宿主系统代理干扰

不要为该容器设置全局 `HTTP_PROXY`、`HTTPS_PROXY` 或 `ALL_PROXY`。如 Docker daemon 配置了全局代理，请核对它是否会影响容器出站；项目只会显式读取 `KUI_FETCH_PROXY` 和 `KUI_OPENVPN_SOCKS_PROXY`。

## 开发验证

```bash
PYTHONWARNINGS='error::ResourceWarning' python3 -m unittest discover -s tests -v
KUI_MANAGEMENT_PASSWORD=your-test-password docker compose config --quiet
docker build --check .
python3 -m compileall -q vps tests
git diff --check
```

针对一台已经启动的实例运行真实 SOCKS5 集成测试：

```bash
KUI_INTEGRATION=1 \
KUI_BASE_URL=http://127.0.0.1:8080 \
KUI_PROXY_HOST=127.0.0.1 \
KUI_PROXY_USER=admin \
KUI_PROXY_PASSWORD='your-actual-password' \
KUI_EXPECT_READY_SLOTS='expected-ready-count' \
python3 -m unittest discover -s tests/integration -v
```

## 项目结构

```text
.
├── Dockerfile
├── compose.yaml
├── index.html
├── vps/                         # 本地 API、调度、路由、SOCKS5、VPNGate
├── tests/                       # 单元与真实集成测试
└── docs/superpowers/            # 设计与实施计划
```

更详细的本地模式说明见 [`README.local.md`](README.local.md)。
