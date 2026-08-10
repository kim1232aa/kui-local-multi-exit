# K-UI Local Multi-Exit

这是从 K-UI 原有 VPNGate/OpenVPN/住宅检测逻辑派生的单 VPS 本地版。它不使用 Cloudflare Pages、Workers、D1 或 Realtime 控制中心，单个 Docker 容器内运行本地面板、SQLite、多源 OpenVPN 调度器和多个出口。

## 当前能力

- 固定 12 个出口槽位，默认 `JP/US/GB/DE/KR/SG` 每国两个。
- 每个槽位可独立修改国家和端口。
- 每个槽位一条 OpenVPN 隧道、一个 TUN 设备、一个 SOCKS5/HTTP 端口，并在同端口支持 SOCKS5 UDP ASSOCIATE。
- 端口 `7920` 至 `7931` 对应 `exit-01` 至 `exit-12`。
- 单槽位换 IP、停用、启用和独立失败状态。
- 连续三次拨号/健康失败后暂时停用；节点刷新时仅在存在对应国家候选后自动恢复。
- 节点源包括 VPNGate、VPNBook、30 天历史池和 `providers/` 手工 `.ovpn`；沿用出口 IP、TestISP 和流媒体检查逻辑。
- 管理面板和本地管理 API 免登录；12 个 SOCKS5 出口仍使用同一组代理账号密码。

## 启动

需要 Linux 主机提供 `/dev/net/tun`，Docker 具有 `NET_ADMIN` 能力。

```bash
export KUI_MANAGEMENT_PASSWORD='change-this-password'
docker compose up -d --build
```

`KUI_MANAGEMENT_PASSWORD` 是 12 个 SOCKS5 出口共用的代理密码，不是面板登录密码；面板免登录，不存在第二组管理密码。

如当前网络必须先经过临时 Clash SOCKS5 才能拉 VPNGate 源或建立 OpenVPN，可显式设置：

```bash
export KUI_FETCH_PROXY='socks5://host.docker.internal:7896'
export KUI_OPENVPN_SOCKS_PROXY='socks5://host.docker.internal:7896'
docker compose up -d --build
```

Compose 已映射 `host.docker.internal`。这两个变量默认均为空；直连可用时不要设置。`KUI_OPENVPN_SOCKS_PROXY` 下只能选择 TCP OpenVPN 节点，因为 OpenVPN 的 SOCKS 传输不支持 UDP 节点。

面板：`http://<VPS-IP>:8080/`

代理：

```text
SOCKS5 exit-01: socks5://admin:<same-password>@<VPS-IP>:7920
SOCKS5 exit-02: socks5://admin:<same-password>@<VPS-IP>:7921
...
SOCKS5 exit-12: socks5://admin:<same-password>@<VPS-IP>:7931
```

不要为容器设置 `HTTP_PROXY`、`HTTPS_PROXY` 或 `ALL_PROXY`。代理出口的路由由槽位 mark 和策略路由控制，不应依赖 Docker 或宿主机系统代理。

## 面板操作

在“住宅IP代理”页的“本机多出口槽位”区域：

- 修改两位国家代码或 `ANY`，修改端口后点击“保存”。
- 点击“换 IP”只重拨当前槽位；接受请求不代表隧道已经就绪，需观察状态变为 `ready`。
- 连续三次失败后槽位显示 `disabled`，点击“启用”才会重新拨号。
- 只有 `enabled=true`、状态为 `ready` 且 SOCKS5 监听器真实就绪的槽位才发布到订阅；卡片会明确显示未发布原因。
- `出口 IP`、`VPNGate 节点`、TestISP 的 ISP/住宅原始分类、每个目标 URL 的 HTTP 状态/分类/错误和槽位错误信息分开显示。
- Realm 页直接管理真实本地 `realm` 进程；镜像没有该二进制时明确显示“二进制不可用”，不会假报启动成功。
- “恢复默认展示”只清除固定槽位的探针展示元数据，不删除槽位和运行状态。

## 真实验证

先验证面板和槽位合同（管理页和本地 API 免登录）：

```bash
curl -fsS http://127.0.0.1:8080/api/local/exits
curl -fsS http://127.0.0.1:8080/healthz
```

隧道就绪后，逐端口验证实际出口：

```bash
curl --socks5-hostname admin:"$KUI_MANAGEMENT_PASSWORD"@127.0.0.1:7920 https://api.ipify.org
curl --socks5-hostname admin:"$KUI_MANAGEMENT_PASSWORD"@127.0.0.1:7921 https://api.ipify.org
```

按同样方式可逐槽验证全部 12 个出口。某个国家没有可用 VPNGate 节点时，槽位应显示失败/停用，不借用其他国家冒充成功。

## 重要说明

VPNGate 是出口来源；TestISP 等服务只是对当前出口 IP 做 ISP/住宅属性检测。检测结果未知不能显示为住宅成功，VPNGate 节点也不能仅因为标签或可连通就被保证为真实住宅线路。

本地容器已包含 24 槽调度、订阅输出和管理操作；实际可用槽数仍取决于 VPNGate 节点、目标国家和外部网络条件。部署后应按上面的命令逐槽核验真实出口。

## 桥接节点（链式代理）

在 `.env` 中配置 `KUI_BRIDGE_NODES` 和 `KUI_BRIDGE_SUB_URLS` 后，订阅会自动生成两类节点：

1. **桥接节点本身**：作为第一跳，可被 Clash/Mihomo 的 `dialer-proxy` 引用。
2. **链式节点**：每个 ready 槽位都会为每个桥接节点生成一个 `exit-XX-via-<桥接名>` 的节点，其 `dialer-proxy` 指向对应桥接节点。

流量路径：

```text
客户端 -> 桥接节点（VLESS/Hysteria2/SS/Trojan/HTTP/SOCKS5）
       -> VPS 上的 Reality 入站
       -> OpenVPN 出口
       -> 目标网站
```

配置示例（`.env`）：

```env
KUI_BRIDGE_NODES=hysteria2://pass@host:8443?sni=x#Hysteria2,vless://uuid@host:443?type=ws&security=tls&sni=x&path=/&host=x#BridgeNode
KUI_BRIDGE_SUB_URLS=https://example.com/sub1,https://example.com/sub2
```

- `KUI_BRIDGE_NODES`：逗号分隔的手动节点分享 URL，**直接信任**并加入订阅。
- `KUI_BRIDGE_SUB_URLS`：逗号分隔的免费订阅地址，本机会拉取、解析，并对每个节点做**连通性测试**，只保留能通 2 个及以上目标站的节点。

测试目标站固定为：

```text
https://chatgpt.com
https://claude.com
https://google.com
https://tradingview.com
```

测试方式：

- HTTP/SOCKS5 节点：直接用 `curl --proxy` 测试。
- VLESS/Hysteria2/Trojan/SS/VMess 节点：在容器内临时启动 `sing-box` 客户端，通过本地 SOCKS5 中转后 `curl` 测试。

并发限制为 8 个测试任务，结果缓存 5 分钟，避免频繁拉取/测试占用资源。

订阅输出示例（Clash YAML）：

```yaml
proxies:
  - name: "Hysteria2"
    type: hysteria2
    ...
  - name: "JP-日本 | KDDI | x.x.x.x | exit-01-via-Hysteria2"
    type: vless
    ...
    dialer-proxy: "Hysteria2"
```

注意：链式节点只在 Clash YAML 订阅中生效（依赖 `dialer-proxy`），普通 base64 订阅链接只能表示直连 Reality 节点。

### 自动刷新与测速

后台线程会按 `KUI_BRIDGE_REFRESH_INTERVAL`（默认 300 秒）自动拉取订阅、测试节点并更新缓存。相关环境变量：

```env
KUI_BRIDGE_REFRESH_INTERVAL=300   # 自动刷新周期（秒）
KUI_BRIDGE_SPEED_TEST=0           # 是否测速：0=只测连通性，1=测速并按速度取前 N
KUI_BRIDGE_TOP_N=16               # 测速时最多保留多少个节点
```

- 默认**不测速**，只保留能通 2 个目标站以上的节点，刷新较快。
- 开启 `KUI_BRIDGE_SPEED_TEST=1` 后，会对每个有效节点下载一个 200KB 文件测速，并保留最快的 `KUI_BRIDGE_TOP_N` 个。

## 自动恢复停用的槽位

槽位连续 3 次拨号/健康失败后会自动停用。容器启动后会每 **60 秒** 检查一次：如果当前节点池中有可用且未被其他槽位占用的节点，就自动重新启用该槽位并尝试重拨。节点池本身仍每 10 分钟刷新一次。
