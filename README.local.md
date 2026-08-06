# K-UI Local Multi-Exit

这是从 K-UI 原有 VPNGate/OpenVPN/住宅检测逻辑派生的单 VPS 本地版。它不使用 Cloudflare Pages、Workers、D1 或 Realtime 控制中心，单个 Docker 容器内运行本地面板、SQLite、VPNGate 调度器和多个 OpenVPN 出口。

## 当前能力

- 固定 12 个出口槽位，默认 `JP/US/GB/DE/KR/SG` 每国两个。
- 每个槽位可独立修改国家和端口。
- 每个槽位一条 OpenVPN 隧道、一个 TUN 设备、一个 SOCKS5/HTTP 端口。
- 端口 `7920` 至 `7931` 对应 `exit-01` 至 `exit-12`。
- 单槽位换 IP、停用、启用和独立失败状态。
- 连续三次拨号/健康失败后自动停用该槽位。
- 沿用原项目的 VPNGate 节点、出口 IP、TestISP 和流媒体检查逻辑。
- 管理面板和本地管理 API 免登录；12 个 SOCKS5 出口仍使用同一组代理账号密码。

## 启动

需要 Linux 主机提供 `/dev/net/tun`，Docker 具有 `NET_ADMIN` 能力。

```bash
export KUI_MANAGEMENT_PASSWORD='change-this-password'
docker compose up -d --build
```

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
- `出口 IP`、`VPNGate 节点`、`原检查结果`和错误信息分开显示。

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

本地容器已包含 12 槽调度、订阅输出和管理操作；实际可用槽数仍取决于 VPNGate 节点、目标国家和外部网络条件。部署后应按上面的命令逐槽核验真实出口。
