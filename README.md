## 🌟 项目赞助商 (Sponsor)

<p align="center">
  <a href="https://derouter.ai?ref=0oZZ1HVc" target="_blank">
    <b>DeRouter</b> — 基于区块链的纯正透明大模型 API 网关
  </a>
</p>

**DeRouter** 通过区块链技术保证 Claude、GPT 官方 API 的**纯正与透明**，杜绝掺水降智问题。目前 Claude、GPT 在能力上仍领先国内大模型。

- 🔗 官网：https://derouter.ai?ref=0oZZ1HVc
- 🐦 Twitter：https://x.com/derouter_net
- 💰 **有多余的 Claude 账号**：可托管到平台赚取收益
- ⚡ **有 API 需求**：可使用其平台，价格为官方 API 的 **1-2 折**

<br>

<p align="center">
  <a href="https://bytevirt.com/aff.php?aff=209" target="_blank">
    <b>ByteVirt</b> — 始于方寸字节，成就无限云端
  </a>
</p>

**ByteVirt** 是一家专注于高性价比云服务器的 VPS 厂商，提供稳定可靠的虚拟化云端主机，适合部署 KUI 节点、探针 bash 及各类自建服务。

- 🔗 官网：https://bytevirt.com/aff.php?aff=209
- 🖥️ **多地域机房**：可按需选择节点位置，满足代理与监控部署需求
- ⚡ **稳定高速**：优质网络与虚拟化性能，保障服务长期在线

---

# KUI x Server Monitor Pro

KUI 是一套基于 Cloudflare 的代理管理、服务器探针和住宅双隧道面板。

- Pages：网页、API、登录和配置。
- D1：保存用户、VPS、节点和流量。
- Realtime Worker + Durable Objects：提供实时状态和配置推送。
- VPS Agent：监控服务器、管理 sing-box 和住宅代理。

## 功能

- XTLS-Reality、Hysteria2、TUIC、Trojan、H2/gRPC-Reality、AnyTLS、Naive、VLESS-Argo。
- CPU、内存、磁盘、负载、网速、TCP/UDP 和线路延迟探针。
- 多用户、流量、配额、到期和订阅管理。
- OpenVPN 主备住宅隧道和 SOCKS5/HTTP 代理。
- WebSocket 实时推送，断线后自动使用 HTTP fallback。
- 每台 VPS 可选择原生、WARP、住宅代理或 SOCKS5 出口。
- 住宅 SOCKS5 运行时节点可追加到管理员普通订阅和 Clash/Mihomo 订阅。
- 管理员订阅保护开关：临时停止订阅更新并返回站点首页内容。
- Realm 中转入口已预留，当前为功能规划占位页。

## 实时状态与额度

Realtime Worker 会根据正在查看面板的人群自动调整 VPS Agent 的常规状态频率：

| 查看状态 | Core/Proxy 状态频率 | 说明 |
|---|---:|---|
| 管理员后台 Dashboard WebSocket 在线 | 5 秒 | 配置、出口切换和实时运维使用最高频率 |
| 仅公开探针 WebSocket 在线 | 10 秒 | 公开探针保持接近实时，同时减少 Worker/DO 消耗 |
| 没有 Dashboard 或公开探针观众 | 30 秒 | 空闲降频，仍保持 Agent 在线与状态更新 |

以下事件不等待状态周期，会立即推送：

- VPS 或住宅代理上线、掉线。
- 节点和 Agent 配置下发结果。
- WARP、住宅代理、手动 SOCKS5 出口切换结果。

两台 VPS 各运行 Core 与 Proxy Agent 时，公开探针持续有人查看的常规状态消息约为 `34,560/天`；无人查看时约为 `11,520/天`。管理员后台持续打开时约为 `69,120/天`。实际 Workers & Pages 用量还会受订阅拉取、公开页面访问、WebSocket 重连和 D1 操作影响。

## 节点出口与住宅代理

每台 VPS 可在“服务器与节点 → 节点出口”选择：

- 原生出口。
- WARP IPv4、WARP IPv6 或 WARP 双栈。
- 住宅 IP 代理。
- 手动 SOCKS5 出口。

住宅 IP 代理支持两种模式：

- **全局代理**：所有受管节点流量通过住宅 SOCKS5 出口。
- **局部代理**：仅已选择的分类域名通过住宅出口，例如 YouTube、Googlevideo 和 YTimg。

局部代理会使用 sing-box 域名嗅探规则来匹配 TLS/HTTP 目标域名。住宅出口只验证 IPv4；在局部模式下，受管节点的 IPv6 流量会被明确拒绝，避免从 WARP 双栈切换后发生 IPv6 绕过或原生 IPv6 泄漏。

修改局部代理分类时，先勾选分类，再点击“应用已选分类”。单个分类勾选不会立即递增出口 revision 或重建 sing-box 配置。

## 订阅保护

管理员可在：

```text
系统设置 → 管理员订阅防泄漏重置 → 订阅保护
```

直接切换订阅保护开关，变更会立即保存，不需要点击“立即生效配置”。

- **关闭**：订阅链接可被客户端正常在线更新。
- **开启**：`/api/sub` 不验证 Token、不读取节点数据，直接返回普通站点首页 HTML；订阅客户端不会获得真实节点，从而停止在线更新。

订阅保护适合在链接疑似泄露、需要临时停止拉取时使用。它不等于完整访问控制：已暴露的订阅路径仍可能被访问记录识别。长期保护建议同时轮换订阅 Token，并使用独立订阅域名、Cloudflare Access 或可信 IP 访问限制。

# 新用户部署

推荐使用下面的顺序，不要跳步：

```text
1. Fork GitHub 仓库
2. 创建一个 Cloudflare D1 数据库
3. 创建 Cloudflare Pages，并绑定这个 D1
4. 配置 Pages 生产环境变量
5. 首次登录 Pages，确认数据库初始化
6. 部署 Realtime Worker，并绑定同一个 D1
7. 检查 Worker /health
8. 将 Worker 地址写回 Pages，重新部署
9. 在 KUI 面板添加 VPS
10. 在 VPS 执行面板生成的 Full Deploy Command
11. 添加节点并验证订阅
```

## 0. 部署前准备

需要准备：

- GitHub 账号。
- Cloudflare 账号，并已添加一个可用的 Pages 账户。
- 一台 Debian/Ubuntu 或 Alpine VPS。
- VPS 公网 IPv4 或 IPv6。
- VPS 可以访问外部 HTTPS。
- VPS SSH root 权限。

建议先不要部署住宅代理。先完成 Pages、Worker、Agent 和普通节点验证，再启用住宅出口。

## 1. Fork 仓库

打开仓库：

```text
https://github.com/a6216abcd/K-UI
```

点击右上角 **Fork**，将仓库复制到自己的 GitHub 账号。

后续 Cloudflare Pages 必须连接你 Fork 后的仓库，不要连接上游仓库。

## 2. 创建 D1 数据库

进入 Cloudflare 控制台：

```text
Workers & Pages → D1 → Create database
```

数据库名称建议填写：

```text
kui-db
```

创建完成后记录数据库名称。Pages 和 Realtime Worker 必须绑定同一个 D1 数据库，不能各自使用自动创建的空数据库。

## 3. 创建 Pages 项目

进入：

```text
Workers & Pages → Create application → Pages → Connect to Git
```

选择你 Fork 的 KUI 仓库，使用以下设置：

| 设置项 | 填写内容 |
|---|---|
| Production branch | `dev`，或你准备发布的分支 |
| Framework preset | `None` |
| Build command | `exit 0` |
| Build output directory | `.` |

点击部署，等待 Pages 首次构建成功。

部署成功后打开 Pages 地址：

```text
https://你的项目.pages.dev
```

## 4. 绑定 Pages 的生产 D1

进入 Pages 项目：

```text
Settings → Functions → D1 database bindings
```

在 **Production** 环境添加：

| Binding name | Database |
|---|---|
| `DB` | 第 2 步创建的 `kui-db` |

必须满足：

- Binding name 必须是 `DB`，大小写不能变。
- 必须绑定在 Production，不要只绑定 Preview。
- 修改 binding 后必须重新部署 Pages。

## 5. 配置 Pages 生产环境变量

进入：

```text
Settings → Environment variables → Production
```

添加以下变量：

| 名称 | 类型 | 说明 |
|---|---|---|
| `ADMIN_USERNAME` | Variable | 管理员用户名，建议使用 `admin` |
| `ADMIN_PASSWORD` | Secret | 管理员强密码，至少 16 位 |
| `PROXY_USER` | Secret | 住宅代理用户名 |
| `PROXY_PASS` | Secret | 住宅代理密码 |

第一次部署可以暂时不添加：

```text
REALTIME_URL
```

保存变量并重新部署 Pages。

## 6. 首次登录并初始化数据库

打开：

```text
https://你的项目.pages.dev
```

使用刚配置的 `ADMIN_USERNAME` 和 `ADMIN_PASSWORD` 登录。

登录后进入“服务器与节点”，确认页面可以正常加载。此时 Pages + D1 基础部署完成。

如果页面提示缺少 DB、登录后 500 或数据无法加载，不要继续部署 Worker，先回到第 4 步检查 D1 binding。

## 7. 部署 Realtime Worker

Realtime Worker 用于实时状态、Dashboard WebSocket 和配置通知。它不是 Pages 本身，必须单独部署。

### 推荐方法：本地 Wrangler 部署

使用本地 Wrangler 可以明确指定 Pages 地址和已有 D1，最不容易绑定到错误的空数据库：

```bash
git clone https://github.com/a6216abcd/K-UI.git
cd K-UI/realtime
npm install
npx wrangler login
```

确认 `wrangler.jsonc` 的 `d1_databases` 使用 Pages 第 2 步创建的同一个数据库：

```jsonc
"d1_databases": [
  {
    "binding": "DB",
    "database_name": "kui-db",
    "database_id": "你的 D1 database_id"
  }
]
```

然后部署：

```bash
npx wrangler deploy
```

### 使用自定义域名时必须设置 PAGES_ORIGIN

默认 Pages 地址形如：

```text
https://你的项目.pages.dev
```

不需要设置 `PAGES_ORIGIN`，Realtime Worker 会自动接受该 Pages 域名的 WebSocket 连接。

如果你为 Pages 绑定了自定义域名，例如：

```text
https://panel.example.com
```

必须进入 Worker：

```text
Workers & Pages → kui-realtime → Settings → Variables and Secrets
```

新增或修改 Worker **Variable**：

| 名称 | 值 |
|---|---|
| `PAGES_ORIGIN` | `https://panel.example.com` |

要求：

- 必须包含 `https://`。
- 末尾不要添加 `/`。
- 必须填写 Pages 实际对外访问的自定义域名，不是 Worker 地址。
- 保存变量后重新部署 Worker。

否则 Worker 会拒绝来自自定义域名的 Dashboard / 公开探针 WebSocket，页面会退回旧数据或 HTTP fallback。

### 备用方法：Cloudflare 一键部署

如果无法使用本地 Node.js，可以使用按钮：

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/a6216abcd/K-UI/tree/dev/realtime)

部署时确认 Worker 名称为：

```text
kui-realtime
```

一键部署完成后，仍必须按照下面的“Worker 必须绑定同一个 D1”检查 DB binding。不要直接使用它自动创建的空 D1。

### Worker 必须绑定同一个 D1

进入：

```text
Workers & Pages → kui-realtime → Settings → Bindings
```

确认：

```text
DB              → 与 Pages 完全相同的 kui-db
VPS_PRESENCE    → VpsPresence
DASHBOARD_HUB   → DashboardHub
```

最容易出错的是 Worker 自动创建了另一个 D1。发现 Worker 的 DB 不是 Pages 正在使用的 D1 时，删除错误 binding，重新绑定正确的数据库。

不要修改或删除两个 Durable Object binding：

```text
VPS_PRESENCE
DASHBOARD_HUB
```

## 8. 验证 Worker

打开：

```text
https://你的Worker地址/health
```

应该返回：

```json
{"ok":true,"service":"kui-realtime","version":1}
```

如果不是这个结果，先不要继续配置 Pages 的 `REALTIME_URL`。

## 9. 回填 Pages 的 REALTIME_URL

确认 Worker `/health` 正常后，回到 Pages：

```text
Settings → Environment variables → Production
```

添加：

| 名称 | 类型 | 值 |
|---|---|---|
| `REALTIME_URL` | Variable | `https://你的Worker地址` |

注意：

- 必须使用 `https://`。
- 末尾不要添加 `/`。
- 必须填写 Worker 地址，不是 Pages 地址。

保存后重新部署 Pages。重新登录后台，确认 Dashboard 实时状态可以连接。

## 10. 添加 VPS

登录 KUI 后台，进入：

```text
服务器与节点 → 接入机器
```

填写：

- VPS 名称。
- VPS 公网 IP。
- 系统类型：Debian/Ubuntu 或 Alpine。

点击接入机器。

添加后，服务器卡片会生成专属的 **Full Deploy Command**。

## 11. 安装 VPS Agent

只复制面板当前生成的完整命令，在对应 VPS 的 root Shell 执行。

不要：

- 手动替换 Agent Token。
- 把其他 VPS 的命令复制到本机。
- 把管理员密码写入安装命令。
- 在本地 Windows 终端执行 Linux 安装命令。

Full Deploy 会安装并管理：

- `kui-agent`
- `sing-box`
- `proxy-lite`
- Core/Proxy realtime client
- 住宅代理所需组件

Debian/Ubuntu 检查：

```bash
systemctl is-active kui-agent sing-box
systemctl status kui-agent --no-pager
journalctl -u kui-agent -n 80 --no-pager
```

Alpine 检查：

```bash
rc-service kui-agent status
rc-service sing-box status
tail -n 80 /var/log/kui-agent.log
```

等待 30-90 秒后刷新面板。服务器卡片显示在线，且 CPU、内存、磁盘和网速开始更新，说明 Agent 部署成功。

## 12. 创建第一个节点

先使用单节点创建测试，确认单节点可用后再使用“极速全量节点下发（8合1）”。

推荐测试顺序：

1. XTLS-Reality。
2. Hysteria2。
3. H2-Reality。
4. gRPC-Reality。
5. 其它协议。

使用 Clash Meta/Mihomo 时：

- H2-Reality 的旧版 Mihomo 可能在延迟测试中显示超时，但节点实际可用。
- 建议使用较新的 Mihomo 内核，并直接访问网页验证节点。
- 不要只依据延迟测试结果判断 H2-Reality 是否可用。

## 13. 启用 8 合 1

确认单节点测试成功后，在服务器卡片中填写起始端口，例如：

```text
8881
```

面板会连续创建：

```text
XTLS-Reality
Hysteria2
TUIC
Trojan
H2-Reality
gRPC-Reality
AnyTLS
Naive
```

起始端口必须满足：

```text
起始端口 >= 10
起始端口 + 7 <= 65535
```

确认 VPS 安全组和系统防火墙允许对应 TCP/UDP 端口：

- XTLS-Reality、Trojan、H2-Reality、gRPC-Reality、AnyTLS、Naive：TCP。
- Hysteria2、TUIC：UDP。

## 部署成功标准

满足以下条件，才算部署完成：

- Pages 可以登录。
- Pages Production 有 `DB` binding。
- Worker `/health` 返回成功。
- Pages 和 Worker 使用同一个 D1。
- Pages 已设置正确的 `REALTIME_URL`。
- VPS `kui-agent` 和 `sing-box` 为 active。
- 面板能显示 VPS 在线状态。
- 修改节点后 VPS 能自动更新配置。
- 订阅能正常生成。
- 至少一个 XTLS-Reality 或 Hysteria2 节点实际可用。
- H2-Reality 要使用较新的 Mihomo 进行测试，旧内核可能只误报延迟超时。

# 常见问题

## Pages 提示缺少 DB

检查：

```text
Pages → Settings → Functions → D1 database bindings
```

确认 Production 环境存在：

```text
DB → 正确的 D1 数据库
```

修改后重新部署 Pages。

## Worker `/health` 正常但面板没有实时状态

依次检查：

1. Worker 的 `DB` 是否与 Pages 使用同一个 D1。
2. Pages Production 是否设置 `REALTIME_URL`。
3. `REALTIME_URL` 是否使用 HTTPS，末尾是否多了 `/`。
4. 浏览器是否重新登录并刷新页面。

## Agent 返回 401 或 403

- VPS 公网 IP 必须先添加到 KUI 面板。
- 必须使用该 VPS 对应的 Full Deploy Command。
- Token 过期或丢失时，重新从面板复制命令并执行。
- 历史 Agent 如果使用旧鉴权方式，必须重新执行当前版本 Full Deploy Command。

## VPS 在线但节点不可用

Debian/Ubuntu：

```bash
systemctl is-active sing-box
sing-box check -c /etc/sing-box/config.json
journalctl -u sing-box -n 100 --no-pager
ss -ltnup
```

Alpine：

```bash
rc-service sing-box status
sing-box check -c /etc/sing-box/config.json
tail -n 100 /var/log/sing-box.log
ss -ltnup
```

重点检查：

- 端口是否被其他服务占用。
- 云安全组是否放行正确的 TCP/UDP 协议。
- Reality 的公钥、short ID、UUID 是否来自同一个节点。
- SNI 是否为空或拼写错误。
- H2/gRPC 节点是否使用了过旧的客户端内核。

## H2-Reality 显示延迟超时

部分旧 Mihomo/Clash Verge 内核会把 H2-Reality 的延迟检测判定为超时，但实际连接仍然可用。

处理方式：

- 更新 Mihomo/Clash Verge 内核。
- 手动选择节点访问网页测试。
- 查看客户端连接日志，而不是只看延迟数字。

## WARP 出口失败

WARP 是可选功能，不影响原生节点部署。先切回：

```text
节点出口 → 原生出口
```

然后检查：

```bash
systemctl status kui-agent --no-pager
journalctl -u kui-agent -n 100 --no-pager
```

常见原因：

- VPS 没有可用 IPv6，却选择了 WARP IPv6 或双栈。
- WARP 数据面校验失败。
- VPS 网络阻断 WireGuard/UDP。
- 系统时间不正确。

## 住宅代理显示 0/2 或 1/2

检查：

- `/dev/net/tun` 是否存在。
- `proxy-lite` 是否运行。
- OpenVPN 是否可以访问外网。
- Pages 是否配置 `PROXY_USER` 和 `PROXY_PASS`。
- 所选国家是否有可用公开 VPN 节点。

住宅代理依赖公开节点和网络质量，不保证始终为 2/2。建议先完成原生出口部署，再单独测试住宅出口。

## 一键 Worker 部署失败

使用本地 Wrangler：

```bash
git clone https://github.com/a6216abcd/K-UI.git
cd K-UI/realtime
npm install
npx wrangler login
```

编辑 `wrangler.jsonc`：

- 填写 Pages 正在使用的 `database_name`。
- 填写同一个 D1 的 `database_id`。
- 使用默认 `*.pages.dev` 域名时不需要配置 `PAGES_ORIGIN`。**绑定自定义域名后必须**在 Worker 环境变量中设置 `PAGES_ORIGIN=https://你的自定义域名`，保存后重新部署 Worker。

然后执行：

```bash
npx wrangler deploy
```

部署后仍然要回到第 7-9 步检查 Worker binding、`/health` 和 Pages 的 `REALTIME_URL`。

# 更新与安全

VPS 组件每小时通过 Pages 鉴权端点检查更新，验证组件名、长度、SHA-256 和基于 Agent Token 的 HMAC 更新清单，通过 Python 语法检查后原子替换。更新后的 Agent 需要完成配置拉取、核心服务健康检查和首次状态上报后才确认新版本。

自动更新文件包括：

```text
/opt/kui/agent.py
/opt/kui/realtime_client.py
/opt/proxy_lite/lite_manager.py
/opt/proxy_lite/proxy_server.py
/opt/proxy_lite/realtime_client.py
```

安全要求：

- `ADMIN_PASSWORD`、`PROXY_USER`、`PROXY_PASS` 使用 Secret。
- 不要公开 Agent Token、Cloudflare API Token 或 VPS root 密码。
- 第三方订阅导入仅允许 HTTPS 公网地址；本机、私网和保留地址会被拒绝。
- 开启订阅保护时，所有正常订阅客户端也不能更新；恢复前请确认不需要在线更新。
- 住宅代理端口只允许可信来源访问。
- 后台自定义 Script 可以执行任意 JavaScript，只允许可信管理员使用。
- 如果 root 密码曾经出现在聊天、Issue 或日志中，立即修改密码。

# 项目结构

```text
KUI/
├── index.html
├── functions/api/[[path]].js
├── realtime/
│   ├── src/index.js
│   ├── wrangler.jsonc
│   └── package.json
└── vps/
    ├── agent.py
    ├── realtime_client.py
    ├── kui.sh
    ├── lite_manager.py
    ├── proxy_server.py
    └── residential-proxy.sh
```

# 支持与贡献

- Issues：https://github.com/a6216abcd/K-UI/issues
- Pull Requests：https://github.com/a6216abcd/K-UI/pulls

提交 Issue 时不要附带密码、Token 或完整 VPS 配置。
