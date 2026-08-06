# K-UI Local Multi-Exit 返工设计规格

## 背景与目标

当前提交已经具备 12 个槽位、SQLite、本地 API、VPNGate/OpenVPN 调度和 K-UI 页面骨架，但审计证明它不能满足“无空壳、不能伪造就绪、真实多出口可验收”的交付要求。

本次返工不重新设计产品，也不删减现有页面。目标是修复现有实现，使它满足用户已经明确的最终合同：

- 独立 GitHub 项目，单 VPS、单 Docker 容器、固定 12 个出口槽位；
- 管理页面和本地管理 API免登录，不出现系统准入或双重登录；
- 12 个代理出口共用同一组 SOCKS5/HTTP 用户名和密码；
- 原 K-UI 管理入口与能力必须真实可操作，不能仅保留 UI、空数组或占位文案；
- 每槽独立国家、候选 VPNGate 节点、端口、OpenVPN、TUN、策略路由和代理监听；
- 只有监听、路由和真实出口验证全部成功才可进入 `ready`；
- 未就绪、失败或停用槽位不能出现在可用代理列表和订阅中；
- TestISP 只有明确返回 `residential` 才标记住宅，未知、失败和错误出口均 fail-closed；
- 临时控制面可使用 `socks5://host.docker.internal:7896`，但代理数据面不得继承宿主或 Docker 的通用代理环境；
- 以真实 Docker/OpenVPN/TUN/SOCKS5 结果作为验收证据，单元测试不能代替真实数据面验证。

用户已明确要求直接继续返工，无需重新选择优先级。本规格取代旧规格中与上述最终合同冲突的两点：管理 Basic Auth、管理凭据与代理凭据分离。最终合同以“管理免登录、代理单组密码”为准。

## 方案比较

### 方案 A：在现有实现上分层修复（采用）

保留当前 Python/SQLite/K-UI 架构，按数据面、存储/API、前端功能、部署验收四层修复。优点是改动可控，现有 95 个测试和原版代码仍可复用；缺点是必须删除当前自洽但错误的合同测试，并对大体量 `index.html` 和 `local_api.py` 做谨慎补齐。

### 方案 B：回到原 K-UI 远程控制架构再加多出口

保留 Cloudflare/D1/Realtime/VPS Agent，全功能天然完整，但与“单机本地管理”冲突，部署复杂度和外部依赖明显增加，不采用。

### 方案 C：只保留本地多出口页，移除原 K-UI 其他入口

实现最简单，但直接违反“不能删减、隐藏或做空壳”，不采用。

## 架构与模块边界

### 1. 槽位状态机

`ExitManager` 是唯一能推进槽位运行状态的组件。每个槽位的 worker、OpenVPN process、listener、stop event 和 generation 都必须在同一 runtime lock 下检查和提交。

有效状态流：

```text
disabled -> idle -> starting -> connecting -> validating -> ready
                           \-> failed -> retry/backoff -> starting
                                      \-> disabled (连续三次失败)
```

进入 `ready` 的原子门槛：

1. 当前槽位仍 enabled，generation 与 worker 一致；
2. OpenVPN 初始化完成；
3. endpoint 保护路由、默认 TUN 路由和 fwmark rule 全部执行成功；
4. 从对应 TUN 探测到非空、格式有效的真实出口 IP；
5. TestISP 明确返回 `residential`；
6. 当前配置的目标 URL 探针满足状态码策略；
7. 代理监听器已成功 bind，并在限定时间内设置 `ready`；
8. 再次在 runtime lock 与存储事务中核对 generation 后提交 `ready`。

任一步失败必须停止 listener/process、清理该槽路由、清空旧运行态字段并记录失败；禁止使用 VPNGate endpoint IP 回退为 egress IP。

### 2. 路由和监听强失败

`RouteManager.install()` 对每条必要命令检查返回码，错误消息包含命令与 stderr。`cleanup()` 保持幂等，可忽略“不存在”类删除失败，但不能让安装失败静默通过。

`ProxyListener.start()` 改为同步等待 bind 结果：成功返回，失败抛出原始异常；`stop()` 关闭监听 socket 和已接受客户端，避免重拨残留连接。并发额度按 listener 或槽位隔离，不使用跨 12 槽共享的全局 semaphore。

### 3. generation 与停止语义

- 停用、重拨、配置变更和失败处理必须先递增 generation，再终止旧 runtime。
- worker 在每个外部边界后检查 generation：OpenVPN 初始化、路由安装、出口探测、住宅探测、目标站探测和 listener bind。
- 状态写入提供 `set_runtime_if_generation()` 事务接口，旧代际永远不能覆盖新状态。
- `stop_slot()` 如果 worker 在限定时间未退出，不能假装已完成；槽位进入 `failed` 并保留明确错误，旧 worker 即使随后返回也无法提交。

### 4. VPNGate 节点快照

SQLite 增加 `vpn_nodes` 表，保存节点 IP、国家、速度、ping、配置、更新时间和惩罚值。刷新成功时事务替换快照；刷新失败时保留旧快照并记录事件。进程启动先加载快照，再异步刷新，因此临时网络故障不会让候选选择器变空。

手动指定节点和自动选择使用同一个资格检查：国家匹配、未被其他槽位占用、配置协议兼容当前 OpenVPN SOCKS 控制代理。UDP-only 配置在 SOCKS 控制代理启用时不得被手动绕过。

### 5. API、代理发布与配置事务

- `/api/proxy/proxies`、普通订阅和 Clash 订阅只发布 `enabled && state == ready && listener_ready` 的槽位。
- 失败时清空 `entry_ip`、`egress_ip`、`current_node`、`check_result`；历史保留在 events/check history，而不是当前快照。
- 配置更新先在数据库事务中完整校验，再停止旧槽位；若后续启动失败，保留新配置和真实失败状态，不能因输入校验错误中断健康槽位。
- `/api/proxy/switch` 必须按明确槽位 ID 或映射后的目标处理；不再读取后忽略 `ip`，也不默认误切第一个槽位。
- 自定义端口采用固定容器端口合同：每个槽位只允许在已发布的 `7920-7931` 中选择且保持唯一。UI 允许重新分配这 12 个端口，但不承诺任意宿主端口。这样 Compose、README 和运行时保持一致。
- 管理页面/API保持免登录；删除无效的登录 UI、`/api/login` token 流和伪造 `Bearer local` 死合同。代理用户名/密码仍由环境配置，并只在确实需要展示/生成订阅的管理接口返回。

### 6. 目标 URL 验证

设置中保存目标 URL 列表，默认包含：

```text
https://www.google.com/
https://chatgpt.com
https://cn.tradingview.com
https://claude.ai
```

每槽从对应 TUN 逐项探测并保留每个 URL 的状态码、错误和耗时。状态码策略：

- 默认 `generate_204` 探针必须精确返回 204；
- 自定义目标接受 2xx 和目标站明确应答的 4xx，但 407 不接受；
- 3xx、5xx、连接失败和超时不接受；
- 槽位就绪策略采用“基础出口探针成功，且配置的自定义目标至少一个明确应答”；UI逐项展示结果，不把单个站点成功描述成四站全部可用。

修改目标列表后递增 probe revision，旧检测结果失效并触发所有 enabled 槽位复检；旧 revision 的 worker 结果不得应用。

## 原 K-UI 功能补齐

本地版可以移除 Cloudflare、跨 VPS 心跳和远程脚本下发机制，但不能保留依赖这些机制的空壳 UI。处理原则不是隐藏，而是将入口改接本地实现：

- **服务器与节点**：SQLite 完整保存 UI 表单字段，包括端口、UUID、SNI、密钥、传输参数、流量和到期；创建、编辑、删除、启停和订阅输出必须往返不丢字段。
- **服务器出口设置**：保存并返回 `egress_mode`、`proxy_mode`、`proxy_categories`、revision/status/error。单机本地模式下目标明确映射到本地槽位；不支持的远程 VPS 操作必须显示明确错误，不能 200 后丢字段。
- **Full Deploy Command**：本地项目不再依赖远端 `agent_token` 和不存在的 `/api/agent_update`。改成生成当前独立项目的 Docker Compose 本机部署/更新命令，或在已有本机实例上显示“不需要额外 Agent”的可执行维护命令；不能显示等待不存在 token 的文案。
- **探针与统计**：使用本地事件和槽位检查历史生成真实统计与探针数据，不返回固定空数组。至少提供 12 槽当前状态、出口、失败、延迟和历史事件；UI现有图表读取真实本地数据。
- **Realm**：保留原版入口并提供本地 Realm 配置、启停、状态和持久化；若镜像未安装 Realm，页面必须提供安装/启用动作及明确状态，不得只有规划占位文案。
- **第三方订阅与协议**：解析成功的协议必须能在普通或 Clash 输出中无损导出；SSR 要么完整支持，要么在导入时明确拒绝并说明，不允许“解析成功后静默丢失”。
- **多用户、系统设置、订阅保护**：CRUD、密码、配额、到期、启停和订阅输出均以 API 往返测试和浏览器操作验证，不仅检查页面文本存在。

## Docker 与控制面代理

Compose 显式透传：

```text
KUI_FETCH_PROXY
KUI_OPENVPN_SOCKS_PROXY
```

并添加 Linux 兼容映射：

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

应用继续清理 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY`、`NO_PROXY` 及小写变量。两个 `KUI_*` 变量只能用于 VPNGate 拉取和 OpenVPN 握手，代理监听器和出口目标探针不能读取它们。

`.gitignore` 增加 `*.ovpn`、`*.log`、`auth.txt`、`socks_auth.txt` 和运行时配置目录。生成的认证文件、VPN 配置和日志使用 `0600`。

Docker healthcheck 继续报告控制面进程健康，但 `/api/local/status` 另外提供 ready/failed/disabled 数量；文档明确“容器 healthy 不等于 12 个出口 ready”。

## 错误处理

- 所有外部命令错误保留命令、返回码和限长 stderr；UI显示槽位最后错误。
- 失败槽位不发布代理，且只允许明确手动启用或该槽自己的退避重试。
- 配置被新 revision 取代时，旧任务返回“已过期，结果未应用”，UI按钮仍可再次触发，不出现不可点击死状态。
- 目标站被 WAF 返回 403 时记录“目标明确应答”，不能写成页面内容可正常使用；连接超时则记录失败。
- 真实节点不足时允许少于 12 个 ready，但必须准确显示 unavailable/failed，禁止用重复出口或宿主出口凑数。

## 测试与验收

### 自动测试

补齐以下回归测试，现有错误合同必须改写：

- 监听端口占用不能进入 ready；
- 任一路由安装命令失败不能进入 ready；
- 出口 IP 为空不能回退 endpoint；
- fail/redial/config 与 commit_ready 并发时旧 generation 不可提交；
- idle/failed/disabled 槽位不进入代理列表和订阅；
- 失败清空当前运行态但事件保留历史；
- 无效配置不会停止健康槽位；
- VPNGate 快照跨进程恢复，刷新失败保留旧快照；
- 手动 UDP 节点不能绕过 SOCKS 控制代理资格检查；
- 自定义端口只允许已发布的 12 端口；
- 四个目标 URL 的状态码策略和 revision 失效；
- 原管理页面所有入口执行真实 API，不存在 token/字段/空数组/占位合同；
- SSR 导入与输出一致；
- Compose 正确传递控制面代理和 host-gateway；
- Python 3.12 容器内运行完整测试。

### 真实集成验收

在不伪造结果的前提下：

1. 使用 Docker Compose 重建并启动；
2. 临时设置 `KUI_FETCH_PROXY=socks5://host.docker.internal:7896` 和 `KUI_OPENVPN_SOCKS_PROXY=socks5://host.docker.internal:7896`；
3. 先启 2 槽，逐端口验证 `api.ipify.org` 与槽位 `egress_ip` 一致且两个出口不混淆；
4. 扩展到 6 槽和 12 槽，节点不足或目标不通必须如实记录失败；
5. 对每个 ready 槽验证 Google、ChatGPT、TradingView、Claude 的实际状态，并区分 2xx、403/WAF、重定向和超时；
6. 验证单槽换 IP、国家修改、端口重新分配不影响其他槽；
7. 人工制造三次失败，确认自动停用、代理从订阅消失、一键/单槽手动启用恢复；
8. 重启容器，确认槽位配置、VPNGate 快照、管理数据恢复；
9. 用无头浏览器逐页操作服务器、节点、多用户、住宅代理、Realm、第三方服务、第三方订阅、系统设置和探针；每个按钮必须产生可观察的 API/状态变化；
10. 最终运行完整单元测试、容器内测试、编译检查、Compose 配置检查和 Git 状态检查。

验收不要求公共 VPNGate 在某一时刻恰好提供 12 个合格住宅出口；要求是调度、状态和 UI真实准确，并对每个实际 `ready` 出口提供可重复证据。

## 完成条件

只有同时满足以下条件才能报告完成：

- 审计列出的 Critical/High 逻辑缺陷均有回归测试并修复；
- 所有原管理入口没有静默丢字段、固定空结果或占位页；
- 单元/合同测试全绿；
- Docker/Python 3.12 测试全绿；
- 至少 2 个真实独立出口完成端到端验证，随后按可用节点扩展验证 6/12 槽；
- 所有 ready 槽逐端口出口 IP 与 API 快照一致；
- 管理页面无登录，代理使用单组账号密码；
- 独立仓库 `main` 工作区干净并推送最终提交。
