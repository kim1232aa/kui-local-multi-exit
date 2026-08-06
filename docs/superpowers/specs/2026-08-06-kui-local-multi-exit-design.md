# K-UI Local Multi-Exit 设计规格

## 目标

从 K-UI 的现有 VPNGate、OpenVPN、出口 IP/住宅检测、代理服务和面板逻辑派生一个单 VPS 本地部署版本，只增加多个相互独立的出口槽位，不重新定义原有检测标准。

## 边界

保留原有逻辑：

- VPNGate API 节点获取与解析
- OpenVPN 配置清洗、认证和启动
- 出口 IP、目标站点、ISP/住宅检测
- SOCKS5/HTTP 代理协议和代理认证
- 节点失败、换 IP、重拨、日志
- K-UI 面板的现有功能和视觉风格

本地版移除单机不需要的远程控制链：Cloudflare Pages/Workers、D1、Realtime C2、跨 VPS Agent 心跳和远程脚本下发。管理 API 与面板由同一应用本地提供，数据用 SQLite 持久化。

唯一新增的核心能力是多出口：固定 12 个槽位，每个槽位可独立配置国家、代理端口和启停状态。默认国家只作为初始配置，不写死在调度逻辑中。

## 运行形态

```text
Docker Compose
└── kui-local-multi-exit
    ├── 本地管理 API + K-UI 面板
    ├── SQLite
    ├── VPNGate 节点池和调度器
    ├── 12 个 OpenVPN 客户端进程
    └── 12 个独立 SOCKS5/HTTP 监听器
```

单容器内部运行多个 OpenVPN 进程；每个槽位使用唯一 TUN 设备、独立路由表和独立代理端口。容器需要 `/dev/net/tun` 与网络管理能力，但不拆成 12 个容器。

## 多出口模型

```text
ExitSlot
├── id: exit-01 ... exit-12
├── country: 两位国家代码或 ANY
├── enabled: bool
├── proxy_port: 独立端口
├── tunnel_name: tun0 ... tun11
├── route_table: 200 ... 211
├── mark: 200 ... 211
├── state: disabled|starting|connecting|ready|degraded|failed
├── current_node
├── entry_ip
├── egress_ip
├── original_check_result
├── last_error
├── failure_streak
└── timestamps
```

每个槽位一次只保持一条活动隧道。槽位重拨只影响自身，不影响其他槽位。国家修改会清理该槽位的旧进程、旧路由和旧状态，然后按新国家重新选节点。连续三次拨号/健康失败后自动停用，管理员可在面板中重新启用。

## 路由和代理隔离

采用单容器内多进程 + 策略路由：

- `openvpn --config ... --dev tunN --route-noexec` 为每个槽位创建独立 TUN。
- 调度器为每个槽位安装唯一路由表和规则，包含 VPN 服务端 endpoint 的直连保护路由，避免连接自身被错误送入 TUN。
- 每个槽位的代理监听器在建立上游连接时绑定对应槽位的路由标记/网络路径；代理请求不能落回宿主机默认代理或其他槽位。
- 健康检查从对应槽位发起，并记录实际出口 IP。
- 所有路由、进程和监听器退出时幂等清理。

第一阶段先以 2 个槽位进行真实路由验收，再扩展到 6 和 12 个槽位；不能仅通过“进程已启动”判定出口成功，必须逐端口验证出口 IP。

## 本地 API 与存储

SQLite 保存：

- `exit_slots`
- `vpn_nodes`
- `settings`
- `check_results`
- `events`

API 最小合同：

- `GET /api/local/status`：面板状态快照
- `GET /api/local/exits`：12 个槽位分页/完整状态
- `PUT /api/local/exits/{id}`：修改国家、端口、启停状态
- `POST /api/local/exits/{id}/redial`：指定槽位换 IP/重拨
- `POST /api/local/exits/{id}/enable`：手动恢复自动停用槽位
- `GET /api/local/events`：日志和故障事件
- `GET /healthz`：本地进程健康状态

管理 API 使用本地配置的 Basic Auth；默认公网监听时不能关闭认证。代理认证沿用原项目配置，且与管理认证分离。

## 前端

复用 K-UI 面板的布局、样式和原有功能入口，新增“多出口”视图/卡片：

- 每槽位显示槽位 ID、国家、端口、当前节点、出口 IP、住宅/ISP 原始结果、状态、连续失败次数和最后错误。
- 支持编辑国家、启停、指定槽位换 IP、手动恢复。
- 不把 `unknown` 或检测服务失败显示为住宅成功；原有检测字段原样展示。
- 操作后显示服务端任务状态，不能把请求接受误显示为已连接。

## 错误处理和恢复

- VPNGate 拉取失败：保留上次节点快照并记录事件，不清空其他槽位。
- 单槽位连接失败：增加失败计数、指数退避、只重试该槽位。
- 连续三次失败：槽位变为 `disabled`，停止该槽位代理监听并保留失败原因。
- 管理员启用：清零连续失败计数，重新进入拨号队列。
- 配置变更：使用 generation 令牌，旧拨号结果不能覆盖新配置。
- 进程退出或容器重启：从 SQLite 恢复槽位配置，清理旧运行态后重新拨号。
- 未知/失败的住宅检测：只标记原始结果，不改变基础连通性结论。

## 验收

1. 单槽位原有流程通过。
2. 2 个槽位同时连接，两个端口的出口 IP 不混淆。
3. 12 个槽位能独立启动、停止和显示状态。
4. 修改一个槽位国家不重启其他槽位。
5. 指定一个槽位换 IP 不影响其他槽位。
6. 单槽位失败自动重拨，连续三次后停用。
7. 手动启用失败槽位后能够重新拨号。
8. 容器重启后 SQLite 配置恢复。
9. 管理认证和代理认证分别有效。
10. 检查无宿主机/Docker 系统代理泄漏，实际请求走对应出口。
11. 原有 Go 项目保持不变；新项目的 Python/K-UI 代码单独验证。
