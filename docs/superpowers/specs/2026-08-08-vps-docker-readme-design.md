# VPS Docker README 修订设计

## 目标

将仓库根 `README.md` 从原版 K-UI 的 Cloudflare Pages、D1、Worker 和多 VPS 部署说明，改为当前独立项目 `kui-local-multi-exit` 的单 VPS Docker 部署与运维手册。GitHub 首页应让用户无需阅读旧项目文档即可完成部署、验证、更新、备份和排错。

## 文档结构

根 README 使用以下顺序：

1. 项目定位与能力边界：单 VPS、单容器、12 个本地出口槽位、面板免登录、SOCKS5 共用一组凭据。
2. 部署前提：Linux VPS、Docker Engine、Compose v2、`/dev/net/tun`、root 或等效 Docker 权限、可用公网网络。
3. 防火墙和安全提醒：开放面板 TCP 8080 与 SOCKS5 TCP 7920-7931；面板免登录，不建议直接暴露到不可信网络；SOCKS5 必须使用强密码。
4. 首次部署：克隆独立仓库、进入目录、导出必填密码、可选用户名和管理端口、执行 `docker compose up -d --build`。
5. 可选上游代理：仅网络受限时设置 `KUI_FETCH_PROXY` 和 `KUI_OPENVPN_SOCKS_PROXY`，说明 SOCKS 上游只支持 TCP OpenVPN 节点，普通 VPS 直连部署不要照抄本机 `7896` 示例。
6. 使用方式：面板地址、12 个 SOCKS5 地址、候选节点和换 IP 操作、发布门禁与状态含义。
7. 验证：容器 health、API、订阅、逐端口真实出口和目标探针验证。
8. 日常运维：日志、状态、重启、更新、备份和恢复命名 volume、停止和卸载。
9. 常见故障：TUN/NET_ADMIN、无可用节点、节点被判机房、目标探针失败、端口占用、Docker 系统代理污染、临时上游不可达。
10. 开发验证：宿主测试、Compose 校验、Docker build check、真实集成测试的环境变量。

## 配置合同

README 中只记录 `compose.yaml` 和 `Dockerfile` 当前真实支持的配置：

- `KUI_MANAGEMENT_USER`，默认 `admin`。
- `KUI_MANAGEMENT_PASSWORD`，必填，是 12 个 SOCKS5 出口共用密码，不是面板密码。
- `KUI_MANAGEMENT_PORT`，默认宿主端口 `8080`。
- `KUI_FETCH_PROXY`，可选，仅用于控制面拉取 VPNGate 数据。
- `KUI_OPENVPN_SOCKS_PROXY`，可选，用于 OpenVPN 握手的 SOCKS5 上游。
- 宿主 TCP `7920-7931` 固定映射到 12 个出口。
- 命名 volume `kui-local-data` 持久化 `/opt/kui-local`。

文档不宣称固定 12 个槽位必然同时可用。实际发布需同时满足槽位启用、OpenVPN 隧道和策略路由正常、SOCKS5 listener 已绑定、出口被 TestISP 判为住宅、默认 204 和四个自定义目标全部通过。

## 错误处理与安全边界

- 部署命令不得硬编码个人 VPS 地址、真实密码或本机代理配置。
- 临时 Clash 示例明确标为可选，并说明 VPS 上的 `host.docker.internal:7896` 只有宿主确实运行该服务时才可用。
- 不提供删除 volume 的默认更新命令；卸载章节将“保留数据”和“连数据删除”分开，并明确后者不可恢复。
- README 明确面板免登录，因此应通过 VPS 防火墙、反向代理访问控制或仅绑定可信网络限制访问。

## 验收

- 根 README 不再要求 Cloudflare Pages、D1、Worker、Wrangler 或 VPS Agent。
- README 中每个变量、端口、volume、能力和验证 URL 与代码/Compose 一致。
- `KUI_MANAGEMENT_PASSWORD=test-only-password docker compose config --quiet` 成功。
- `docker build --check .` 成功。
- `python3 -m unittest tests.test_deployment_contract -v` 成功。
- 文档示例不包含私人凭据或当前运行时出口 IP。
