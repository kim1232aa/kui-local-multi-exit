# VPS Docker README Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将根 `README.md` 替换为准确、完整、可直接执行的单 VPS Docker 部署与运维手册。

**Architecture:** 文档以 `compose.yaml`、`Dockerfile` 和当前 API 合同为唯一事实来源，把首次部署、验证、更新、备份和排错组织成一条线性操作路径。`README.local.md` 保留为补充说明，根 README 不再展示旧 Cloudflare 架构。

**Tech Stack:** Markdown、Docker Engine、Docker Compose v2、Python `unittest`

## Global Constraints

- 只描述单 VPS、单 Docker 容器、本地 SQLite 和 12 个出口槽位。
- 不写入真实密码、私人 VPS 地址、当前运行出口 IP 或强制的本机 `7896` 配置。
- `KUI_MANAGEMENT_PASSWORD` 必填，并明确它是 SOCKS5 共用密码而不是面板登录密码。
- 面板免登录，必须明确网络访问控制风险。
- 不保证 VPNGate 始终有 12 个同时可用出口。
- 更新操作不得删除 `kui-local-data`；永久删除 volume 必须单独标记为不可恢复。

---

### Task 1: 重写根部署手册

**Files:**
- Modify: `README.md`
- Reference: `README.local.md`
- Reference: `compose.yaml`
- Reference: `Dockerfile`
- Test: `tests/test_deployment_contract.py`

**Interfaces:**
- Consumes: Compose 变量 `KUI_MANAGEMENT_USER`、`KUI_MANAGEMENT_PASSWORD`、`KUI_MANAGEMENT_PORT`、`KUI_FETCH_PROXY`、`KUI_OPENVPN_SOCKS_PROXY`。
- Produces: GitHub 首页可直接执行的 VPS 部署、验证和运维说明。

- [ ] **Step 1: 用独立项目说明替换根 README**

写入以下章节并给出完整命令：项目定位、功能边界、部署前提、Docker 安装参考、克隆仓库、首次启动、端口开放、可选上游代理、面板和 SOCKS5 地址、状态/日志、真实出口验证、更新、备份恢复、停止卸载、常见故障、开发验证。

首次部署核心命令必须为：

```bash
git clone https://github.com/kim1232aa/kui-local-multi-exit.git
cd kui-local-multi-exit
export KUI_MANAGEMENT_PASSWORD='请替换为强密码'
docker compose up -d --build
```

临时代理示例必须说明仅当 VPS 宿主确实监听对应端口时才使用：

```bash
export KUI_FETCH_PROXY='socks5://host.docker.internal:7896'
export KUI_OPENVPN_SOCKS_PROXY='socks5://host.docker.internal:7896'
```

更新流程必须保留 volume：

```bash
git pull --ff-only
docker compose up -d --build
```

备份和恢复使用命名 volume `kui-local-data`，并明确恢复前停止容器。永久卸载命令与普通停止命令分开。

- [ ] **Step 2: 扫描旧架构和私人配置残留**

Run:

```bash
python3 - <<'PY'
from pathlib import Path
text = Path('README.md').read_text(encoding='utf-8')
for forbidden in ('Cloudflare Pages', 'D1 database', 'Wrangler', 'Durable Objects', '103.62.49.130'):
    assert forbidden not in text, forbidden
for required in ('docker compose up -d --build', 'KUI_MANAGEMENT_PASSWORD', '/dev/net/tun', 'NET_ADMIN', '7920-7931', 'kui-local-data', 'git pull --ff-only'):
    assert required in text, required
print('README contract OK')
PY
```

Expected: `README contract OK`。

- [ ] **Step 3: 验证 Compose 与镜像合同**

Run:

```bash
KUI_MANAGEMENT_PASSWORD=test-only-password docker compose config --quiet
docker build --check .
python3 -m unittest tests.test_deployment_contract -v
```

Expected: 全部命令退出码为 0，部署合同 `OK`。

- [ ] **Step 4: 检查 Markdown 和工作区差异**

Run:

```bash
git diff --check
git diff -- README.md
```

Expected: 无空白错误；diff 只把根 README 从旧 Cloudflare 项目说明改为独立 VPS Docker 手册。

- [ ] **Step 5: 提交文档**

```bash
git add README.md docs/superpowers/plans/2026-08-08-vps-docker-readme.md
git commit -m "docs: add VPS Docker deployment guide"
```

### Task 2: 推送并核对远端

**Files:**
- No file changes expected

**Interfaces:**
- Consumes: Task 1 的已验证提交。
- Produces: `origin/main` 上可见的根 README。

- [ ] **Step 1: 推送主分支**

```bash
git push origin main
```

Expected: 推送成功且不是 force push。

- [ ] **Step 2: 核对本地和远端提交**

```bash
git fetch origin
git status --short --branch
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
```

Expected: `main...origin/main` 无 ahead/behind，工作区干净。
