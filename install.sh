#!/bin/sh

set -eu

REPOSITORY_URL=${KUI_REPOSITORY_URL:-https://github.com/kim1232aa/kui-local-multi-exit.git}
INSTALL_DIR=${KUI_INSTALL_DIR:-/opt/kui-local-multi-exit}
OS_RELEASE_FILE=${KUI_OS_RELEASE_FILE:-/etc/os-release}
TUN_DEVICE=${KUI_TUN_DEVICE:-/dev/net/tun}
SYSTEM_BIN=${KUI_SYSTEM_BIN:-}
ETC_DIR=${KUI_ETC_DIR:-/etc}
HEALTH_TIMEOUT=${KUI_HEALTH_TIMEOUT:-180}
HEALTH_INTERVAL=${KUI_HEALTH_INTERVAL:-3}
CLOUDFLARE_TIMEOUT=${KUI_CLOUDFLARE_TIMEOUT:-90}
CLOUDFLARE_INTERVAL=${KUI_CLOUDFLARE_INTERVAL:-5}
PUBLIC_HOST=""
SLOT_COUNT="auto"
MANAGEMENT_PORT="8080"
REALITY_PORT="8443"

usage() {
    cat <<'EOF'
K-UI Local Multi-Exit 一键安装

用法：
  sudo sh install.sh [选项]

选项：
  --public-host HOST      Reality 公网 IP 或域名；默认自动发现
  --slot-count N|auto     槽位数 1-34；默认 auto
  --management-port PORT  管理面板端口；默认 8080
  --reality-port PORT     Reality 入口端口；默认 8443
  --install-dir DIR       安装目录；默认 /opt/kui-local-multi-exit
  -h, --help              显示帮助

副作用：安装缺失的 Docker Engine/Compose，写入安装目录，创建 Docker
volumes，并启动容器。不会修改防火墙、sudoers、Docker 用户组或删除 volume。
EOF
}

fail() {
    printf '错误：%s\n' "$*" >&2
    exit 1
}

valid_port() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

valid_positive_integer() {
    case "$1" in
        ''|0*|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --public-host)
            [ "$#" -ge 2 ] || fail "--public-host 缺少参数"
            PUBLIC_HOST=$2
            shift 2
            ;;
        --slot-count)
            [ "$#" -ge 2 ] || fail "--slot-count 缺少参数"
            SLOT_COUNT=$2
            shift 2
            ;;
        --management-port)
            [ "$#" -ge 2 ] || fail "--management-port 缺少参数"
            MANAGEMENT_PORT=$2
            shift 2
            ;;
        --reality-port)
            [ "$#" -ge 2 ] || fail "--reality-port 缺少参数"
            REALITY_PORT=$2
            shift 2
            ;;
        --install-dir)
            [ "$#" -ge 2 ] || fail "--install-dir 缺少参数"
            INSTALL_DIR=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *) fail "未知参数：$1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || fail "请使用 root 运行：curl ... | sudo sh"
[ -r "$OS_RELEASE_FILE" ] || fail "无法读取 $OS_RELEASE_FILE"
# shellcheck disable=SC1090
. "$OS_RELEASE_FILE"
case "${ID:-}" in
    debian|ubuntu) ;;
    *) fail "仅支持 Debian/Ubuntu，当前系统：${ID:-unknown}" ;;
esac
MACHINE_ARCH=${KUI_MACHINE_ARCH:-$(uname -m)}
case "$MACHINE_ARCH" in
    x86_64|amd64|aarch64|arm64) ;;
    *) fail "不支持的 CPU 架构：$MACHINE_ARCH；仅支持 amd64/arm64" ;;
esac

case "$SLOT_COUNT" in
    auto) ;;
    ''|*[!0-9]*) fail "--slot-count 必须是 auto 或 1-34" ;;
    *) [ "$SLOT_COUNT" -ge 1 ] && [ "$SLOT_COUNT" -le 34 ] || fail "--slot-count 必须是 auto 或 1-34" ;;
esac
valid_port "$MANAGEMENT_PORT" || fail "--management-port 必须是 1-65535"
valid_port "$REALITY_PORT" || fail "--reality-port 必须是 1-65535"
[ "$MANAGEMENT_PORT" != "$REALITY_PORT" ] || fail "管理端口和 Reality 端口不能相同"
valid_positive_integer "$HEALTH_TIMEOUT" || fail "KUI_HEALTH_TIMEOUT 必须是正整数"
valid_positive_integer "$HEALTH_INTERVAL" || fail "KUI_HEALTH_INTERVAL 必须是正整数"
valid_positive_integer "$CLOUDFLARE_TIMEOUT" || fail "KUI_CLOUDFLARE_TIMEOUT 必须是正整数"
valid_positive_integer "$CLOUDFLARE_INTERVAL" || fail "KUI_CLOUDFLARE_INTERVAL 必须是正整数"
case "$PUBLIC_HOST" in
    ''|*[!A-Za-z0-9._:-]*) [ -z "$PUBLIC_HOST" ] || fail "--public-host 只能包含域名、IPv4 或 IPv6 地址" ;;
esac
[ -c "$TUN_DEVICE" ] || fail "TUN 字符设备不可用：$TUN_DEVICE。请先在 VPS 控制台启用 TUN/TAP"

printf '将安装缺失的 Docker/Compose，写入 %s，创建 Docker volumes 并启动容器。\n' "$INSTALL_DIR"
printf '%s\n' '不会修改防火墙、sudoers、Docker 用户组，也不会删除现有 volumes。'

if [ -n "$SYSTEM_BIN" ]; then
    PATH="$SYSTEM_BIN:$PATH"
    export PATH
fi

setup_docker_repository() {
    apt-get update
    apt-get install -y ca-certificates curl
    install -m 0755 -d "$ETC_DIR/apt/keyrings"
    install -m 0755 -d "$ETC_DIR/apt/sources.list.d"
    curl -fsSL "https://download.docker.com/linux/${ID}/gpg" -o "$ETC_DIR/apt/keyrings/docker.asc"
    chmod a+r "$ETC_DIR/apt/keyrings/docker.asc"
    architecture=$(dpkg --print-architecture)
    codename=${VERSION_CODENAME:-}
    [ -n "$codename" ] || fail "系统缺少 VERSION_CODENAME，无法配置 Docker APT 仓库"
    cat > "$ETC_DIR/apt/sources.list.d/docker.sources" <<EOF
Types: deb
URIs: https://download.docker.com/linux/${ID}
Suites: ${codename}
Components: stable
Architectures: ${architecture}
Signed-By: ${ETC_DIR}/apt/keyrings/docker.asc
EOF
    apt-get update
}

install_docker() {
    printf '%s\n' '[1/5] 安装 Docker Engine 和 Compose 插件（Docker 官方 APT 仓库）...'
    setup_docker_repository
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

if ! command -v docker >/dev/null 2>&1; then
    install_docker
else
    printf '%s\n' '[1/5] Docker 已安装，保留现有版本。'
fi

command -v git >/dev/null 2>&1 || {
    apt-get update
    apt-get install -y git
}
command -v curl >/dev/null 2>&1 || {
    apt-get update
    apt-get install -y ca-certificates curl
}
if ! docker compose version >/dev/null 2>&1; then
    setup_docker_repository
    apt-get install -y docker-buildx-plugin docker-compose-plugin
fi
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 不可用"
docker info >/dev/null 2>&1 || fail "Docker daemon 不可用"

printf '%s\n' '[2/5] 获取或更新项目...'
if [ -d "$INSTALL_DIR/.git" ]; then
    git -C "$INSTALL_DIR" pull --ff-only
elif [ -e "$INSTALL_DIR" ]; then
    fail "$INSTALL_DIR 已存在但不是 Git 仓库；为避免覆盖，安装已停止"
else
    git clone --depth 1 "$REPOSITORY_URL" "$INSTALL_DIR"
fi
[ -f "$INSTALL_DIR/compose.yaml" ] || fail "安装目录缺少 compose.yaml"

ENV_FILE="$INSTALL_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    printf '%s\n' '[3/5] 生成初始配置和随机管理凭据...'
    umask 077
    if command -v openssl >/dev/null 2>&1; then
        management_password=$(openssl rand -hex 24)
    else
        management_password=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
    fi
    cat > "$ENV_FILE" <<EOF
KUI_MANAGEMENT_USER=admin
KUI_MANAGEMENT_PASSWORD=${management_password}
KUI_MANAGEMENT_PORT=${MANAGEMENT_PORT}
KUI_REALITY_PORT=${REALITY_PORT}
KUI_PUBLIC_HOST=${PUBLIC_HOST}
KUI_SLOT_COUNT=${SLOT_COUNT}
EOF
    chmod 600 "$ENV_FILE"
else
    printf '%s\n' '[3/5] 保留现有 .env 和凭据。'
    existing_management_port=$(sed -n 's/^KUI_MANAGEMENT_PORT=//p' "$ENV_FILE" | tail -n 1 | tr -d '\r')
    existing_reality_port=$(sed -n 's/^KUI_REALITY_PORT=//p' "$ENV_FILE" | tail -n 1 | tr -d '\r')
    [ -z "$existing_management_port" ] || MANAGEMENT_PORT=$existing_management_port
    [ -z "$existing_reality_port" ] || REALITY_PORT=$existing_reality_port
    valid_port "$MANAGEMENT_PORT" || fail ".env 中的 KUI_MANAGEMENT_PORT 必须是 1-65535"
    valid_port "$REALITY_PORT" || fail ".env 中的 KUI_REALITY_PORT 必须是 1-65535"
fi

cd "$INSTALL_DIR"
if ! docker volume inspect kui-cloudshell-secrets >/dev/null 2>&1; then
    docker volume create kui-cloudshell-secrets >/dev/null
fi

printf '%s\n' '[4/5] 构建并启动核心服务...'
docker compose up -d --build kui-local-multi-exit kui-reality-gateway

wait_healthy() {
    service=$1
    elapsed=0
    while [ "$elapsed" -le "$HEALTH_TIMEOUT" ]; do
        container_id=$(docker compose ps -q "$service" 2>/dev/null || true)
        if [ -n "$container_id" ]; then
            health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)
            [ "$health" = "healthy" ] && return 0
        fi
        sleep "$HEALTH_INTERVAL"
        elapsed=$((elapsed + HEALTH_INTERVAL))
    done
    docker compose ps >&2 || true
    fail "$service 未在 ${HEALTH_TIMEOUT} 秒内变为 healthy"
}

printf '%s\n' '[5/5] 验证服务...'
wait_healthy kui-local-multi-exit
wait_healthy kui-reality-gateway
docker compose exec -T kui-reality-gateway \
    kui-sing-box check -c /var/lib/kui-reality/config.json >/dev/null
curl --noproxy '*' -fsS --max-time 10 \
    "http://127.0.0.1:${MANAGEMENT_PORT}/healthz" >/dev/null

cloudflare_ready=0
if docker compose exec -T kui-local-multi-exit sh -c '
    for file in cf-tunnel-creds.json cf-hostname uuid sub-path sub-front.yaml res-domains.txt; do
        test -s "/run/cloudshell-secrets/$file" || exit 1
    done
' >/dev/null 2>&1; then
    cloudflare_ready=1
fi

if [ "$cloudflare_ready" -eq 1 ]; then
    docker compose up -d --build
    wait_healthy kui-cloudshell-origin
    cloudflare_host=$(docker compose exec -T kui-local-multi-exit cat /run/cloudshell-secrets/cf-hostname | tr -d '\r\n')
    cloudflare_path=$(docker compose exec -T kui-local-multi-exit cat /run/cloudshell-secrets/sub-path | tr -d '\r\n')
    elapsed=0
    public_subscription=""
    while [ "$elapsed" -le "$CLOUDFLARE_TIMEOUT" ]; do
        public_subscription=$(curl --noproxy '*' -fsS --max-time 20 "https://${cloudflare_host}${cloudflare_path}" 2>/dev/null || true)
        if printf '%s' "$public_subscription" | grep -q '^proxies:' \
            && printf '%s' "$public_subscription" | grep -q '^proxy-groups:' \
            && printf '%s' "$public_subscription" | grep -q '^rules:'; then
            break
        fi
        public_subscription=""
        sleep "$CLOUDFLARE_INTERVAL"
        elapsed=$((elapsed + CLOUDFLARE_INTERVAL))
    done
    [ -n "$public_subscription" ] || fail "Cloudflare 公网订阅未在 ${CLOUDFLARE_TIMEOUT} 秒内就绪"
    printf '%s\n' '安装完成。Cloudflare Tunnel 已启动。'
    printf '订阅地址：https://%s%s\n' "$cloudflare_host" "$cloudflare_path"
else
    printf '%s\n' '安装完成。Cloudflare secrets 不完整，Cloudflare 入口未启动；核心管理/API 和 Reality 已启动。'
    printf '%s\n' '补齐 kui-cloudshell-secrets 后，在安装目录执行：docker compose up -d --build'
fi
printf '管理面板：http://<VPS-IP>:%s/\n' "$MANAGEMENT_PORT"
printf 'Reality 端口：%s/tcp\n' "$REALITY_PORT"
printf '安装目录：%s\n' "$INSTALL_DIR"
