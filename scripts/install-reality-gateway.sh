#!/usr/bin/env bash
set -euo pipefail

SING_BOX_VERSION="1.13.14"
SING_BOX_BIN="/usr/local/bin/kui-sing-box"
CONFIG_DIR="/etc/kui-reality-gateway"
CONFIG_PATH="$CONFIG_DIR/config.json"
IDENTITIES_PATH="$CONFIG_DIR/nodes-private.json"
LEGACY_NODE_ENV="$CONFIG_DIR/node.env"
CLIENT_LINK_PATH="$CONFIG_DIR/client.txt"
MIHOMO_PATH="$CONFIG_DIR/mihomo.yaml"
SERVICE_PATH="/etc/systemd/system/kui-reality-gateway.service"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBLIC_DIR="$PROJECT_ROOT/runtime/reality"
PUBLIC_NODES_PATH="$PUBLIC_DIR/public-nodes.json"
CONTAINER_NAME="${KUI_CONTAINER_NAME:-kui-local-multi-exit}"
REALITY_BASE_PORT="${KUI_REALITY_PORT:-8443}"
REALITY_SNI="${KUI_REALITY_SNI:-addons.mozilla.org}"
EXIT_BASE_PORT="${KUI_REALITY_EXIT_PORT:-7920}"
PUBLIC_HOST="${KUI_PUBLIC_HOST:-}"
NODE_COUNT=24

if [ "$(id -u)" -ne 0 ]; then
    echo "run this installer as root" >&2
    exit 1
fi

for value in "$REALITY_BASE_PORT" "$EXIT_BASE_PORT"; do
    if ! [[ "$value" =~ ^[0-9]+$ ]] || [ "$value" -lt 1 ] || [ "$value" -gt 65535 ]; then
        echo "Reality and exit ports must be between 1 and 65535" >&2
        exit 1
    fi
done
if [ $((REALITY_BASE_PORT + NODE_COUNT - 1)) -gt 65535 ] || [ $((EXIT_BASE_PORT + NODE_COUNT - 1)) -gt 65535 ]; then
    echo "configured port range exceeds 65535" >&2
    exit 1
fi
if ! [[ "$REALITY_SNI" =~ ^[A-Za-z0-9.-]+$ ]]; then
    echo "invalid Reality SNI" >&2
    exit 1
fi
if [ -z "$PUBLIC_HOST" ]; then
    PUBLIC_HOST="$(curl -4fsS --connect-timeout 5 --max-time 10 https://api.ipify.org 2>/dev/null || true)"
fi
if [ -z "$PUBLIC_HOST" ]; then
    echo "set KUI_PUBLIC_HOST to the VPS public IP or hostname" >&2
    exit 1
fi

install_sing_box() {
    local arch suffix expected temporary actual extracted
    case "$(uname -m)" in
        x86_64) arch="amd64"; expected="aae9172317c61760aae3dafcde889b2e51b7ea590c40d2b3c7ccdeae14b361b6" ;;
        aarch64) arch="arm64"; expected="08d37b2bf12145ec44307333490cecca4c917df054cd8e27a210f8d9cdbe0fd9" ;;
        *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
    esac
    suffix="linux-${arch}-glibc"
    temporary="$(mktemp -d)"
    curl -fL --retry 3 --connect-timeout 15 \
        -o "$temporary/sing-box.tar.gz" \
        "https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-${suffix}.tar.gz"
    actual="$(sha256sum "$temporary/sing-box.tar.gz" | awk '{print $1}')"
    if [ "$actual" != "$expected" ]; then
        rm -rf "$temporary"
        echo "sing-box checksum mismatch" >&2
        exit 1
    fi
    tar -xzf "$temporary/sing-box.tar.gz" -C "$temporary"
    extracted="$temporary/sing-box-${SING_BOX_VERSION}-${suffix}/sing-box"
    test -x "$extracted"
    install -m 0755 "$extracted" "$SING_BOX_BIN"
    rm -rf "$temporary"
}

if [ ! -x "$SING_BOX_BIN" ] || ! "$SING_BOX_BIN" version 2>/dev/null | grep -q "$SING_BOX_VERSION"; then
    install_sing_box
fi

proxy_user="${KUI_PROXY_USER:-}"
proxy_password="${KUI_PROXY_PASSWORD:-}"
if [ -z "$proxy_user" ] || [ -z "$proxy_password" ]; then
    while IFS= read -r item; do
        case "$item" in
            KUI_MANAGEMENT_USER=*) proxy_user="${item#KUI_MANAGEMENT_USER=}" ;;
            KUI_MANAGEMENT_PASSWORD=*) proxy_password="${item#KUI_MANAGEMENT_PASSWORD=}" ;;
        esac
    done < <(docker inspect "$CONTAINER_NAME" --format '{{range .Config.Env}}{{println .}}{{end}}')
fi
if [ -z "$proxy_user" ] || [ -z "$proxy_password" ]; then
    echo "unable to read the local SOCKS credentials from $CONTAINER_NAME" >&2
    exit 1
fi

install -d -m 0700 "$CONFIG_DIR"
install -d -m 0755 "$PUBLIC_DIR"
export SING_BOX_BIN CONFIG_PATH IDENTITIES_PATH LEGACY_NODE_ENV CLIENT_LINK_PATH MIHOMO_PATH PUBLIC_NODES_PATH
export PUBLIC_HOST REALITY_BASE_PORT REALITY_SNI EXIT_BASE_PORT NODE_COUNT
export PROXY_USER="$proxy_user" PROXY_PASSWORD="$proxy_password"
python3 - <<'PY'
import json
import os
import re
import secrets
import subprocess
import tempfile
import urllib.parse
import uuid
from pathlib import Path

binary = os.environ["SING_BOX_BIN"]
identities_path = Path(os.environ["IDENTITIES_PATH"])
legacy_path = Path(os.environ["LEGACY_NODE_ENV"])
config_path = Path(os.environ["CONFIG_PATH"])
public_path = Path(os.environ["PUBLIC_NODES_PATH"])
base_port = int(os.environ["REALITY_BASE_PORT"])
exit_base_port = int(os.environ["EXIT_BASE_PORT"])
node_count = int(os.environ["NODE_COUNT"])
public_host = os.environ["PUBLIC_HOST"]
sni = os.environ["REALITY_SNI"]


def atomic_json(path: Path, value, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=True, indent=2)
            handle.write("\n")
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def generate_identity(slot_id: str) -> dict:
    output = subprocess.check_output([binary, "generate", "reality-keypair"], text=True)
    private_match = re.search(r"PrivateKey:\s*(\S+)", output)
    public_match = re.search(r"PublicKey:\s*(\S+)", output)
    if not private_match or not public_match:
        raise RuntimeError("failed to parse sing-box Reality key pair")
    return {
        "slot_id": slot_id,
        "uuid": str(uuid.uuid4()),
        "private_key": private_match.group(1),
        "public_key": public_match.group(1),
        "short_id": secrets.token_hex(8),
    }


existing = {}
if identities_path.exists():
    try:
        loaded = json.loads(identities_path.read_text(encoding="utf-8"))
        for node in loaded.get("nodes", []):
            if isinstance(node, dict) and node.get("slot_id"):
                existing[str(node["slot_id"])] = node
    except (OSError, ValueError, json.JSONDecodeError):
        raise RuntimeError(f"invalid existing Reality identity file: {identities_path}")
elif legacy_path.exists():
    legacy = {}
    for line in legacy_path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            legacy[key.strip()] = value.strip().strip("'\"")
    required = ("REALITY_UUID", "REALITY_PRIVATE_KEY", "REALITY_PUBLIC_KEY", "REALITY_SHORT_ID")
    if all(legacy.get(key) for key in required):
        existing["exit-01"] = {
            "slot_id": "exit-01",
            "uuid": legacy["REALITY_UUID"],
            "private_key": legacy["REALITY_PRIVATE_KEY"],
            "public_key": legacy["REALITY_PUBLIC_KEY"],
            "short_id": legacy["REALITY_SHORT_ID"],
        }

identities = []
for index in range(node_count):
    slot_id = f"exit-{index + 1:02d}"
    node = existing.get(slot_id) or generate_identity(slot_id)
    node = {
        "slot_id": slot_id,
        "uuid": str(node["uuid"]),
        "private_key": str(node["private_key"]),
        "public_key": str(node["public_key"]),
        "short_id": str(node["short_id"]),
        "port": base_port + index,
        "exit_port": exit_base_port + index,
    }
    identities.append(node)

private_payload = {"version": 1, "nodes": identities}
atomic_json(identities_path, private_payload, 0o600)

inbounds = []
outbounds = []
rules = []
public_nodes = []
links = []
mihomo_nodes = []
for node in identities:
    slot_id = node["slot_id"]
    inbound_tag = f"xtls-reality-{slot_id}"
    outbound_tag = f"openvpn-{slot_id}"
    inbounds.append({
        "type": "vless",
        "tag": inbound_tag,
        "listen": "0.0.0.0",
        "listen_port": node["port"],
        "users": [{"uuid": node["uuid"], "flow": "xtls-rprx-vision"}],
        "tls": {
            "enabled": True,
            "server_name": sni,
            "reality": {
                "enabled": True,
                "handshake": {"server": sni, "server_port": 443},
                "private_key": node["private_key"],
                "short_id": [node["short_id"]],
            },
        },
    })
    outbounds.append({
        "type": "socks",
        "tag": outbound_tag,
        "server": "127.0.0.1",
        "server_port": node["exit_port"],
        "username": os.environ["PROXY_USER"],
        "password": os.environ["PROXY_PASSWORD"],
    })
    rules.append({"inbound": [inbound_tag], "action": "route", "outbound": outbound_tag})
    public = {
        "slot_id": slot_id,
        "address": public_host,
        "port": node["port"],
        "uuid": node["uuid"],
        "sni": sni,
        "public_key": node["public_key"],
        "short_id": node["short_id"],
    }
    public_nodes.append(public)
    query = urllib.parse.urlencode({
        "encryption": "none",
        "flow": "xtls-rprx-vision",
        "security": "reality",
        "sni": sni,
        "fp": "chrome",
        "pbk": node["public_key"],
        "sid": node["short_id"],
        "type": "tcp",
        "headerType": "none",
    })
    links.append(f"vless://{node['uuid']}@{public_host}:{node['port']}?{query}#KUI-XTLS-Reality-{slot_id}")
    mihomo_nodes.append({
        "name": f"KUI-XTLS-Reality-{slot_id}",
        "type": "vless",
        "server": public_host,
        "port": node["port"],
        "uuid": node["uuid"],
        "network": "tcp",
        "udp": True,
        "tls": True,
        "servername": sni,
        "flow": "xtls-rprx-vision",
        "client-fingerprint": "chrome",
        "reality-opts": {"public-key": node["public_key"], "short-id": node["short_id"]},
    })

config = {
    "log": {"level": "info", "timestamp": True},
    "inbounds": inbounds,
    "outbounds": outbounds,
    "route": {"rules": rules},
}
atomic_json(config_path, config, 0o600)
atomic_json(public_path, {"version": 1, "nodes": public_nodes}, 0o644)
Path(os.environ["CLIENT_LINK_PATH"]).write_text("\n".join(links) + "\n", encoding="utf-8")
os.chmod(os.environ["CLIENT_LINK_PATH"], 0o600)

# JSON is valid YAML, so Mihomo can import this fragment without another YAML dependency.
Path(os.environ["MIHOMO_PATH"]).write_text(
    json.dumps({"proxies": mihomo_nodes}, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
os.chmod(os.environ["MIHOMO_PATH"], 0o600)
PY

cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=KUI XTLS-Reality gateways for OpenVPN multi-exit
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
ExecStart=$SING_BOX_BIN run -c $CONFIG_PATH
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

"$SING_BOX_BIN" check -c "$CONFIG_PATH"
systemctl daemon-reload
systemctl enable --now kui-reality-gateway.service
systemctl restart kui-reality-gateway.service
systemctl is-active --quiet kui-reality-gateway.service

echo "Reality gateways are active on TCP ${REALITY_BASE_PORT}-$((REALITY_BASE_PORT + NODE_COUNT - 1))."
echo "OpenVPN exits are mapped to local SOCKS ports ${EXIT_BASE_PORT}-$((EXIT_BASE_PORT + NODE_COUNT - 1))."
echo "Public node manifest: $PUBLIC_NODES_PATH"
echo "Client links: $CLIENT_LINK_PATH"
echo "Mihomo nodes: $MIHOMO_PATH"
