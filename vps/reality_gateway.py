"""Generate and run the shared-port VLESS + Reality gateway."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence

from .internal_proxy import load_internal_proxy_credentials
from .runtime_profile import resolve_runtime_profile
from .slot_config import MAX_SLOT_COUNT, slot_number


def generate_x25519_keypair(sing_box_bin: str = "sing-box") -> tuple[str, str]:
    """Generate a Reality key pair with the bundled sing-box binary."""
    resolved_bin = shutil.which(sing_box_bin) or sing_box_bin
    result = subprocess.run(
        [resolved_bin, "generate", "reality-keypair"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "sing-box reality key generation failed")
    private_match = re.search(r"^PrivateKey:\s*(\S+)\s*$", result.stdout, re.MULTILINE)
    public_match = re.search(r"^PublicKey:\s*(\S+)\s*$", result.stdout, re.MULTILINE)
    if not private_match or not public_match:
        raise RuntimeError("unable to parse sing-box Reality key pair")
    return private_match.group(1), public_match.group(1)


def get_public_ip(timeout: int = 3) -> str:
    """Resolve the public Reality host, preferring the explicit deployment value."""
    env_host = os.environ.get("KUI_REALITY_PUBLIC_HOST") or os.environ.get("KUI_PUBLIC_HOST")
    if env_host and env_host.strip():
        return env_host.strip()

    for url in (
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://ip.sb",
        "https://icanhazip.com",
    ):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "curl/7.68.0"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                ip = response.read().decode("utf-8").strip()
            ipaddress.IPv4Address(ip)
            return ip
        except Exception:
            continue
    raise RuntimeError("unable to determine the public Reality host; set KUI_PUBLIC_HOST")


def _slot_number(slot_id: str) -> int:
    return slot_number(slot_id) or MAX_SLOT_COUNT + 1


def _load_identity_payload(path: Path) -> dict[str, dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    raw_nodes = data.get("nodes", data)
    if isinstance(raw_nodes, dict):
        return {
            str(slot_id): value
            for slot_id, value in raw_nodes.items()
            if isinstance(value, dict)
        }
    if isinstance(raw_nodes, list):
        return {
            str(value["slot_id"]): value
            for value in raw_nodes
            if isinstance(value, dict) and value.get("slot_id")
        }
    return {}


def _write_identities(path: Path, identities: Mapping[str, Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_text(
        json.dumps({"version": 2, "nodes": identities}, indent=2),
        encoding="utf-8",
    )
    tmp_path.chmod(0o600)
    tmp_path.replace(path)
    path.chmod(0o600)


def load_or_create_identities(identities_file: Path | str, count: int = MAX_SLOT_COUNT) -> dict[str, dict[str, Any]]:
    """Keep all stored identities, returning only the requested managed slots.

    Existing per-slot keys are migrated to one shared Reality key pair by reusing
    `exit-01` when available; UUIDs remain per slot and therefore preserve links.
    """
    if not 1 <= int(count) <= MAX_SLOT_COUNT:
        raise ValueError(f"count must be between 1 and {MAX_SLOT_COUNT}")
    identities_path = Path(identities_file)
    identities = _load_identity_payload(identities_path)
    changed = not identities_path.exists()

    shared_source = identities.get("exit-01")
    if not shared_source:
        shared_source = next((item for item in identities.values() if item.get("private_key") and item.get("public_key")), None)
    if shared_source and shared_source.get("private_key") and shared_source.get("public_key"):
        private_key = str(shared_source["private_key"])
        public_key = str(shared_source["public_key"])
        short_id = str(shared_source.get("short_id") or secrets.token_hex(4))
        if not shared_source.get("short_id"):
            changed = True
    else:
        private_key, public_key = generate_x25519_keypair()
        short_id = secrets.token_hex(4)
        changed = True

    for index in range(1, int(count) + 1):
        slot_id = f"exit-{index:02d}"
        current = identities.get(slot_id, {})
        node_uuid = str(current.get("uuid") or uuid.uuid4())
        replacement = {
            "slot_id": slot_id,
            "uuid": node_uuid,
            "private_key": private_key,
            "public_key": public_key,
            "short_id": short_id,
        }
        if current != replacement:
            identities[slot_id] = replacement
            changed = True

    if changed:
        _write_identities(identities_path, identities)
    return {
        slot_id: identities[slot_id]
        for slot_id in sorted(identities, key=_slot_number)
        if 1 <= _slot_number(slot_id) <= int(count)
    }


def build_sing_box_config(
    identities: Mapping[str, Mapping[str, Any]],
    socks_host: str = "kui-local-multi-exit",
    socks_base_port: int = 7920,
    reality_port: int = 8443,
    sni: str = "dl.google.com",
    proxy_user: str = "vpn",
    proxy_password: str = "vpn",
    **legacy: Any,
) -> dict[str, Any]:
    """Build one VLESS Reality inbound and route each authenticated UUID by name."""
    if "reality_base_port" in legacy:
        reality_port = int(legacy.pop("reality_base_port"))
    if legacy:
        raise TypeError(f"unsupported arguments: {', '.join(sorted(legacy))}")
    sorted_slots = sorted(identities, key=_slot_number)
    if not sorted_slots:
        raise ValueError("at least one Reality identity is required")
    first = identities[sorted_slots[0]]
    users = [
        {
            "name": slot_id,
            "uuid": str(identities[slot_id]["uuid"]),
            "flow": "xtls-rprx-vision",
        }
        for slot_id in sorted_slots
    ]
    outbounds = [
        {
            "type": "socks",
            "tag": f"openvpn-{slot_id}",
            "server": socks_host,
            "server_port": socks_base_port + (_slot_number(slot_id) - 1),
            "username": proxy_user,
            "password": proxy_password,
        }
        for slot_id in sorted_slots
    ]
    rules = [
        {
            "inbound": ["xtls-reality"],
            "auth_user": [slot_id],
            "action": "route",
            "outbound": f"openvpn-{slot_id}",
        }
        for slot_id in sorted_slots
    ]
    return {
        "log": {"level": "info"},
        "inbounds": [
            {
                "type": "vless",
                "tag": "xtls-reality",
                "listen": "0.0.0.0",
                "listen_port": int(reality_port),
                "users": users,
                "tls": {
                    "enabled": True,
                    "server_name": sni,
                    "reality": {
                        "enabled": True,
                        "handshake": {"server": sni, "server_port": 443},
                        "private_key": str(first["private_key"]),
                        "short_id": [str(first["short_id"])],
                    },
                },
            }
        ],
        "outbounds": outbounds,
        "route": {"rules": rules},
    }


def build_public_nodes_manifest(
    identities: Mapping[str, Mapping[str, Any]],
    public_host: str,
    reality_port: int = 8443,
    sni: str = "dl.google.com",
    **legacy: Any,
) -> dict[str, Any]:
    """Build public VLESS links without private keys or SOCKS credentials."""
    if "reality_base_port" in legacy:
        reality_port = int(legacy.pop("reality_base_port"))
    if legacy:
        raise TypeError(f"unsupported arguments: {', '.join(sorted(legacy))}")
    nodes = []
    for slot_id in sorted(identities, key=_slot_number):
        identity = identities[slot_id]
        node_uuid = str(identity["uuid"])
        public_key = str(identity["public_key"])
        short_id = str(identity["short_id"])
        link = (
            f"vless://{node_uuid}@{public_host}:{int(reality_port)}?"
            f"encryption=none&flow=xtls-rprx-vision&security=reality&"
            f"sni={sni}&fp=chrome&pbk={public_key}&sid={short_id}&"
            f"type=tcp&headerType=none#KUI-XTLS-Reality-{slot_id}"
        )
        nodes.append(
            {
                "slot_id": slot_id,
                "address": public_host,
                "port": int(reality_port),
                "uuid": node_uuid,
                "sni": sni,
                "public_key": public_key,
                "short_id": short_id,
                "flow": "xtls-rprx-vision",
                "network": "tcp",
                "link": link,
            }
        )
    return {"version": 2, "public_host": public_host, "nodes": nodes}


def check_sing_box_config(config_file: Path | str, sing_box_bin: str = "sing-box") -> None:
    resolved_bin = shutil.which(sing_box_bin) or sing_box_bin
    result = subprocess.run(
        [resolved_bin, "check", "-c", str(config_file)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"sing-box config check failed (code {result.returncode}): {result.stderr or result.stdout}")


def exec_sing_box(config_file: Path | str, sing_box_bin: str = "sing-box") -> None:
    resolved_bin = shutil.which(sing_box_bin) or sing_box_bin
    os.execvp(resolved_bin, [resolved_bin, "run", "-c", str(config_file)])


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _gateway_count() -> int:
    raw = os.environ.get("KUI_SLOT_COUNT", "").strip()
    if raw and raw.lower() != "auto":
        try:
            count = int(raw)
        except ValueError as error:
            raise ValueError(f"KUI_SLOT_COUNT must be an integer between 1 and {MAX_SLOT_COUNT}") from error
        if not 1 <= count <= MAX_SLOT_COUNT:
            raise ValueError(f"KUI_SLOT_COUNT must be between 1 and {MAX_SLOT_COUNT}")
        return count
    legacy = os.environ.get("KUI_REALITY_COUNT", "").strip()
    if legacy:
        try:
            count = int(legacy)
        except ValueError as error:
            raise ValueError(f"KUI_REALITY_COUNT must be an integer between 1 and {MAX_SLOT_COUNT}") from error
        if not 1 <= count <= MAX_SLOT_COUNT:
            raise ValueError(f"KUI_REALITY_COUNT must be between 1 and {MAX_SLOT_COUNT}")
        return count
    return resolve_runtime_profile().slot_count


def run_gateway(
    do_exec: bool = True,
    sing_box_bin: str | None = None,
    args: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Generate verified configuration and publish its matching public manifest."""
    del args
    count = _gateway_count()
    reality_port = _env_int(
        "KUI_REALITY_PORT",
        _env_int("KUI_REALITY_BASE_PORT", 8443, minimum=1, maximum=65535),
        minimum=1,
        maximum=65535,
    )
    socks_host = os.environ.get("KUI_REALITY_SOCKS_HOST", "kui-local-multi-exit")
    socks_base_port = _env_int("KUI_REALITY_SOCKS_BASE_PORT", 7920, minimum=1, maximum=65535)
    sni = os.environ.get("KUI_REALITY_SNI", "dl.google.com")
    data_dir = Path(os.environ.get("KUI_REALITY_DATA_DIR", "/var/lib/kui-reality"))
    internal_workspace = Path(os.environ.get("KUI_INTERNAL_PROXY_WORKSPACE", "/opt/kui-local"))
    proxy_user, proxy_password = load_internal_proxy_credentials(internal_workspace)
    identities_file = Path(os.environ.get("KUI_REALITY_IDENTITIES_FILE", str(data_dir / "identities.json")))
    config_file = Path(os.environ.get("KUI_REALITY_CONFIG_FILE", str(data_dir / "config.json")))
    nodes_file = Path(os.environ.get("KUI_REALITY_NODES_FILE", "/run/kui-reality/public-nodes.json"))
    bin_name = sing_box_bin or os.environ.get("KUI_SING_BOX_BIN", "sing-box")

    public_host = get_public_ip()
    identities = load_or_create_identities(identities_file, count=count)
    config_dict = build_sing_box_config(
        identities,
        socks_host=socks_host,
        socks_base_port=socks_base_port,
        reality_port=reality_port,
        sni=sni,
        proxy_user=proxy_user,
        proxy_password=proxy_password,
    )
    manifest_dict = build_public_nodes_manifest(
        identities,
        public_host=public_host,
        reality_port=reality_port,
        sni=sni,
    )

    config_file.parent.mkdir(parents=True, exist_ok=True)
    tmp_config = config_file.with_suffix(".tmp")
    tmp_config.write_text(json.dumps(config_dict, indent=2), encoding="utf-8")
    tmp_config.chmod(0o600)
    tmp_config.replace(config_file)
    config_file.chmod(0o600)

    if not shutil.which(bin_name):
        raise RuntimeError(f"sing-box binary not found: {bin_name}")
    check_sing_box_config(config_file, sing_box_bin=bin_name)

    nodes_file.parent.mkdir(parents=True, exist_ok=True)
    tmp_nodes = nodes_file.with_suffix(".tmp")
    tmp_nodes.write_text(json.dumps(manifest_dict, indent=2), encoding="utf-8")
    tmp_nodes.chmod(0o644)
    tmp_nodes.replace(nodes_file)
    nodes_file.chmod(0o644)

    if do_exec:
        exec_sing_box(config_file, sing_box_bin=bin_name)
    return {
        "identities_file": str(identities_file),
        "config_file": str(config_file),
        "nodes_file": str(nodes_file),
        "public_host": public_host,
        "identities": identities,
        "config": config_dict,
        "manifest": manifest_dict,
    }


def main() -> None:
    run_gateway(do_exec=True)


if __name__ == "__main__":
    main()
