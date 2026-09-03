"""Publish per-slot SOCKS5 exits on the host with management credentials."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, Sequence

from .internal_proxy import load_internal_proxy_credentials
from .reality_gateway import check_sing_box_config, exec_sing_box
from .runtime_profile import resolve_runtime_profile
from .slot_config import BASE_PROXY_PORT, MAX_SLOT_COUNT, slot_number


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


def _slot_count() -> int:
    raw = os.environ.get("KUI_SLOT_COUNT", "").strip()
    if raw and raw.lower() != "auto":
        try:
            count = int(raw)
        except ValueError as error:
            raise ValueError(f"KUI_SLOT_COUNT must be an integer between 1 and {MAX_SLOT_COUNT}") from error
        if not 1 <= count <= MAX_SLOT_COUNT:
            raise ValueError(f"KUI_SLOT_COUNT must be between 1 and {MAX_SLOT_COUNT}")
        return count
    return resolve_runtime_profile().slot_count


def build_socks5_bridge_config(
    *,
    slot_count: int,
    socks_host: str,
    socks_base_port: int,
    auto_port: int,
    public_user: str,
    public_password: str,
    internal_user: str,
    internal_password: str,
) -> dict[str, Any]:
    """Re-publish each managed slot with the subscription's public credentials."""
    if not 1 <= int(slot_count) <= MAX_SLOT_COUNT:
        raise ValueError(f"KUI_SLOT_COUNT must be between 1 and {MAX_SLOT_COUNT}")
    if not public_user or not public_password:
        raise ValueError("KUI_MANAGEMENT_USER and KUI_MANAGEMENT_PASSWORD are required")
    users = [{"username": public_user, "password": public_password}]
    slots = [f"exit-{index:02d}" for index in range(1, int(slot_count) + 1)]
    inbounds = [
        {
            "type": "mixed",
            "tag": "auto-in",
            "listen": "0.0.0.0",
            "listen_port": int(auto_port),
            "users": users,
        }
    ]
    outbounds: list[dict[str, Any]] = [
        {
            "type": "urltest",
            "tag": "auto",
            "outbounds": slots,
            "url": "http://www.gstatic.com/generate_204",
            "interval": "30s",
            "tolerance": 150,
            "idle_timeout": "30s",
            "interrupt_exist_connections": False,
        }
    ]
    rules = []
    for sid in slots:
        port = int(socks_base_port) + (slot_number(sid) or 1) - 1
        inbounds.append(
            {
                "type": "mixed",
                "tag": sid,
                "listen": "0.0.0.0",
                "listen_port": port,
                "users": users,
            }
        )
        outbounds.append(
            {
                "type": "socks",
                "tag": sid,
                "server": socks_host,
                "server_port": port,
                "version": "5",
                "username": internal_user,
                "password": internal_password,
            }
        )
        rules.append({"inbound": sid, "outbound": sid})
    outbounds.append({"type": "direct", "tag": "direct"})
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "final": "auto"},
    }


def run_bridge(
    do_exec: bool = True,
    sing_box_bin: str | None = None,
    args: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Generate a verified bridge config and optionally exec sing-box."""
    del args
    count = _slot_count()
    socks_host = os.environ.get("KUI_REALITY_SOCKS_HOST", "kui-local-multi-exit")
    socks_base_port = _env_int("KUI_REALITY_SOCKS_BASE_PORT", BASE_PROXY_PORT, minimum=1, maximum=65535)
    auto_port = _env_int("KUI_SOCKS5_AUTO_PORT", 1080, minimum=1, maximum=65535)
    public_user = os.environ.get("KUI_MANAGEMENT_USER", "admin").strip() or "admin"
    public_password = os.environ.get("KUI_MANAGEMENT_PASSWORD", "")
    workspace = Path(os.environ.get("KUI_INTERNAL_PROXY_WORKSPACE", "/opt/kui-local"))
    data_dir = Path(os.environ.get("KUI_SOCKS5_BRIDGE_DATA_DIR", "/var/lib/kui-socks5-bridge"))
    config_file = Path(os.environ.get("KUI_SOCKS5_BRIDGE_CONFIG_FILE", str(data_dir / "config.json")))
    bin_name = sing_box_bin or os.environ.get("KUI_SING_BOX_BIN", "sing-box")
    internal_user, internal_password = load_internal_proxy_credentials(workspace)
    config_dict = build_socks5_bridge_config(
        slot_count=count,
        socks_host=socks_host,
        socks_base_port=socks_base_port,
        auto_port=auto_port,
        public_user=public_user,
        public_password=public_password,
        internal_user=internal_user,
        internal_password=internal_password,
    )
    config_file.parent.mkdir(parents=True, exist_ok=True)
    tmp_config = config_file.with_suffix(".tmp")
    tmp_config.write_text(json.dumps(config_dict, indent=2), encoding="utf-8")
    tmp_config.chmod(0o600)
    tmp_config.replace(config_file)
    config_file.chmod(0o600)
    if not shutil.which(bin_name) and not Path(bin_name).exists():
        raise RuntimeError(f"sing-box binary not found: {bin_name}")
    check_sing_box_config(config_file, sing_box_bin=bin_name)
    if do_exec:
        exec_sing_box(config_file, sing_box_bin=bin_name)
    return {"config_file": str(config_file), "config": config_dict, "slot_count": count}


def main() -> None:
    run_bridge(do_exec=True)


if __name__ == "__main__":
    main()
