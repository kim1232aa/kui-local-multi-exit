from __future__ import annotations

import base64
import json
import os
import re
import socket
import time
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

from .vpngate import fetch_api_text, sanitize_openvpn_config


VPNBOOK_PAGE_URL = "https://www.vpnbook.com/freevpn/openvpn"
VPNBOOK_API_URL = "https://www.vpnbook.com/api/openvpn"
PUBLICVPNLIST_COUNTRIES_URL = "https://publicvpnlist.com/api/v1/countries"
DEFAULT_MANUAL_DIR = "/opt/kui-providers"
MAX_PROFILE_BYTES = 512 * 1024


def _fetch_text(url: str, timeout: int = 20) -> str:
    return fetch_api_text(url, timeout=timeout)


def _resolve_remote_ipv4(raw: str) -> str:
    match = re.search(r"(?mi)^\s*remote\s+(\S+)(?:\s+\d+)?", raw)
    if not match:
        raise ValueError("OpenVPN profile has no remote")
    host = match.group(1).strip("[]")
    try:
        return str(__import__("ipaddress").IPv4Address(host))
    except ValueError:
        pass
    for result in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM):
        return result[4][0]
    raise OSError(f"no IPv4 endpoint for {host}")


def _node_from_profile(
    raw: str,
    *,
    country: str,
    source: str,
    username: str = "",
    password: str = "",
    ping: int = 5000,
    score: int = 0,
    provider_id: str = "",
) -> dict[str, Any]:
    endpoint_ip = _resolve_remote_ipv4(raw)
    return {
        "ip": endpoint_ip,
        "country": country.upper(),
        "ping": int(ping),
        "score": int(score),
        "config": sanitize_openvpn_config(raw, endpoint_ip),
        "harvested_at": time.time(),
        "source": source,
        "username": username,
        "password": password,
        "provider_id": provider_id,
    }


def fetch_vpnbook_nodes(timeout: int = 20) -> list[dict[str, Any]]:
    if os.environ.get("KUI_ENABLE_VPNBOOK", "1").strip().lower() in {"0", "false", "no"}:
        return []
    page = _fetch_text(VPNBOOK_PAGE_URL, timeout=timeout)
    server_matches = re.findall(
        r'\\?"id\\?":\\?"([^"\\]+)\\?".*?'
        r'\\?"hostname\\?":\\?"([^"\\]+)\\?".*?'
        r'\\?"countryCode\\?":\\?"([A-Z]{2})\\?"',
        page,
        flags=re.DOTALL,
    )
    seen_hosts: set[str] = set()
    servers: list[tuple[str, str, str]] = []
    for server_id, hostname, country in server_matches:
        if not hostname.endswith(".vpnbook.com") or hostname in seen_hosts:
            continue
        if not re.fullmatch(r"(?:us|ca|uk|de|fr)\d+", server_id):
            server_id = hostname.split(".", 1)[0]
        if not re.fullmatch(r"(?:us|ca|uk|de|fr)\d+", server_id):
            continue
        seen_hosts.add(hostname)
        servers.append((server_id, hostname, country))
    password_match = re.search(
        r'Password</label>.*?<code[^>]*>([A-Za-z0-9_-]{4,64})</code>',
        page,
        flags=re.DOTALL | re.IGNORECASE,
    )
    if not servers or not password_match:
        raise ValueError("unable to parse VPNBook servers or credentials")
    username = "vpnbook"
    password = password_match.group(1)
    nodes: list[dict[str, Any]] = []
    for index, (server_id, hostname, country) in enumerate(servers):
        query = urllib.parse.urlencode({"hostname": hostname, "protocol": "tcp443"})
        try:
            raw = _fetch_text(f"{VPNBOOK_API_URL}?{query}", timeout=timeout)
            nodes.append(
                _node_from_profile(
                    raw,
                    country=country,
                    source="vpnbook",
                    username=username,
                    password=password,
                    ping=2000 + index,
                    provider_id=server_id,
                )
            )
        except Exception:
            continue
    return nodes


def _manual_metadata(path: Path) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for candidate in (path.with_suffix(".json"), path.parent / "provider.json"):
        if not candidate.is_file():
            continue
        value = json.loads(candidate.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            metadata.update({str(key): str(item) for key, item in value.items() if item is not None})
    return metadata


def _country_from_path(path: Path, metadata: dict[str, str]) -> str:
    explicit = metadata.get("country", "").upper()
    if re.fullmatch(r"[A-Z]{2}", explicit):
        return explicit
    for token in (path.parent.name, path.stem):
        match = re.search(r"(?:^|[-_.])([A-Za-z]{2})(?:[-_.]|$)", token)
        if match:
            return match.group(1).upper()
    return "ZZ"


def load_manual_nodes(root: str | Path | None = None) -> list[dict[str, Any]]:
    provider_root = Path(root or os.environ.get("KUI_OPENVPN_PROVIDER_DIR", DEFAULT_MANUAL_DIR))
    if not provider_root.is_dir():
        return []
    nodes: list[dict[str, Any]] = []
    for path in sorted(provider_root.rglob("*.ovpn")):
        try:
            if path.stat().st_size > MAX_PROFILE_BYTES:
                continue
            raw = path.read_text(encoding="utf-8")
            metadata = _manual_metadata(path)
            nodes.append(
                _node_from_profile(
                    raw,
                    country=_country_from_path(path, metadata),
                    source=metadata.get("source", f"manual:{path.parent.name}"),
                    username=metadata.get("username", ""),
                    password=metadata.get("password", ""),
                    ping=int(metadata.get("ping", "3000")),
                    score=int(metadata.get("score", "0")),
                    provider_id=str(path.relative_to(provider_root)),
                )
            )
        except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
            continue
    return nodes


def fetch_publicvpnlist_catalog(timeout: int = 15) -> dict[str, Any]:
    try:
        payload = json.loads(_fetch_text(PUBLICVPNLIST_COUNTRIES_URL, timeout=timeout))
    except Exception as error:
        return {"source": "publicvpnlist", "error": str(error)[:500], "countries": {}, "checked_at": int(time.time())}
    countries: dict[str, int] = {}
    for item in payload.get("data", []):
        if not isinstance(item, dict):
            continue
        code = str(item.get("country_code", "")).upper()
        count = int(item.get("online_count") or item.get("server_count") or item.get("count") or 0)
        if re.fullmatch(r"[A-Z]{2}", code):
            countries[code] = count
    return {
        "source": "publicvpnlist",
        "countries": countries,
        "meta": payload.get("meta", {}),
        "checked_at": int(time.time()),
    }


def fetch_proton_nodes(timeout: int = 20) -> list[dict[str, Any]]:
    # Proton OpenVPN profiles and credentials are account-specific. Import them
    # through KUI_OPENVPN_PROVIDER_DIR; this hook keeps provider reporting clear.
    del timeout
    return []


def _deduplicate(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}
    source_priority = {"manual": 0, "vpnbook": 1, "vpngate": 2}
    for node in nodes:
        ip = str(node["ip"])
        previous = selected.get(ip)
        if previous is None:
            selected[ip] = node
            continue
        current_source = str(node.get("source", ""))
        previous_source = str(previous.get("source", ""))
        current_rank = next((rank for prefix, rank in source_priority.items() if current_source.startswith(prefix)), 9)
        previous_rank = next((rank for prefix, rank in source_priority.items() if previous_source.startswith(prefix)), 9)
        if (current_rank, int(node.get("ping", 9999)), -int(node.get("score", 0))) < (
            previous_rank,
            int(previous.get("ping", 9999)),
            -int(previous.get("score", 0)),
        ):
            selected[ip] = node
    return list(selected.values())


def fetch_all_openvpn_nodes(timeout: int = 60) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from .vpngate import fetch_nodes

    providers: dict[str, dict[str, Any]] = {}
    combined: list[dict[str, Any]] = []
    for name, loader in (
        ("vpngate", lambda: fetch_nodes(timeout=timeout)),
        ("vpnbook", lambda: fetch_vpnbook_nodes(timeout=min(timeout, 20))),
        ("manual", load_manual_nodes),
        ("proton", lambda: fetch_proton_nodes(timeout=min(timeout, 20))),
    ):
        try:
            nodes = loader()
            if name == "vpngate":
                for node in nodes:
                    node.setdefault("source", "vpngate")
                    node.setdefault("username", "vpn")
                    node.setdefault("password", "vpn")
            providers[name] = {"ok": True, "count": len(nodes)}
            combined.extend(nodes)
        except Exception as error:
            providers[name] = {"ok": False, "count": 0, "error": str(error)[:500]}
    public_catalog = fetch_publicvpnlist_catalog(timeout=min(timeout, 15))
    providers["publicvpnlist"] = {
        "ok": "error" not in public_catalog,
        "metadata_only": True,
        "country_count": len(public_catalog.get("countries", {})),
        "error": public_catalog.get("error", ""),
    }
    nodes = _deduplicate(combined)
    return nodes, {
        "providers": providers,
        "countries": dict(Counter(str(node.get("country", "ZZ")) for node in nodes)),
        "total": len(nodes),
        "publicvpnlist": public_catalog,
        "refreshed_at": int(time.time()),
    }
