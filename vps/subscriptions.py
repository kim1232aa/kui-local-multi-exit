from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit


@dataclass(frozen=True)
class ParseResult:
    nodes: list[dict[str, Any]]
    protocol_counts: dict[str, int]
    debug: dict[str, Any]


def _decode_base64(value: str) -> str:
    normalized = value.strip().replace("-", "+").replace("_", "/")
    normalized += "=" * (-len(normalized) % 4)
    return base64.b64decode(normalized).decode("utf-8")


def _empty_node(protocol: str, *, name: str, address: str, port: int) -> dict[str, Any]:
    return {
        "name": name,
        "protocol": protocol,
        "address": address,
        "port": port,
        "uuid": "",
        "password": "",
        "sni": "",
        "public_key": "",
        "short_id": "",
        "flow": "",
        "network": "tcp",
        "host": "",
        "path": "",
        "extra": "",
    }


def _first(params: dict[str, list[str]], key: str, default: str = "") -> str:
    return unquote(params.get(key, [default])[0])


def _parse_vless(raw: str) -> dict[str, Any] | None:
    parsed = urlsplit(raw)
    if not parsed.username or not parsed.hostname:
        return None
    params = parse_qs(parsed.query)
    public_key = _first(params, "pbk")
    protocol = "Reality" if _first(params, "security") == "reality" or public_key else "VLESS"
    node = _empty_node(protocol, name=unquote(parsed.fragment), address=parsed.hostname, port=parsed.port or 443)
    node.update({
        "uuid": unquote(parsed.username),
        "sni": _first(params, "sni", parsed.hostname),
        "public_key": public_key,
        "short_id": _first(params, "sid"),
        "flow": _first(params, "flow"),
        "network": _first(params, "type", "tcp").lower(),
        "host": _first(params, "host"),
        "path": _first(params, "path"),
    })
    return node


def _parse_password_url(raw: str, protocol: str, *, udp: bool = False) -> dict[str, Any] | None:
    parsed = urlsplit(raw)
    if not parsed.hostname or not parsed.username:
        return None
    params = parse_qs(parsed.query)
    node = _empty_node(protocol, name=unquote(parsed.fragment), address=parsed.hostname, port=parsed.port or 443)
    node.update({
        "password": unquote(parsed.username),
        "sni": _first(params, "sni", parsed.hostname),
        "network": "udp" if udp else "tcp",
    })
    return node


def _parse_hysteria2(raw: str) -> dict[str, Any] | None:
    node = _parse_password_url(raw, "Hysteria2", udp=True)
    if node:
        node["uuid"] = node["password"]
    return node


def _parse_tuic_or_naive(raw: str, protocol: str, *, udp: bool = False) -> dict[str, Any] | None:
    parsed = urlsplit(raw)
    if not parsed.hostname or not parsed.username:
        return None
    params = parse_qs(parsed.query)
    node = _empty_node(protocol, name=unquote(parsed.fragment), address=parsed.hostname, port=parsed.port or 443)
    node.update({
        "uuid": unquote(parsed.username),
        "password": unquote(parsed.password or ""),
        "sni": _first(params, "sni", parsed.hostname),
        "network": "udp" if udp else "tcp",
    })
    return node


def _parse_vmess(raw: str) -> dict[str, Any] | None:
    try:
        data = json.loads(_decode_base64(raw[8:]))
        address = str(data.get("add") or data.get("host") or "")
        if not address or not data.get("id"):
            return None
        node = _empty_node("VMess", name=str(data.get("ps") or ""), address=address, port=int(data.get("port") or 443))
        node.update({
            "uuid": str(data.get("id") or data.get("uuid") or ""),
            "sni": str(data.get("sni") or data.get("host") or address),
            "network": str(data.get("net") or "tcp").lower(),
            "host": str(data.get("host") or ""),
            "path": str(data.get("path") or ""),
            "extra": raw,
        })
        return node
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeError):
        return None


def _parse_ss(raw: str) -> dict[str, Any] | None:
    without_fragment, _, fragment = raw[5:].partition("#")
    try:
        if "@" in without_fragment:
            credentials, endpoint = without_fragment.rsplit("@", 1)
            method_password = _decode_base64(credentials)
        else:
            method_password, endpoint = _decode_base64(without_fragment).rsplit("@", 1)
        method, password = method_password.split(":", 1)
        parsed = urlsplit(f"//{endpoint}")
        if not parsed.hostname:
            return None
        node = _empty_node("SS", name=unquote(fragment), address=parsed.hostname, port=parsed.port or 8388)
        node.update({"uuid": method, "password": password, "sni": parsed.hostname, "extra": json.dumps({"method": method})})
        return node
    except (ValueError, UnicodeError):
        return None


def _parse_ssr(raw: str) -> dict[str, Any] | None:
    try:
        decoded = _decode_base64(raw[6:].split("#", 1)[0])
        base = decoded.split("/?", 1)[0]
        address, port, protocol_mode, method, obfs, encoded_password = base.split(":", 5)
        node = _empty_node("SSR", name="", address=address, port=int(port or 8388))
        node.update({
            "uuid": method,
            "password": _decode_base64(encoded_password),
            "sni": address,
            "extra": json.dumps({"method": method, "protocol": protocol_mode, "obfs": obfs}),
        })
        return node
    except (ValueError, UnicodeError):
        return None


def _parse_line(raw: str) -> dict[str, Any] | None:
    lowered = raw.lower()
    if lowered.startswith("vmess://"):
        return _parse_vmess(raw)
    if lowered.startswith("vless://"):
        return _parse_vless(raw)
    if lowered.startswith("trojan://"):
        return _parse_password_url(raw, "Trojan")
    if lowered.startswith(("hysteria2://", "hy2://", "hysteria://")):
        return _parse_hysteria2(raw)
    if lowered.startswith("tuic://"):
        return _parse_tuic_or_naive(raw, "TUIC", udp=True)
    if lowered.startswith(("naive+https://", "naive://")):
        return _parse_tuic_or_naive(raw, "Naive")
    if lowered.startswith("ss://"):
        return _parse_ss(raw)
    if lowered.startswith("anytls://"):
        return _parse_password_url(raw, "AnyTLS")
    return None


def parse_subscription(content: str) -> ParseResult:
    decoded = content.strip()
    if "://" not in decoded:
        try:
            decoded = _decode_base64(decoded)
        except (ValueError, UnicodeError):
            decoded = content
    lines = [line.strip() for line in decoded.splitlines() if line.strip()]
    nodes = [node for raw in lines if (node := _parse_line(raw))]
    protocol_counts: dict[str, int] = {}
    for node in nodes:
        protocol = str(node["protocol"])
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
    return ParseResult(
        nodes=nodes,
        protocol_counts=protocol_counts,
        debug={"totalLines": len(lines), "matched": len(nodes), "rejected": len(lines) - len(nodes)},
    )
