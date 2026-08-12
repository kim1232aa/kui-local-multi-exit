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


def _extra_json(values: dict[str, Any]) -> str:
    compact = {key: value for key, value in values.items() if value not in ("", None, False, [])}
    return json.dumps(compact, ensure_ascii=False, separators=(",", ":")) if compact else ""


def _parse_vless(raw: str) -> dict[str, Any] | None:
    try:
        parsed = urlsplit(raw)
        if not parsed.username or not parsed.hostname:
            return None
        params = parse_qs(parsed.query)
        security = _first(params, "security", "none").lower()
        public_key = _first(params, "pbk") or _first(params, "public_key")
        short_id = _first(params, "sid") or _first(params, "short_id")
        sni = _first(params, "sni") or _first(params, "servername") or parsed.hostname
        protocol = "Reality" if security == "reality" or public_key else "VLESS"
        metadata = {
            "security": security,
            "fingerprint": _first(params, "fp") or _first(params, "fingerprint"),
            "alpn": _first(params, "alpn"),
            "service_name": _first(params, "serviceName") or _first(params, "service_name"),
            "insecure": any(
                _first(params, key).lower() in {"1", "true"}
                for key in ("allowInsecure", "allow_insecure", "insecure")
            ),
        }
        node = _empty_node(protocol, name=unquote(parsed.fragment), address=parsed.hostname, port=parsed.port or 443)
        node.update({
            "uuid": unquote(parsed.username),
            "sni": sni,
            "public_key": public_key,
            "short_id": short_id,
            "flow": _first(params, "flow"),
            "network": _first(params, "type", "tcp").lower(),
            "host": _first(params, "host"),
            "path": _first(params, "path"),
            "extra": _extra_json(metadata),
        })
        return node
    except (TypeError, ValueError):
        return None


def _parse_password_url(raw: str, protocol: str, *, udp: bool = False) -> dict[str, Any] | None:
    try:
        parsed = urlsplit(raw)
        if not parsed.hostname or not parsed.username:
            return None
        params = parse_qs(parsed.query)
        metadata = {
            "insecure": (
                _first(params, "insecure").lower() in {"1", "true"}
                or _first(params, "allowInsecure").lower() in {"1", "true"}
                or _first(params, "allow_insecure").lower() in {"1", "true"}
            ),
            "alpn": _first(params, "alpn"),
        }
        node = _empty_node(protocol, name=unquote(parsed.fragment), address=parsed.hostname, port=parsed.port or 443)
        node.update({
            "password": unquote(parsed.username),
            "sni": _first(params, "sni", parsed.hostname),
            "network": "udp" if udp else "tcp",
            "extra": _extra_json(metadata),
        })
        return node
    except (TypeError, ValueError):
        return None


def _parse_hysteria2(raw: str) -> dict[str, Any] | None:
    node = _parse_password_url(raw, "Hysteria2", udp=True)
    if node:
        node["uuid"] = node["password"]
    return node


def _parse_tuic_or_naive(raw: str, protocol: str, *, udp: bool = False) -> dict[str, Any] | None:
    try:
        parsed = urlsplit(raw)
        if not parsed.hostname or not parsed.username:
            return None
        params = parse_qs(parsed.query)
        metadata = {
            "insecure": (
                _first(params, "insecure").lower() in {"1", "true"}
                or _first(params, "allowInsecure").lower() in {"1", "true"}
                or _first(params, "allow_insecure").lower() in {"1", "true"}
            ),
            "alpn": _first(params, "alpn"),
        }
        node = _empty_node(protocol, name=unquote(parsed.fragment), address=parsed.hostname, port=parsed.port or 443)
        node.update({
            "uuid": unquote(parsed.username),
            "password": unquote(parsed.password or ""),
            "sni": _first(params, "sni", parsed.hostname),
            "network": "udp" if udp else "tcp",
            "extra": _extra_json(metadata),
        })
        return node
    except (TypeError, ValueError):
        return None


def _parse_socks(raw: str) -> dict[str, Any] | None:
    try:
        parsed = urlsplit(raw)
        if not parsed.hostname:
            return None
        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        # A few feeds use the v2ray-style base64 credential form in the
        # userinfo component. Accept it without changing the stored schema.
        if username and not password and ":" not in username:
            try:
                decoded = _decode_base64(username)
                if ":" in decoded:
                    username, password = decoded.split(":", 1)
            except (ValueError, UnicodeError):
                pass
        node = _empty_node("Socks5", name=unquote(parsed.fragment), address=parsed.hostname, port=parsed.port or 1080)
        node.update({
            "password": password,
            "sni": parsed.hostname,
            "extra": _extra_json({"username": username}),
        })
        return node
    except (TypeError, ValueError):
        return None


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
    if lowered.startswith(("socks5://", "socks://")):
        return _parse_socks(raw)
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


_SINGBOX_RESERVED_TAGS = {"select", "auto", "direct", "dns-local"}


def _extra_data(node: dict[str, Any]) -> dict[str, Any]:
    raw = node.get("extra")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.lstrip().startswith("{"):
        try:
            value = json.loads(raw)
            if isinstance(value, dict):
                return value
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
    return {}


def _vmess_data(node: dict[str, Any]) -> dict[str, Any]:
    raw = node.get("extra")
    if not isinstance(raw, str) or not raw.lower().startswith("vmess://"):
        return {}
    try:
        value = json.loads(_decode_base64(raw[8:]))
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError, json.JSONDecodeError, UnicodeError):
        return {}


def _node_value(node: dict[str, Any], key: str, default: Any = "") -> Any:
    value = node.get(key)
    if value not in (None, ""):
        return value
    for source in (_extra_data(node), _vmess_data(node)):
        value = source.get(key)
        if value not in (None, ""):
            return value
    return default


def _reality_values(node: dict[str, Any]) -> tuple[str, str]:
    public_key = str(
        _node_value(node, "public_key", "")
        or _node_value(node, "public-key", "")
        or _node_value(node, "pbk", "")
        or ""
    )
    short_id = str(
        _node_value(node, "short_id", "")
        or _node_value(node, "short-id", "")
        or _node_value(node, "sid", "")
        or ""
    )
    candidates: list[Any] = [
        node.get("reality-opts"),
        node.get("reality_opts"),
        _extra_data(node).get("reality-opts"),
        _extra_data(node).get("reality_opts"),
    ]
    tls = node.get("tls")
    if isinstance(tls, dict):
        candidates.append(tls.get("reality"))
    for options in candidates:
        if not isinstance(options, dict):
            continue
        public_key = public_key or str(
            options.get("public_key") or options.get("public-key") or options.get("pbk") or ""
        )
        short_id = short_id or str(
            options.get("short_id") or options.get("short-id") or options.get("sid") or ""
        )
    return public_key, short_id


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, dict):
        return bool(value.get("enabled", True))
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _protocol_name(node: dict[str, Any]) -> str:
    return str(node.get("protocol") or node.get("type") or "").strip().lower().replace("_", "-")


def _server_details(node: dict[str, Any]) -> tuple[str, int] | None:
    address = str(node.get("address") or node.get("server") or "").strip()
    port = _as_int(node.get("port") or node.get("server_port"), 0)
    if not address or not 1 <= port <= 65535:
        return None
    return address, port


def _unique_tag(node: dict[str, Any], used: set[str]) -> str:
    protocol = _protocol_name(node) or "node"
    details = _server_details(node)
    fallback = f"{protocol.upper()}-{details[0]}:{details[1]}" if details else protocol.upper()
    base = str(node.get("name") or fallback).strip() or fallback
    candidate = base
    suffix = 2
    while candidate in used:
        candidate = f"{base} ({suffix})"
        suffix += 1
    used.add(candidate)
    return candidate


def _split_values(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def _apply_transport(entry: dict[str, Any], node: dict[str, Any], forced_network: str = "") -> None:
    network = (forced_network or str(_node_value(node, "network", "tcp") or "tcp")).strip().lower()
    if network in {"tcp", "udp"}:
        if network == "udp":
            entry["network"] = "udp"
        return
    if network in {"ws", "websocket"}:
        transport: dict[str, Any] = {
            "type": "ws",
            "path": str(_node_value(node, "path", "/") or "/"),
        }
        host = str(_node_value(node, "host", "") or "")
        if host:
            transport["headers"] = {"Host": host}
        entry["transport"] = transport
    elif network in {"http", "h2"}:
        transport = {
            "type": "http",
            "path": str(_node_value(node, "path", "/") or "/"),
        }
        host = str(_node_value(node, "host", "") or _node_value(node, "sni", "") or "")
        if host:
            transport["host"] = [host]
        entry["transport"] = transport
    elif network == "grpc":
        service_name = str(_node_value(node, "service_name", "") or _node_value(node, "path", "")).lstrip("/")
        entry["transport"] = {"type": "grpc", "service_name": service_name or "grpc"}
    elif network in {"httpupgrade", "http-upgrade"}:
        entry["transport"] = {
            "type": "httpupgrade",
            "path": str(_node_value(node, "path", "/") or "/"),
            "host": str(_node_value(node, "host", "") or ""),
        }
    elif network == "quic":
        entry["transport"] = {"type": "quic"}


def _tls_config(node: dict[str, Any], server: str, *, force: bool = False, reality: bool = False) -> dict[str, Any] | None:
    tls_value = node.get("tls")
    tls_enabled = force or reality or _as_bool(tls_value)
    security = str(_node_value(node, "security", "") or "").lower()
    if security in {"tls", "xtls", "reality"}:
        tls_enabled = True
    if not tls_enabled:
        return None
    server_name = str(_node_value(node, "sni", "") or _node_value(node, "servername", "") or server)
    tls: dict[str, Any] = {"enabled": True, "server_name": server_name}
    alpn = _split_values(_node_value(node, "alpn", ""))
    if alpn:
        tls["alpn"] = alpn
    insecure = node.get("insecure") or node.get("skip-cert-verify") or _node_value(node, "insecure", False)
    if _as_bool(insecure):
        tls["insecure"] = True
    fingerprint = str(
        node.get("client-fingerprint")
        or _node_value(node, "fingerprint", "")
        or _node_value(node, "fp", "")
        or ("chrome" if reality else "")
    )
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if reality:
        public_key, short_id = _reality_values(node)
        if not public_key:
            return None
        tls["reality"] = {
            "enabled": True,
            "public_key": public_key,
            "short_id": short_id,
        }
    return tls


def _naive_tls_config(node: dict[str, Any], server: str) -> dict[str, Any]:
    return {
        "enabled": True,
        "server_name": str(_node_value(node, "sni", "") or _node_value(node, "servername", "") or server),
    }


def _build_singbox_outbound(node: dict[str, Any], tag: str) -> dict[str, Any] | None:
    protocol = _protocol_name(node)
    details = _server_details(node)
    if not details:
        return None
    server, port = details

    if protocol in {"socks", "socks5", "socks-5"}:
        entry: dict[str, Any] = {
            "type": "socks",
            "tag": tag,
            "server": server,
            "server_port": port,
            "version": "5",
        }
        username = str(node.get("username") or _node_value(node, "username", "") or node.get("uuid", "") or "")
        password = str(node.get("password") or "")
        if username or password:
            entry["username"] = username
            entry["password"] = password
        _apply_transport(entry, node)
        return entry

    reality_protocols = {"reality", "xtls-reality", "h2-reality", "grpc-reality"}
    if protocol in {"vless", *reality_protocols}:
        uuid = str(_node_value(node, "uuid", "") or "")
        if not uuid:
            return None
        public_key, _ = _reality_values(node)
        is_reality = (
            protocol in reality_protocols
            or bool(public_key)
            or str(_node_value(node, "security", "") or "").lower() == "reality"
        )
        if is_reality and not public_key:
            return None
        entry = {
            "type": "vless",
            "tag": tag,
            "server": server,
            "server_port": port,
            "uuid": uuid,
        }
        flow = str(_node_value(node, "flow", "") or "")
        if flow:
            entry["flow"] = flow
        tls = _tls_config(node, server, reality=is_reality)
        if is_reality and not tls:
            return None
        if tls:
            entry["tls"] = tls
        forced_network = {"h2-reality": "http", "grpc-reality": "grpc"}.get(protocol, "")
        _apply_transport(entry, node, forced_network)
        return entry

    if protocol == "vmess":
        uuid = str(node.get("uuid") or _node_value(node, "id", "") or "")
        if not uuid:
            return None
        security = str(_node_value(node, "security", "") or _node_value(node, "scy", "auto") or "auto")
        if security not in {"auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305", "aes-128-ctr"}:
            security = "auto"
        entry = {
            "type": "vmess",
            "tag": tag,
            "server": server,
            "server_port": port,
            "uuid": uuid,
            "security": security,
            "alter_id": _as_int(_node_value(node, "alter_id", _node_value(node, "aid", 0)), 0),
        }
        vmess_tls = _node_value(node, "tls", "")
        if vmess_tls and not isinstance(vmess_tls, dict):
            tls_node = {**node, "tls": str(vmess_tls).lower() not in {"", "none", "false", "0"}}
        else:
            tls_node = node
        tls = _tls_config(tls_node, server)
        if tls:
            entry["tls"] = tls
        _apply_transport(entry, node)
        return entry

    if protocol == "trojan":
        password = str(node.get("password") or node.get("private_key") or "")
        if not password:
            return None
        entry = {
            "type": "trojan",
            "tag": tag,
            "server": server,
            "server_port": port,
            "password": password,
        }
        tls = _tls_config(node, server, force=True)
        if tls:
            entry["tls"] = tls
        _apply_transport(entry, node)
        return entry

    if protocol in {"hysteria2", "hy2", "hysteria"}:
        password = str(node.get("password") or node.get("uuid") or node.get("private_key") or "")
        if not password:
            return None
        entry = {
            "type": "hysteria2",
            "tag": tag,
            "server": server,
            "server_port": port,
            "password": password,
        }
        tls = _tls_config(node, server, force=True)
        if tls:
            entry["tls"] = tls
        _apply_transport(entry, node)
        return entry

    if protocol == "tuic":
        uuid = str(_node_value(node, "uuid", "") or "")
        password = str(node.get("password") or node.get("private_key") or "")
        if not uuid or not password:
            return None
        entry = {
            "type": "tuic",
            "tag": tag,
            "server": server,
            "server_port": port,
            "uuid": uuid,
            "password": password,
        }
        tls = _tls_config(node, server, force=True)
        if tls:
            entry["tls"] = tls
        _apply_transport(entry, node)
        return entry

    if protocol in {"ss", "shadowsocks"}:
        method = str(node.get("cipher") or _node_value(node, "method", "") or node.get("uuid") or "")
        password = str(node.get("password") or "")
        if not method or not password:
            return None
        return {
            "type": "shadowsocks",
            "tag": tag,
            "server": server,
            "server_port": port,
            "method": method,
            "password": password,
        }

    if protocol == "anytls":
        password = str(node.get("password") or node.get("private_key") or "")
        if not password:
            return None
        entry = {
            "type": "anytls",
            "tag": tag,
            "server": server,
            "server_port": port,
            "password": password,
        }
        tls = _tls_config(node, server, force=True)
        if tls:
            entry["tls"] = tls
        return entry

    if protocol == "naive":
        username = str(node.get("uuid") or node.get("username") or "")
        password = str(node.get("password") or node.get("private_key") or "")
        if not username or not password:
            return None
        entry = {
            "type": "naive",
            "tag": tag,
            "server": server,
            "server_port": port,
            "username": username,
            "password": password,
            "tls": _naive_tls_config(node, server),
        }
        return entry

    # Keep unsupported third-party protocols out of the JSON instead of
    # emitting a guessed outbound that the sing-box validator would reject.
    return None


def generate_singbox_config(outbound_nodes: list[dict[str, Any]]) -> str:
    """Generate a sing-box 1.13-compatible client configuration."""
    entries: list[dict[str, Any]] = []
    tags: list[str] = []
    used_tags = set(_SINGBOX_RESERVED_TAGS)
    for node in outbound_nodes or []:
        if not isinstance(node, dict):
            continue
        tag = _unique_tag(node, used_tags)
        try:
            entry = _build_singbox_outbound(node, tag)
        except (TypeError, ValueError, KeyError):
            entry = None
        if entry is not None:
            entries.append(entry)
            tags.append(tag)

    outbounds: list[dict[str, Any]] = [{"type": "direct", "tag": "direct"}]
    outbounds.extend(entries)
    if tags:
        outbounds.append({
            "type": "urltest",
            "tag": "auto",
            "outbounds": tags,
            "url": "https://www.gstatic.com/generate_204",
            "interval": "3m",
        })
        selector_targets = ["auto", *tags, "direct"]
        selector_default = "auto"
    else:
        selector_targets = ["direct"]
        selector_default = "direct"
    outbounds.append({
        "type": "selector",
        "tag": "select",
        "outbounds": selector_targets,
        "default": selector_default,
    })

    config = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [{"type": "local", "tag": "dns-local"}],
            "final": "dns-local",
        },
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 2080,
        }],
        "outbounds": outbounds,
        "route": {
            "rules": [
                {"action": "hijack-dns"},
                {"ip_is_private": True, "action": "route", "outbound": "direct"},
            ],
            "final": "select",
            "auto_detect_interface": True,
        },
    }
    return json.dumps(config, indent=2, ensure_ascii=False)
