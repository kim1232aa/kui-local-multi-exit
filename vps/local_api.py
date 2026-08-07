from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import mimetypes
import re
import secrets
import socket
import time
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .exit_manager import ExitManager
from .proxy_server import set_credentials
from .realm_manager import RealmManager, RealmUnavailable
from .store import LocalStore
from .subscriptions import parse_subscription
from .vpngate import direct_url_opener, fetch_countries


TESTISP_API_URL = "https://testisp.info/api/check"
GITHUB_PROBE_DATA_URL = "https://raw.githubusercontent.com/a63414262/CF-Server-Monitor-Pro/refs/heads/main/nodes.json"
MAX_GITHUB_PROBE_DATA_BYTES = 4 * 1024 * 1024
MAX_SUBSCRIPTION_BYTES = 4 * 1024 * 1024


class UnsupportedField(ValueError):
    """The client sent a field this endpoint does not implement."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_subscription_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment or parsed.port not in {None, 443} or not parsed.hostname:
        raise ValueError("订阅地址不安全")
    if parsed.hostname.lower() in {"localhost", "localhost.localdomain"} or parsed.hostname.lower().endswith((".localhost", ".local")):
        raise ValueError("订阅地址不安全")
    addresses = {result[4][0] for result in socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)}
    if not addresses:
        raise ValueError("订阅地址无法解析")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError("订阅地址不安全")
    return parsed.geturl()


def fetch_subscription_text(value: str, timeout: int = 15) -> str:
    current = validate_subscription_url(value)
    opener = build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    for redirect_count in range(4):
        request = Request(current, headers={"User-Agent": "v2rayN/6.44", "Accept": "*/*"})
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            if 300 <= error.code < 400 and error.headers.get("Location") and redirect_count < 3:
                current = validate_subscription_url(urljoin(current, error.headers["Location"]))
                error.close()
                continue
            error.close()
            raise ValueError(f"订阅请求失败: {error.code}") from error
        with response:
            raw = response.read(MAX_SUBSCRIPTION_BYTES + 1)
        if len(raw) > MAX_SUBSCRIPTION_BYTES:
            raise ValueError("订阅文件过大")
        return raw.decode("utf-8")
    raise ValueError("订阅重定向过多")


def fetch_testisp_report(ip: str, timeout: int = 10) -> dict[str, Any]:
    normalized = str(ipaddress.ip_address(ip))
    request = Request(
        f"{TESTISP_API_URL}?ip={quote(normalized, safe='')}",
        headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
    )
    with direct_url_opener().open(request, timeout=timeout) as response:
        data = json.loads(response.read().decode("utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("geo"), dict) or not isinstance(data.get("isp"), dict):
        raise ValueError("TestISP returned an invalid report")
    return data


def fetch_github_probe_data(timeout: int = 15) -> dict[str, Any]:
    request = Request(
        GITHUB_PROBE_DATA_URL,
        headers={"User-Agent": "KUI-Local-Multi-Exit/1.0", "Accept": "application/json"},
    )
    with direct_url_opener().open(request, timeout=timeout) as response:
        raw = response.read(MAX_GITHUB_PROBE_DATA_BYTES + 1)
    if len(raw) > MAX_GITHUB_PROBE_DATA_BYTES:
        raise ValueError("probe data exceeds 4 MiB")
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("probe data must be a JSON object")
    if "themes" in data and not isinstance(data["themes"], list):
        raise ValueError("probe themes must be an array")
    return data


LOCAL_PROBE_SETTINGS = {
    "theme": "theme1",
    "is_public": "false",
    "site_title": "K-UI Local Multi-Exit",
    "show_price": "false",
    "show_expire": "false",
    "show_bw": "false",
    "show_tf": "false",
    "custom_css": "",
    "custom_bg": "",
    "custom_head": "",
    "custom_script": "",
    "report_interval": "15",
    "enable_popup": "false",
    "popup_content": "",
    "cached_nodes_data": "",
}

COUNTRY_PRESETS = (
    "US", "JP", "KR", "SG", "HK", "TW", "GB", "DE", "FR", "NL", "CA", "AU",
    "IN", "VN", "BR", "AE", "MY", "TH", "PH", "ID", "TR", "ZA", "IT", "ES",
    "RU", "CH", "SE", "PL", "NO", "DK", "FI", "IE", "AT", "NZ", "BE", "PT",
    "CZ", "GR", "HU", "RO", "BG", "HR", "SK", "SI", "LT", "LV", "EE", "UA",
    "RS", "BA", "CY", "MT", "IS", "LU",
)
VPS_FIELDS = {
    "ip", "name", "os", "egress_mode", "proxy_mode", "proxy_categories",
    "egress_revision", "egress_status", "egress_applied_mode",
    "egress_applied_revision", "egress_error", "egress_ip", "socks5_addr",
    "socks5_port", "socks5_user", "socks5_pass",
}
NODE_FIELDS = {
    "id", "ip", "vps_ip", "name", "protocol", "address", "port", "username",
    "uuid", "password", "sni", "private_key", "public_key", "short_id", "flow",
    "network", "host", "path", "extra", "relay_type", "target_ip", "target_port",
    "target_id", "enable", "traffic_used", "traffic_limit", "expire_time",
    "reset_traffic",
}


class LocalAPIServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        *,
        store: LocalStore,
        manager: ExitManager,
        realm_manager: RealmManager | None = None,
        web_root: Path | str,
        username: str,
        password: str,
    ):
        if not username or not password:
            raise ValueError("management username and password are required")
        self.store = store
        self.manager = manager
        self.realm_manager = realm_manager or RealmManager(store)
        self.web_root = Path(web_root).resolve()
        self.username = username
        self.password = password
        self._countries_cache: tuple[float, list[str]] | None = None
        super().__init__(address, LocalAPIHandler)


class LocalAPIHandler(BaseHTTPRequestHandler):
    server: LocalAPIServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, status: int, body: dict[str, Any] | list[Any]) -> None:
        payload = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def _send_text(self, status: int, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 65536:
            raise ValueError("request body is too large")
        raw = self.rfile.read(length) if length else b"{}"
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def _slot_match(self, suffix: str = ""):
        path = self.path.split("?", 1)[0]
        return re.fullmatch(rf"/api/local/exits/(exit-(?:0[1-9]|1[0-2])){suffix}", path)

    def _query_param(self, name: str) -> str | None:
        from urllib.parse import parse_qs, urlparse
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        values = params.get(name)
        return values[0] if values else None

    @staticmethod
    def _hash_password(password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def _probe_settings(self) -> dict[str, str]:
        """Merge stored settings over the local defaults so saved values win."""
        merged = dict(LOCAL_PROBE_SETTINGS)
        stored = self.server.store.get_all_settings()
        for key, value in stored.items():
            if key.startswith("probe_"):
                merged[key[len("probe_"):]] = value
            elif key in LOCAL_PROBE_SETTINGS:
                merged[key] = value
        return merged

    def _slot_projection(self) -> list[dict[str, Any]]:
        projected = []
        for slot in self.server.manager.snapshot():
            listener_ready = bool(self.server.manager.listener_ready(slot["id"]))
            updated_at = int(slot.get("updated_at") or 0)
            metadata: dict[str, Any] = {}
            raw_metadata = self.server.store.get_setting(f"probe_server_{slot['id']}")
            if raw_metadata:
                try:
                    parsed = json.loads(raw_metadata)
                    if isinstance(parsed, dict):
                        metadata = parsed
                except json.JSONDecodeError:
                    metadata = {}
            metadata.pop("id", None)
            projected.append(
                {
                    **slot,
                    "listener_ready": listener_ready,
                    "last_updated": updated_at * 1000,
                    "name": slot["id"],
                    "region": slot["country"],
                    "country_code": slot["country"],
                    "ping_ct": "0",
                    "ping_cu": "0",
                    "ping_cm": "0",
                    "ping_bd": "0",
                    "cpu": "0",
                    "memory": "0",
                    "net_in_speed": "0",
                    "net_out_speed": "0",
                    "net_rx": "0",
                    "net_tx": "0",
                    "monthly_rx": "0",
                    "monthly_tx": "0",
                    "realtime_state": "online"
                    if slot["enabled"] and slot["state"] == "ready" and listener_ready
                    else "offline",
                    **metadata,
                    "id": slot["id"],
                }
            )
        return projected

    def _statistics(self) -> list[dict[str, Any]]:
        daily: dict[str, dict[str, Any]] = {}

        def bucket(timestamp: int) -> dict[str, Any]:
            day = time.strftime("%Y-%m-%d", time.localtime(timestamp))
            return daily.setdefault(
                day,
                {
                    "day": day,
                    "event_count": 0,
                    "check_count": 0,
                    "accepted_checks": 0,
                    "total_bytes": 0,
                },
            )

        for event in self.server.store.list_events(limit=500):
            bucket(int(event["created_at"]))["event_count"] += 1
        for check in self.server.store.list_check_results(limit=500):
            row = bucket(int(check["created_at"]))
            row["check_count"] += 1
            result = check["result"]
            accepted = bool(result.get("accepted"))
            if not accepted and isinstance(result.get("targets"), dict):
                accepted = bool(result["targets"].get("accepted"))
            row["accepted_checks"] += int(accepted)
        return [daily[day] for day in sorted(daily)]

    def _publishable_slots(self) -> list[dict[str, Any]]:
        return [
            slot
            for slot in self._slot_projection()
            if slot["enabled"] and slot["state"] == "ready" and slot["listener_ready"]
        ]

    def _proxy_details(self) -> list[dict[str, Any]]:
        return [
            {
                "tunnel": slot["id"],
                "country": slot["country"],
                "node_ip": slot["egress_ip"] or slot["entry_ip"],
                "port": slot["proxy_port"],
                "active": slot["state"] == "ready" and self.server.manager.listener_ready(slot["id"]),
                "listener_ready": self.server.manager.listener_ready(slot["id"]),
            }
            for slot in self.server.manager.snapshot()
        ]

    def _proxy_nodes(self) -> list[dict[str, Any]]:
        events = self.server.store.list_events(limit=50)
        logs = "\n".join(
            f"[{event['created_at']}] {event['slot_id'] or 'local'} {event['kind']}: {event['message']}"
            for event in reversed(events)
        )
        return [
            {
                "ip": "local",
                "details": json.dumps(self._proxy_details(), ensure_ascii=False, separators=(",", ":")),
                "last_seen": int(time.time() * 1000),
                "logs": logs,
            }
        ]

    def _request_proxy_host(self) -> str:
        host = self.headers.get("Host", "127.0.0.1").strip()
        if host.startswith("["):
            return host[1:].split("]", 1)[0]
        return host.split(":", 1)[0] or "127.0.0.1"

    @staticmethod
    def _subscription_link(node: dict[str, Any]) -> str:
        address = str(node["address"])
        display_address = f"[{address}]" if ":" in address and not address.startswith("[") else address
        name = quote(str(node.get("name") or f"TP_{node['protocol']}_{node['port']}"), safe="")
        protocol = str(node["protocol"])
        if protocol == "VMess" and str(node.get("extra", "")).startswith("vmess://"):
            return str(node["extra"])
        if protocol in {"VLESS", "Reality"}:
            query = ["encryption=none"]
            if protocol == "Reality":
                query.extend(("security=reality", f"sni={quote(str(node.get('sni', '')), safe='')}", "fp=chrome"))
                if node.get("public_key"):
                    query.append(f"pbk={quote(str(node['public_key']), safe='')}")
                if node.get("short_id"):
                    query.append(f"sid={quote(str(node['short_id']), safe='')}")
                if node.get("flow"):
                    query.append(f"flow={quote(str(node['flow']), safe='')}")
            else:
                query.append("security=none")
            query.append(f"type={quote(str(node.get('network') or 'tcp'), safe='')}")
            return f"vless://{quote(str(node.get('uuid', '')), safe='')}@{display_address}:{node['port']}?{'&'.join(query)}#{name}"
        if protocol == "Trojan":
            return f"trojan://{quote(str(node.get('password', '')), safe='')}@{display_address}:{node['port']}?security=tls&sni={quote(str(node.get('sni', '')), safe='')}#{name}"
        if protocol == "Hysteria2":
            return f"hysteria2://{quote(str(node.get('password') or node.get('uuid', '')), safe='')}@{display_address}:{node['port']}?insecure=1&sni={quote(str(node.get('sni', '')), safe='')}#{name}"
        if protocol == "TUIC":
            return f"tuic://{quote(str(node.get('uuid', '')), safe='')}:{quote(str(node.get('password', '')), safe='')}@{display_address}:{node['port']}?sni={quote(str(node.get('sni', '')), safe='')}#{name}"
        if protocol == "Naive":
            return f"naive+https://{quote(str(node.get('uuid', '')), safe='')}:{quote(str(node.get('password', '')), safe='')}@{display_address}:{node['port']}?sni={quote(str(node.get('sni', '')), safe='')}#{name}"
        if protocol == "AnyTLS":
            return f"anytls://{quote(str(node.get('password', '')), safe='')}@{display_address}:{node['port']}?sni={quote(str(node.get('sni', '')), safe='')}#{name}"
        if protocol == "SS":
            credentials = base64.urlsafe_b64encode(f"{node.get('uuid', '')}:{node.get('password', '')}".encode()).decode().rstrip("=")
            return f"ss://{credentials}@{display_address}:{node['port']}#{name}"
        return ""

    @staticmethod
    def _clash_proxy(node: dict[str, Any]) -> tuple[str, str] | None:
        name = str(node.get("name") or f"TP_{node['protocol']}_{node['port']}")
        quoted_name = json.dumps(name, ensure_ascii=False)
        address = json.dumps(str(node["address"]), ensure_ascii=False)
        protocol = str(node["protocol"])
        lines = [
            f"  - name: {quoted_name}",
            f"    type: {protocol.lower()}",
            f"    server: {address}",
            f"    port: {int(node['port'])}",
        ]
        if protocol in {"VLESS", "Reality"}:
            lines[1] = "    type: vless"
            lines.extend((f"    uuid: {json.dumps(str(node.get('uuid', '')))}", "    udp: true"))
            network = str(node.get("network") or "tcp")
            lines.append(f"    network: {json.dumps(network)}")
            if protocol == "Reality":
                lines.extend((
                    "    tls: true",
                    f"    servername: {json.dumps(str(node.get('sni', '')))}",
                    "    client-fingerprint: chrome",
                    "    reality-opts:",
                    f"      public-key: {json.dumps(str(node.get('public_key', '')))}",
                    f"      short-id: {json.dumps(str(node.get('short_id', '')))}",
                ))
                if node.get("flow"):
                    lines.append(f"    flow: {json.dumps(str(node['flow']))}")
            if network == "ws":
                lines.extend((
                    "    ws-opts:",
                    f"      path: {json.dumps(str(node.get('path') or '/'))}",
                    "      headers:",
                    f"        Host: {json.dumps(str(node.get('host') or node.get('sni') or node['address']))}",
                ))
            elif network == "grpc":
                lines.extend(("    grpc-opts:", f"      grpc-service-name: {json.dumps(str(node.get('path', '')).lstrip('/'))}"))
        elif protocol == "Trojan":
            lines.extend((
                f"    password: {json.dumps(str(node.get('password', '')))}",
                f"    sni: {json.dumps(str(node.get('sni', '')))}",
                "    udp: true",
            ))
        elif protocol == "Hysteria2":
            lines[1] = "    type: hysteria2"
            lines.extend((
                f"    password: {json.dumps(str(node.get('password') or node.get('uuid', '')))}",
                f"    sni: {json.dumps(str(node.get('sni', '')))}",
                "    skip-cert-verify: true",
            ))
        elif protocol == "TUIC":
            lines.extend((
                f"    uuid: {json.dumps(str(node.get('uuid', '')))}",
                f"    password: {json.dumps(str(node.get('password', '')))}",
                f"    sni: {json.dumps(str(node.get('sni', '')))}",
                "    skip-cert-verify: true",
                "    udp-relay-mode: native",
            ))
        elif protocol == "SS":
            lines[1] = "    type: ss"
            lines.extend((
                f"    cipher: {json.dumps(str(node.get('uuid', '')))}",
                f"    password: {json.dumps(str(node.get('password', '')))}",
                "    udp: true",
            ))
        elif protocol == "VMess":
            lines[1] = "    type: vmess"
            lines.extend((
                f"    uuid: {json.dumps(str(node.get('uuid', '')))}",
                "    alterId: 0",
                "    cipher: auto",
                "    udp: true",
                f"    network: {json.dumps(str(node.get('network') or 'tcp'))}",
            ))
            if str(node.get("network") or "") == "ws":
                lines.extend((
                    "    ws-opts:",
                    f"      path: {json.dumps(str(node.get('path') or '/'))}",
                    "      headers:",
                    f"        Host: {json.dumps(str(node.get('host') or node.get('sni') or node['address']))}",
                ))
        else:
            return None
        return name, "\n".join(lines)

    def _local_subscription_links(self) -> list[str]:
        host = self._request_proxy_host()
        username = quote(self.server.username, safe="")
        password = quote(self.server.password, safe="")
        links = []
        for slot in self._publishable_slots():
            name = quote(f"{slot['country']}_{slot['id']}_{slot['state']}", safe="")
            links.append(f"socks5://{username}:{password}@{host}:{slot['proxy_port']}#{name}")
        return links

    def _local_clash_proxies(self) -> list[tuple[str, str]]:
        host = self._request_proxy_host()
        proxies = []
        for slot in self._publishable_slots():
            name = f"{slot['country']}_{slot['id']}_{slot['state']}"
            proxy = "\n".join((
                f"  - name: {json.dumps(name, ensure_ascii=False)}",
                "    type: socks5",
                f"    server: {host}",
                f"    port: {slot['proxy_port']}",
                f"    username: {json.dumps(self.server.username)}",
                f"    password: {json.dumps(self.server.password)}",
                "    udp: true",
            ))
            proxies.append((name, proxy))
        return proxies

    def _ensure_admin_subscription_token(self) -> str:
        admin_user = self.server.store.get_user(self.server.username)
        if admin_user and admin_user.get("sub_token"):
            return str(admin_user["sub_token"])
        if not admin_user:
            self.server.store.add_user(self.server.username, self._hash_password(self.server.password))
        token = secrets.token_urlsafe(16)
        self.server.store.update_user(self.server.username, sub_token=token)
        return token

    def do_GET(self) -> None:
        if self.path.split("?", 1)[0] == "/healthz":
            self._send_json(HTTPStatus.OK, {"ok": True})
            return
        if self.path.split("?", 1)[0] == "/api/local/status":
            slots = [
                {**slot, "listener_ready": bool(self.server.manager.listener_ready(slot["id"]))}
                for slot in self.server.manager.snapshot()
            ]
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "total": len(slots),
                    "ready": len(self._publishable_slots()),
                    "enabled": sum(bool(slot["enabled"]) for slot in slots),
                    "exits": slots,
                },
            )
            return
        if self.path.split("?", 1)[0] == "/api/local/exits":
            slots = [
                {**slot, "listener_ready": bool(self.server.manager.listener_ready(slot["id"]))}
                for slot in self.server.manager.snapshot()
            ]
            self._send_json(HTTPStatus.OK, {"exits": slots})
            return
        path = self.path.split("?", 1)[0]
        if path.startswith("/api/local/events"):
            self._send_json(HTTPStatus.OK, {"events": self.server.store.list_events(limit=200)})
            return
        if path == "/api/data":
            servers = self.server.store.list_vps()
            nodes = self.server.store.list_nodes()
            users = self.server.store.list_users()
            safe_users = [{**u, "password": ""} for u in users]
            site_title = self.server.store.get_setting("site_title", "")
            my_sub_token = self._ensure_admin_subscription_token()
            self._send_json(HTTPStatus.OK, {
                "mode": "local",
                "servers": servers,
                "nodes": nodes,
                "users": safe_users,
                "exits": self.server.manager.snapshot(),
                "siteTitle": site_title,
                "mySubToken": my_sub_token,
                "realtimeUrl": "",
            })
            return
        if path == "/api/stats":
            self._send_json(HTTPStatus.OK, self._statistics())
            return
        if path == "/api/probe/public":
            self._send_json(
                HTTPStatus.OK,
                {"settings": self._probe_settings(), "servers": self._slot_projection(), "realtime_url": ""},
            )
            return
        if path == "/api/probe/admin/data":
            self._send_json(
                HTTPStatus.OK,
                {"settings": self._probe_settings(), "servers": self._slot_projection()},
            )
            return
        if path == "/api/realm":
            self._send_json(HTTPStatus.OK, self.server.realm_manager.status())
            return
        if path == "/api/local/deploy-command":
            self._send_json(
                HTTPStatus.OK,
                {
                    "repository_url": "https://github.com/kim1232aa/kui-local-multi-exit.git",
                    "environment": {
                        "KUI_MANAGEMENT_PASSWORD": "<shared-proxy-password>",
                        "KUI_FETCH_PROXY": "",
                        "KUI_OPENVPN_SOCKS_PROXY": "",
                    },
                    "compose_command": "docker compose up -d --build",
                },
            )
            return
        if path == "/api/proxy/countries":
            cached = self.server._countries_cache
            if cached and time.time() - cached[0] < 600:
                self._send_json(HTTPStatus.OK, cached[1])
                return
            configured = {slot["country"] for slot in self.server.manager.snapshot() if slot["country"] != "ANY"}
            countries = set(COUNTRY_PRESETS) | configured
            try:
                dynamic = fetch_countries(timeout=6)
                countries |= set(dynamic)
            except Exception:
                pass
            result = sorted(countries)
            self.server._countries_cache = (time.time(), result)
            self._send_json(HTTPStatus.OK, result)
            return
        if path == "/api/proxy/config":
            slots = self.server.manager.snapshot()
            first = slots[0] if slots else {"country": "JP", "proxy_port": 7920, "enabled": False}
            country = first["country"]
            port = first["proxy_port"]
            self._send_json(
                HTTPStatus.OK,
                {
                    "0": country,
                    "country": country,
                    "port": port,
                    "switch_trigger": 0,
                    "proxy": {
                        "enabled": bool(first["enabled"]),
                        "country": country,
                        "port": port,
                        "user": self.server.username,
                        "pass": self.server.password,
                    },
                    "realtime_url": "",
                },
            )
            return
        if path in {"/api/proxy/pool", "/api/proxy/nodes"}:
            self._send_json(HTTPStatus.OK, self._proxy_nodes())
            return
        if path == "/api/proxy/proxies":
            username = quote(self.server.username, safe="")
            password = quote(self.server.password, safe="")
            host = self._request_proxy_host()
            lines = [
                f"socks5://{username}:{password}@{host}:{slot['proxy_port']}#{slot['country']}_{slot['id']}_{slot['state']}"
                for slot in self._publishable_slots()
            ]
            self._send_text(HTTPStatus.OK, "\n".join(lines) + ("\n" if lines else ""))
            return
        if path == "/api/sub":
            if self.server.store.get_setting("probe_subscription_protection") == "true":
                self._send_text(HTTPStatus.OK, "K-UI Local Multi-Exit")
                return
            username = self._query_param("user") or ""
            token = self._query_param("token") or ""
            user = self.server.store.get_user(username)
            if not user or not user.get("enable") or not token or not hmac.compare_digest(token, str(user.get("sub_token", ""))):
                self._send_json(HTTPStatus.NOT_FOUND, {"code": "not_found", "error": "subscription not found"})
                return
            links = self._local_subscription_links()
            thirdparty_nodes = self.server.store.list_enabled_thirdparty_nodes()
            links.extend(link for node in thirdparty_nodes if (link := self._subscription_link(node)))
            if self._query_param("format") == "clash":
                proxy_entries = self._local_clash_proxies()
                for node in thirdparty_nodes:
                    if entry := self._clash_proxy(node):
                        proxy_entries.append(entry)
                proxy_lines = [entry for _, entry in proxy_entries]
                names = [name for name, _ in proxy_entries]
                names_yaml = "\n".join(f"      - {json.dumps(name, ensure_ascii=False)}" for name in names) or "      - DIRECT"
                body = (
                    "port: 7890\nsocks-port: 7891\nallow-lan: true\nmode: rule\nproxies:\n"
                    + "\n".join(proxy_lines)
                    + "\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies:\n"
                    + names_yaml
                    + "\nrules:\n  - MATCH,PROXY\n"
                )
                self._send_text(HTTPStatus.OK, body)
                return
            encoded = base64.b64encode("\n".join(links).encode()).decode()
            self._send_text(HTTPStatus.OK, encoded)
            return
        if path == "/api/vps":
            self._send_json(HTTPStatus.OK, self.server.store.list_vps())
            return
        if path == "/api/nodes":
            self._send_json(HTTPStatus.OK, self.server.store.list_nodes())
            return
        if path == "/api/users":
            users = self.server.store.list_users()
            safe_users = [{**u, "password": ""} for u in users]
            self._send_json(HTTPStatus.OK, safe_users)
            return
        if path == "/api/thirdparty":
            self._send_json(HTTPStatus.OK, self.server.store.list_thirdparty())
            return
        if path == "/api/local/nodes":
            country = self._query_param("country") or "ANY"
            self._send_json(HTTPStatus.OK, self.server.manager.list_nodes(country))
            return
        if path == "/api/probe/detail":
            detail_id = self._query_param("id") or ""
            detail = next((slot for slot in self._slot_projection() if slot["id"] == detail_id), None)
            if detail is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"code": "not_found", "error": "probe server not found"})
                return
            detail["check_history"] = self.server.store.list_check_results(
                slot_id=detail_id,
                limit=100,
            )
            self._send_json(HTTPStatus.OK, detail)
            return
        if path == "/api/proxy/testisp-lookup":
            self._send_json(HTTPStatus.BAD_REQUEST, {"code": "invalid_request", "error": "IP is required"})
            return
        if path.startswith("/api/proxy/testisp-lookup/"):
            ip = path.rsplit("/", 1)[-1]
            try:
                report = fetch_testisp_report(ip)
            except ValueError as error:
                self._send_json(HTTPStatus.BAD_REQUEST, {"code": "invalid_request", "error": str(error)})
                return
            except Exception as error:
                self._send_json(HTTPStatus.BAD_GATEWAY, {"code": "upstream_error", "error": str(error)[:500]})
                return
            self._send_json(HTTPStatus.OK, report)
            return
        self._serve_asset()

    def do_PUT(self) -> None:
        path = self.path.split("?", 1)[0]
        match = self._slot_match()
        if match:
            slot_id = match.group(1)
            try:
                payload = self._read_json()
                allowed = {"country", "proxy_port", "enabled"}
                if set(payload) - allowed:
                    raise ValueError("unsupported slot field")
                current = self.server.store.validate_slot_update(
                    slot_id,
                    country=payload.get("country"),
                    proxy_port=payload.get("proxy_port"),
                    enabled=payload.get("enabled"),
                )
                changed = any(
                    getattr(current, key) != (str(value).upper() if key == "country" else value)
                    for key, value in payload.items()
                )
                if not changed:
                    self._send_json(HTTPStatus.OK, {"exit": current.as_dict()})
                    return
                if current.enabled:
                    self.server.manager.stop_slot(slot_id)
                updated = self.server.store.update_slot(slot_id, **payload)
                if updated.enabled:
                    updated = self.server.manager.start_slot(slot_id)
                self.server.store.record_event(slot_id, "configuration", "slot configuration updated")
                self._send_json(HTTPStatus.OK, {"exit": updated.as_dict()})
            except (ValueError, json.JSONDecodeError) as error:
                self._send_json(HTTPStatus.BAD_REQUEST, {"code": "invalid_request", "error": str(error)})
            except KeyError:
                self._send_json(HTTPStatus.NOT_FOUND, {"code": "not_found", "error": "slot not found"})
            return
        try:
            payload = self._read_json()
            if path == "/api/vps":
                unknown = set(payload) - VPS_FIELDS
                if unknown:
                    raise UnsupportedField(f"unsupported vps fields: {', '.join(sorted(unknown))}")
                ip = str(payload.get("ip", ""))
                if not ip:
                    raise ValueError("ip is required")
                fields = {key: value for key, value in payload.items() if key != "ip"}
                for key in ("socks5_port", "egress_revision", "egress_applied_revision"):
                    if key in fields:
                        fields[key] = int(fields[key])
                updated = self.server.store.update_vps(ip, **fields)
                self._send_json(HTTPStatus.OK, updated)
                return
            if path == "/api/nodes":
                unknown = set(payload) - NODE_FIELDS
                if unknown:
                    raise UnsupportedField(f"unsupported node fields: {', '.join(sorted(unknown))}")
                node_id = int(payload.get("id", 0))
                if not node_id:
                    raise ValueError("id is required")
                if payload.get("ip") and payload.get("vps_ip") and payload["ip"] != payload["vps_ip"]:
                    raise ValueError("ip and vps_ip must match")
                fields = {
                    key: value
                    for key, value in payload.items()
                    if key not in {"id", "vps_ip", "reset_traffic"}
                }
                if "vps_ip" in payload:
                    fields["ip"] = payload["vps_ip"]
                if payload.get("reset_traffic"):
                    fields["traffic_used"] = 0
                if "enable" in fields:
                    fields["enable"] = int(bool(fields["enable"]))
                for key in ("port", "target_port", "target_id", "traffic_used", "traffic_limit", "expire_time"):
                    if key in fields:
                        fields[key] = int(fields[key])
                updated = self.server.store.update_node(node_id, **fields)
                self._send_json(HTTPStatus.OK, updated)
                return
            if path == "/api/users":
                username = str(payload.get("username", ""))
                if not username:
                    raise ValueError("username is required")
                fields = {}
                if "enable" in payload:
                    fields["enable"] = int(bool(payload["enable"]))
                if payload.get("reset_traffic"):
                    fields["traffic_used"] = 0
                if "traffic_limit" in payload:
                    fields["traffic_limit"] = int(payload["traffic_limit"])
                if "expire_time" in payload:
                    fields["expire_time"] = int(payload["expire_time"])
                if fields:
                    updated = self.server.store.update_user(username, **fields)
                    self._send_json(HTTPStatus.OK, {**updated, "password": ""})
                else:
                    raise ValueError("no fields to update")
                return
            if path == "/api/settings":
                for key, value in payload.items():
                    self.server.store.set_setting(key, str(value))
                self._send_json(HTTPStatus.OK, {"success": True})
                return
            if path == "/api/user/password":
                new_password = str(payload.get("password", ""))
                if len(new_password) < 8:
                    raise ValueError("password must be at least 8 characters")
                password_hash = self._hash_password(new_password)
                admin_user = self.server.store.get_user(self.server.username)
                if admin_user:
                    self.server.store.update_user(self.server.username, password=password_hash)
                else:
                    self.server.store.add_user(self.server.username, password_hash)
                self.server.password = new_password
                set_credentials(self.server.username, new_password)
                self._send_json(HTTPStatus.OK, {"success": True})
                return
            if path == "/api/user/sub_token":
                new_token = secrets.token_urlsafe(16)
                admin_user = self.server.store.get_user(self.server.username)
                if admin_user:
                    self.server.store.update_user(self.server.username, sub_token=new_token)
                else:
                    self.server.store.add_user(self.server.username, self._hash_password(self.server.password))
                    self.server.store.update_user(self.server.username, sub_token=new_token)
                self._send_json(HTTPStatus.OK, {"sub_token": new_token})
                return
            if path == "/api/probe/admin/server":
                server_id = str(payload.get("id", "")).strip()
                try:
                    self.server.store.get_slot(server_id)
                except KeyError:
                    self._send_json(HTTPStatus.NOT_FOUND, {"code": "not_found", "error": "probe server not found"})
                    return
                allowed = {
                    "id", "name", "server_group", "is_hidden", "price", "expire_date",
                    "bandwidth", "traffic_limit", "reset_day",
                }
                unknown = set(payload) - allowed
                if unknown:
                    raise UnsupportedField(f"unsupported probe fields: {', '.join(sorted(unknown))}")
                metadata = {key: payload[key] for key in allowed if key in payload}
                metadata["id"] = server_id
                self.server.store.set_setting(
                    f"probe_server_{server_id}",
                    json.dumps(metadata, ensure_ascii=False, separators=(",", ":")),
                )
                self._send_json(HTTPStatus.OK, metadata)
                return
            if path == "/api/realm":
                self.server.realm_manager.configure(payload)
                self._send_json(HTTPStatus.OK, self.server.realm_manager.status())
                return
            if path == "/api/thirdparty":
                tp_id = int(payload.get("id", 0))
                fields = {k: payload[k] for k in ("name", "url", "enable") if k in payload}
                if "enable" in fields:
                    fields["enable"] = int(bool(fields["enable"]))
                updated = self.server.store.update_thirdparty(tp_id, **fields)
                self._send_json(HTTPStatus.OK, updated)
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"code": "not_found", "error": "endpoint not found"})
        except UnsupportedField as error:
            self._send_json(HTTPStatus.BAD_REQUEST, {"code": "unsupported_field", "error": str(error)})
        except (ValueError, json.JSONDecodeError) as error:
            self._send_json(HTTPStatus.BAD_REQUEST, {"code": "invalid_request", "error": str(error)})
        except KeyError:
            self._send_json(HTTPStatus.NOT_FOUND, {"code": "not_found", "error": "resource not found"})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/api/ui_ping":
            try:
                self._read_json()
            except (ValueError, json.JSONDecodeError) as error:
                self._send_json(HTTPStatus.BAD_REQUEST, {"code": "invalid_request", "error": str(error)})
                return
            self._send_json(HTTPStatus.OK, {"success": True})
            return
        connect_match = self._slot_match(re.escape("/connect"))
        if connect_match:
            try:
                payload = self._read_json()
                node_ip = str(payload.get("node_ip", "")).strip()
                if not node_ip:
                    raise ValueError("node_ip is required")
                slot = self.server.manager.connect_slot(connect_match.group(1), node_ip)
                self._send_json(HTTPStatus.ACCEPTED, {"accepted": True, "exit": slot.as_dict()})
            except KeyError:
                self._send_json(HTTPStatus.NOT_FOUND, {"code": "not_found", "error": "slot not found"})
            except (ValueError, json.JSONDecodeError) as error:
                self._send_json(HTTPStatus.BAD_REQUEST, {"code": "invalid_request", "error": str(error)})
            return
        actions = {
            "/redial": self.server.manager.redial_slot,
            "/enable": self.server.manager.enable_slot,
            "/disable": self.server.manager.disable_slot,
        }
        for suffix, action in actions.items():
            match = self._slot_match(re.escape(suffix))
            if not match:
                continue
            try:
                self._read_json()
                slot = action(match.group(1))
                self._send_json(HTTPStatus.ACCEPTED, {"accepted": True, "exit": slot.as_dict()})
            except KeyError:
                self._send_json(HTTPStatus.NOT_FOUND, {"code": "not_found", "error": "slot not found"})
            except (ValueError, json.JSONDecodeError) as error:
                self._send_json(HTTPStatus.BAD_REQUEST, {"code": "invalid_request", "error": str(error)})
            return
        try:
            payload = self._read_json()
            if path == "/api/realm":
                action = str(payload.get("action", "")).strip().lower()
                if action == "start":
                    result = self.server.realm_manager.start()
                elif action == "stop":
                    result = self.server.realm_manager.stop()
                elif action == "restart":
                    result = self.server.realm_manager.restart()
                else:
                    raise ValueError("action must be start, stop, or restart")
                self._send_json(HTTPStatus.OK, result)
                return
            if path == "/api/vps":
                unknown = set(payload) - VPS_FIELDS
                if unknown:
                    raise UnsupportedField(f"unsupported vps fields: {', '.join(sorted(unknown))}")
                ip = str(payload.get("ip", ""))
                name = str(payload.get("name", ""))
                if not ip:
                    raise ValueError("ip is required")
                os_type = str(payload.get("os", "debian"))
                fields = {
                    key: value
                    for key, value in payload.items()
                    if key not in {"ip", "name", "os"}
                }
                for key in ("socks5_port", "egress_revision", "egress_applied_revision"):
                    if key in fields:
                        fields[key] = int(fields[key])
                created = self.server.store.add_vps(ip, name, os_type, **fields)
                self.server.store.record_event(None, "vps", f"vps added: {ip} ({name})")
                self._send_json(HTTPStatus.OK, created)
                return
            if path == "/api/nodes":
                unknown = set(payload) - NODE_FIELDS
                if unknown:
                    raise UnsupportedField(f"unsupported node fields: {', '.join(sorted(unknown))}")
                if payload.get("ip") and payload.get("vps_ip") and payload["ip"] != payload["vps_ip"]:
                    raise ValueError("ip and vps_ip must match")
                ip = str(payload.get("vps_ip") or payload.get("ip") or "")
                name = str(payload.get("name") or payload.get("username") or "")
                protocol = str(payload.get("protocol", ""))
                traffic_limit = int(payload.get("traffic_limit", 0))
                expire_time = int(payload.get("expire_time", 0))
                if not ip:
                    raise ValueError("ip is required")
                fields = {
                    key: value
                    for key, value in payload.items()
                    if key not in {
                        "id", "ip", "vps_ip", "name", "protocol", "traffic_limit",
                        "expire_time", "reset_traffic",
                    }
                }
                if "enable" in fields:
                    fields["enable"] = int(bool(fields["enable"]))
                for key in ("port", "target_port", "target_id", "traffic_used"):
                    if key in fields:
                        fields[key] = int(fields[key])
                created = self.server.store.add_node(
                    ip,
                    name,
                    protocol,
                    traffic_limit,
                    expire_time,
                    node_id=int(payload["id"]) if payload.get("id") is not None else None,
                    **fields,
                )
                self._send_json(HTTPStatus.OK, created)
                return
            if path == "/api/users":
                username = str(payload.get("username", ""))
                password = str(payload.get("password", ""))
                if not username or not password:
                    raise ValueError("username and password are required")
                if len(password) < 8:
                    raise ValueError("password must be at least 8 characters")
                password_hash = self._hash_password(password)
                traffic_limit = int(payload.get("traffic_limit", 0))
                expire_time = int(payload.get("expire_time", 0))
                created = self.server.store.add_user(username, password_hash, traffic_limit, expire_time)
                self._send_json(HTTPStatus.OK, {**created, "password": ""})
                return
            if path == "/api/settings":
                for key, value in payload.items():
                    self.server.store.set_setting(key, str(value))
                self._send_json(HTTPStatus.OK, {"success": True})
                return
            if path == "/api/thirdparty":
                name = str(payload.get("name", "")).strip()
                url = str(payload.get("url", "")).strip()
                if not url:
                    raise ValueError("url is required")
                content = fetch_subscription_text(url)
                result = parse_subscription(content)
                if not result.nodes:
                    raise ValueError("订阅中没有可识别的节点")
                created = self.server.store.add_thirdparty(name or "第三方订阅", url, result.nodes)
                self._send_json(HTTPStatus.OK, {
                    "success": True,
                    "id": created["id"],
                    "parsedCount": len(result.nodes),
                    "debug": {"protocolCounts": result.protocol_counts, "debug": result.debug},
                })
                return
            if path == "/api/proxy/switch":
                slots = self.server.manager.snapshot()
                slot_id = str(payload.get("slot_id", "")).strip()
                if not slot_id and payload.get("port"):
                    port = int(payload["port"])
                    matches = [slot["id"] for slot in slots if slot["proxy_port"] == port]
                    if len(matches) == 1:
                        slot_id = matches[0]
                if not slot_id:
                    raise ValueError("slot_id is required")
                if not any(slot["id"] == slot_id for slot in slots):
                    raise KeyError(slot_id)
                slot = self.server.manager.redial_slot(slot_id)
                self._send_json(HTTPStatus.ACCEPTED, {"accepted": True, "exit": slot.as_dict()})
                return
            if path == "/api/proxy/config":
                country = str(payload.get("country", payload.get("0", ""))).upper()
                port = int(payload.get("port", 0))
                switch_trigger = payload.get("switch_trigger", 0)
                enabled = payload.get("enabled")
                slots = self.server.manager.snapshot()
                target_slot = None
                if port:
                    for slot in slots:
                        if slot["proxy_port"] == port:
                            target_slot = slot
                            break
                if not target_slot and slots:
                    target_slot = slots[0]
                if not target_slot:
                    raise ValueError("no slot available for proxy config")
                slot_id = target_slot["id"]
                if enabled is not None and bool(enabled) != bool(target_slot["enabled"]):
                    if enabled:
                        self.server.manager.enable_slot(slot_id)
                    else:
                        self.server.manager.disable_slot(slot_id)
                if country and country != target_slot["country"]:
                    current = self.server.store.validate_slot_update(
                        slot_id,
                        country=country,
                        proxy_port=None,
                        enabled=None,
                    )
                    if current.enabled:
                        self.server.manager.stop_slot(slot_id)
                    self.server.store.update_slot(slot_id, country=country)
                    if self.server.store.get_slot(slot_id).enabled:
                        self.server.manager.start_slot(slot_id)
                target_slot = self.server.store.get_slot(slot_id).as_dict()
                if switch_trigger:
                    try:
                        self.server.manager.redial_slot(slot_id)
                    except Exception:
                        pass
                self._send_json(HTTPStatus.OK, {
                    "0": target_slot["country"],
                    "country": target_slot["country"],
                    "port": target_slot["proxy_port"],
                    "switch_trigger": switch_trigger,
                    "proxy": {
                        "enabled": bool(target_slot["enabled"]),
                        "country": target_slot["country"],
                        "port": target_slot["proxy_port"],
                        "user": self.server.username,
                        "pass": self.server.password,
                    },
                    "slot_map": {
                        "0": target_slot["country"],
                        "country": target_slot["country"],
                        "port": target_slot["proxy_port"],
                    },
                })
                return
            if path == "/api/probe/admin/settings":
                settings = payload.get("settings", payload)
                if isinstance(settings, dict):
                    for key, value in settings.items():
                        self.server.store.set_setting(f"probe_{key}", str(value))
                self._send_json(HTTPStatus.OK, {"success": True})
                return
            if path == "/api/probe/admin/pull_github":
                try:
                    data = fetch_github_probe_data()
                except Exception as error:
                    self._send_json(HTTPStatus.BAD_GATEWAY, {"code": "upstream_error", "error": str(error)[:500]})
                    return
                serialized = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
                self.server.store.set_setting("probe_cached_nodes_data", serialized)
                self._send_json(HTTPStatus.OK, {"success": True})
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"code": "not_found", "error": "endpoint not found"})
        except UnsupportedField as error:
            self._send_json(HTTPStatus.BAD_REQUEST, {"code": "unsupported_field", "error": str(error)})
        except RealmUnavailable as error:
            self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"code": "unavailable", "error": str(error)})
        except (ValueError, json.JSONDecodeError) as error:
            self._send_json(HTTPStatus.BAD_REQUEST, {"code": "invalid_request", "error": str(error)})
        except RuntimeError as error:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"code": "operation_failed", "error": str(error)})
        except KeyError:
            self._send_json(HTTPStatus.NOT_FOUND, {"code": "not_found", "error": "resource not found"})

    def do_DELETE(self) -> None:
        path = self.path.split("?", 1)[0]
        try:
            if path == "/api/vps":
                ip = self._query_param("ip") or ""
                if not ip:
                    raise ValueError("ip is required")
                self.server.store.delete_vps(ip)
                self.server.store.record_event(None, "vps", f"vps deleted: {ip}")
                self._send_json(HTTPStatus.OK, {"success": True})
                return
            if path == "/api/nodes":
                node_id = int(self._query_param("id") or "0")
                if not node_id:
                    raise ValueError("id is required")
                self.server.store.delete_node(node_id)
                self._send_json(HTTPStatus.OK, {"success": True})
                return
            if path == "/api/users":
                username = self._query_param("username") or ""
                if not username:
                    raise ValueError("username is required")
                self.server.store.delete_user(username)
                self._send_json(HTTPStatus.OK, {"success": True})
                return
            if path == "/api/thirdparty":
                tp_id = int(self._query_param("id") or "0")
                if not tp_id:
                    raise ValueError("id is required")
                self.server.store.delete_thirdparty(tp_id)
                self._send_json(HTTPStatus.OK, {"success": True})
                return
            if path == "/api/probe/admin/server":
                server_id = self._query_param("id") or ""
                self.server.store.get_slot(server_id)
                self.server.store.delete_setting(f"probe_server_{server_id}")
                self._send_json(HTTPStatus.OK, {"success": True})
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"code": "not_found", "error": "endpoint not found"})
        except ValueError as error:
            self._send_json(HTTPStatus.BAD_REQUEST, {"code": "invalid_request", "error": str(error)})
        except KeyError:
            self._send_json(HTTPStatus.NOT_FOUND, {"code": "not_found", "error": "resource not found"})

    def _serve_asset(self) -> None:
        path = self.path.split("?", 1)[0]
        relative = "index.html" if path in {"/", "/index.html"} else path.lstrip("/")
        candidate = (self.server.web_root / relative).resolve()
        try:
            candidate.relative_to(self.server.web_root)
        except ValueError:
            self._send_json(HTTPStatus.NOT_FOUND, {"code": "not_found", "error": "asset not found"})
            return
        if not candidate.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"code": "not_found", "error": "asset not found"})
            return
        payload = candidate.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mimetypes.guess_type(candidate.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store" if candidate.name == "index.html" else "public, max-age=3600")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)
