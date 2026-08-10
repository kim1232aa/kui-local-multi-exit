from __future__ import annotations

import base64
import csv
import http.client
import io
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any


API_URL = "https://www.vpngate.net/api/iphone/"
STREAM_URLS = (
    "https://www.google.com/",
    "https://chatgpt.com",
    "https://cn.tradingview.com",
    "https://claude.ai",
)


class _EndpointHTTPSConnection(http.client.HTTPSConnection):
    """Connect to an endpoint IP while retaining the origin hostname for TLS."""

    def __init__(self, host: str, *args, server_hostname: str | None = None, **kwargs):
        self._server_hostname = server_hostname or host
        super().__init__(host, *args, **kwargs)

    def connect(self):
        super(http.client.HTTPSConnection, self).connect()
        server_hostname = self._tunnel_host or self._server_hostname
        self.sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname)


class _EndpointHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, server_hostname: str):
        super().__init__()
        self.server_hostname = server_hostname

    def https_open(self, request):
        def connection_class(host, **kwargs):
            kwargs.pop("check_hostname", None)
            return _EndpointHTTPSConnection(host, server_hostname=self.server_hostname, **kwargs)

        return self.do_open(
            connection_class,
            request,
            context=self._context,
            check_hostname=getattr(self, "_check_hostname", None),
        )


def direct_url_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def resolve_ipv4_endpoints(hostname: str) -> list[str]:
    endpoints = []
    for result in socket.getaddrinfo(hostname, 443, socket.AF_INET, socket.SOCK_STREAM):
        ip = result[4][0]
        if ip not in endpoints:
            endpoints.append(ip)
    return endpoints


def open_direct_url(request: urllib.request.Request, timeout: int, server_hostname: str | None = None):
    if server_hostname:
        # Connect to the resolved endpoint IP, but keep TLS SNI and certificate
        # verification bound to the original hostname on Python 3.12+.
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _EndpointHTTPSHandler(server_hostname),
        )
        return opener.open(request, timeout=timeout)
    return direct_url_opener().open(request, timeout=timeout)


def build_endpoint_request(endpoint: str, original_url: str) -> urllib.request.Request:
    parsed = urllib.parse.urlsplit(original_url)
    endpoint_url = urllib.parse.urlunsplit((parsed.scheme, endpoint, parsed.path, parsed.query, parsed.fragment))
    request = urllib.request.Request(endpoint_url, headers={"User-Agent": "KUI-Local-Multi-Exit/1.0", "Host": parsed.netloc})
    return request


def sanitize_openvpn_config(raw: str, expected_ip: str) -> str:
    allowed = {
        "proto",
        "port",
        "cipher",
        "auth",
        "auth-nocache",
        "remote-cert-tls",
        "verify-x509-name",
        "tls-version-min",
        "tls-cipher",
        "compress",
        "comp-lzo",
        "key-direction",
        "reneg-sec",
    }
    blocked = {
        "script-security",
        "up",
        "down",
        "route-up",
        "route-pre-down",
        "plugin",
        "management",
        "config",
        "cd",
        "chroot",
        "daemon",
        "log",
        "log-append",
        "writepid",
        "client-connect",
        "client-disconnect",
        "learn-address",
    }
    blocks = {"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"}
    ipaddress.IPv4Address(expected_ip)
    output = ["client", "dev tun", "nobind", "persist-key", "persist-tun", "remote-random"]
    in_block = None
    for original in raw.splitlines():
        line = original.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if in_block:
            output.append(line)
            if line.lower() == f"</{in_block}>":
                in_block = None
            continue
        if line.startswith("<") and line.endswith(">") and not line.startswith("</"):
            name = line[1:-1].strip().lower()
            if name not in blocks:
                raise ValueError(f"unsafe OpenVPN inline block: {name}")
            in_block = name
            output.append(f"<{name}>")
            continue
        parts = line.split()
        directive = parts[0].lower()
        if directive in blocked:
            raise ValueError(f"unsafe OpenVPN directive: {directive}")
        if directive == "remote":
            port = int(parts[2]) if len(parts) > 2 else 1194
            if not 1 <= port <= 65535:
                raise ValueError("invalid OpenVPN remote port")
            output.append(f"remote {expected_ip} {port}")
        elif directive in allowed:
            output.append(line)
    if in_block:
        raise ValueError(f"unterminated OpenVPN block: {in_block}")
    if not any(line.startswith("remote ") for line in output):
        raise ValueError("OpenVPN profile has no remote")
    return "\n".join(output) + "\n"


def fetch_api_text(url: str = API_URL, timeout: int = 20) -> str:
    proxy = os.environ.get("KUI_FETCH_PROXY", "").strip()
    text = ""
    if proxy:
        if urllib.parse.urlsplit(proxy).scheme not in {"http", "https", "socks5", "socks5h"}:
            raise ValueError("KUI_FETCH_PROXY must use http, https, socks5, or socks5h")
        if proxy.startswith("socks5://"):
            proxy = "socks5h://" + proxy[len("socks5://"):]
        result = subprocess.run(
            [
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--max-time",
                str(timeout),
                "--proxy",
                proxy,
                "--user-agent",
                "KUI-Local-Multi-Exit/1.0",
                url,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise OSError(result.stderr.strip() or f"curl exited with {result.returncode}")
        text = result.stdout
    else:
        parsed = urllib.parse.urlsplit(url)
        endpoints = resolve_ipv4_endpoints(parsed.hostname or "")
        if not endpoints:
            raise OSError(f"no IPv4 endpoint for {parsed.hostname}")
        for endpoint in endpoints:
            try:
                request = build_endpoint_request(endpoint, url)
                # Python 3.12+ 需要显式传递 SNI 以匹配证书
                with open_direct_url(request, timeout=timeout, server_hostname=parsed.hostname) as response:
                    text = response.read().decode("utf-8", errors="replace")
                break
            except (OSError, urllib.error.URLError):
                continue
    return text


def _csv_lines(text: str) -> list[str]:
    lines = [line for line in text.splitlines() if line and not line.startswith("*")]
    if lines and lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    return lines


def fetch_countries(url: str = API_URL, timeout: int = 20) -> list[str]:
    text = fetch_api_text(url, timeout=timeout)
    countries: set[str] = set()
    for line in _csv_lines(text):
        parts = line.split(",")
        if len(parts) > 6:
            country = parts[6].strip().upper()
            if len(country) == 2 and country != "XX" and country != "--":
                countries.add(country)
    return sorted(countries)


def fetch_nodes(url: str = API_URL, timeout: int = 20) -> list[dict[str, Any]]:
    text = fetch_api_text(url, timeout=timeout)
    if not text:
        return []
    reader = csv.DictReader(io.StringIO("\n".join(_csv_lines(text))))
    nodes_by_ip: dict[str, dict[str, Any]] = {}
    for row in reader:
        try:
            ip = str(ipaddress.IPv4Address(row["IP"].strip()))
            config = base64.b64decode(row["OpenVPN_ConfigData_Base64"], validate=True).decode("utf-8", errors="replace")
            candidate = {
                "ip": ip,
                "country": row.get("CountryShort", "").upper(),
                "ping": int(row.get("Ping") or 9999),
                "score": int(row.get("Score") or 0),
                "config": sanitize_openvpn_config(config, ip),
                "harvested_at": time.time(),
                "source": "vpngate",
                "username": "vpn",
                "password": "vpn",
                "provider_id": row.get("HostName", ""),
            }
            previous = nodes_by_ip.get(ip)
            if previous is None or (candidate["ping"], -candidate["score"]) < (previous["ping"], -previous["score"]):
                nodes_by_ip[ip] = candidate
        except (KeyError, ValueError, TypeError):
            continue
    return list(nodes_by_ip.values())


class NodePool:
    def __init__(self):
        self._lock = threading.RLock()
        self._nodes: dict[str, dict[str, Any]] = {}
        self._penalties: dict[str, int] = {}

    def replace(self, nodes: list[dict[str, Any]]) -> None:
        with self._lock:
            merged: dict[str, dict[str, Any]] = {}
            for node in nodes:
                ip = str(node["ip"])
                previous = self._nodes.get(ip)
                if previous:
                    # 保留惩罚性 ping，防止坏节点被新快照刷新后又回到前列
                    node = dict(node)
                    node["ping"] = max(int(node.get("ping", 9999)), int(previous.get("ping", 9999)))
                merged[ip] = node
            self._nodes = merged

    def penalize(self, ip: str, amount: int) -> None:
        with self._lock:
            self._penalties[ip] = self._penalties.get(ip, 0) + amount

    def select(self, country: str, excluded: set[str]) -> dict[str, Any] | None:
        with self._lock:
            candidates = [
                node
                for node in self._nodes.values()
                if (country == "ANY" or node["country"] == country) and node["ip"] not in excluded
            ]
            candidates.sort(key=lambda node: (node["ping"] + self._penalties.get(node["ip"], 0), -node["score"]))
            return dict(candidates[0]) if candidates else None

    def get(self, ip: str, country: str = "ANY") -> dict[str, Any] | None:
        with self._lock:
            node = self._nodes.get(ip)
            if not node or (country != "ANY" and node.get("country") != country):
                return None
            return dict(node)

    def counts(self) -> dict[str, int]:
        with self._lock:
            result: dict[str, int] = {}
            for node in self._nodes.values():
                result[node["country"]] = result.get(node["country"], 0) + 1
            return result

    def list_nodes(self, country: str = "ANY") -> list[dict[str, Any]]:
        with self._lock:
            candidates = [
                node
                for node in self._nodes.values()
                if country == "ANY" or node["country"] == country
            ]
            candidates.sort(key=lambda node: (node["ping"] + self._penalties.get(node["ip"], 0), -node["score"]))
            return [{key: value for key, value in node.items() if key != "config"} for node in candidates]


def detect_egress(interface: str, run: Callable[..., Any] = subprocess.run) -> str:
    for family, url in (("-4", "https://api.ipify.org"), ("-6", "https://api6.ipify.org")):
        result = run(
            ["curl", "-s", "-m", "10", "--interface", interface, family, url],
            capture_output=True,
            text=True,
            check=False,
        )
        candidate = result.stdout.strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            continue
    return ""


def check_residential(ip: str, timeout: int = 10) -> tuple[bool, dict[str, Any]]:
    request = urllib.request.Request(
        f"https://testisp.info/api/check?ip={ip}",
        headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
    )
    try:
        with direct_url_opener().open(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception as error:
        return False, {"status": "unknown", "error": str(error)[:500]}
    isp = data.get("isp", {})
    geo = data.get("geo", {})
    flag = str(isp.get("flag", "")).lower()
    isp_type = str(isp.get("type", "")).lower()
    warning = str(isp.get("warning", "")).lower()
    residential = flag == "residential"
    return residential, {"status": "checked", "raw": data, "is_residential": residential}


DEFAULT_STREAM_URL = "https://www.gstatic.com/generate_204"


def _probe_accepts(url: str, code: str) -> bool:
    if not re.fullmatch(r"[0-9]{3}", code) or code == "000":
        return False
    if url.rstrip("/").endswith("/generate_204"):
        return code == "204"
    status = int(code)
    return 200 <= status < 300 or 400 <= status < 500 and status != 407


def _probe_classification(url: str, code: str, returncode: int) -> str:
    if returncode != 0 or code == "000":
        return "timeout" if returncode == 28 or code == "000" else "transport_error"
    if not re.fullmatch(r"[0-9]{3}", code):
        return "invalid_response"
    status = int(code)
    if 300 <= status < 400:
        return "redirect"
    if status == 407:
        return "proxy_auth_required"
    if status >= 500:
        return "server_error"
    if _probe_accepts(url, code):
        return "explicit_response"
    return "unexpected_status"


def probe_targets(
    interface: str,
    urls: tuple[str, ...] | list[str],
    run: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    custom_targets = tuple(dict.fromkeys(str(url).strip() for url in urls if str(url).strip()))
    targets = (DEFAULT_STREAM_URL, *[url for url in custom_targets if url != DEFAULT_STREAM_URL])
    attempts = []
    for url in targets:
        started = time.monotonic()
        command = [
            "curl", "-o", "/dev/null", "-s", "-w", "%{http_code}",
            "-A", "Mozilla/5.0", "-m", "10", "--location", "--max-redirs", "20",
            "--interface", interface,
            "--doh-url", "https://cloudflare-dns.com/dns-query",
            "--resolve", "cloudflare-dns.com:443:1.1.1.1",
        ]
        result = run([*command, url], capture_output=True, text=True, check=False)
        code = result.stdout.strip()
        accepted = result.returncode == 0 and _probe_accepts(url, code)
        attempts.append(
            {
                "url": url,
                "code": code,
                "accepted": accepted,
                "classification": _probe_classification(url, code, result.returncode),
                "elapsed_ms": max(0, int((time.monotonic() - started) * 1000)),
                "error": (getattr(result, "stderr", "") or "").strip()[:500],
            }
        )
    base_ok = bool(attempts and attempts[0]["accepted"])
    custom_ok = bool(attempts[1:]) and all(attempt["accepted"] for attempt in attempts[1:])
    return {
        "base_ok": base_ok,
        "custom_ok": custom_ok,
        "accepted": base_ok and custom_ok,
        "attempts": attempts,
    }


def check_streaming(
    interface: str,
    run: Callable[..., Any] = subprocess.run,
    urls: tuple[str, ...] | list[str] | None = None,
) -> tuple[bool, dict[str, Any]]:
    targets = (DEFAULT_STREAM_URL,) if urls is None else tuple(urls)
    attempts = []
    for url in targets:
        result = run(
            ["curl", "-o", "/dev/null", "-s", "-w", "%{http_code}", "-A", "Mozilla/5.0", "-m", "10", "--interface", interface, url],
            capture_output=True,
            text=True,
            check=False,
        )
        code = result.stdout.strip()
        attempt = {
            "url": url,
            "code": code,
            "accepted": result.returncode == 0 and _probe_accepts(url, code),
            "classification": _probe_classification(url, code, result.returncode),
        }
        attempts.append(attempt)
        if attempt["accepted"]:
            return True, {"attempts": attempts}
    return False, {"attempts": attempts}
