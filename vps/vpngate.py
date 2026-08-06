from __future__ import annotations

import base64
import csv
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
    "https://www.youtube.com",
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://www.google.com/robots.txt",
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


def open_direct_url(request: urllib.request.Request, timeout: int):
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
                with open_direct_url(request, timeout=timeout) as response:
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
    nodes: list[dict[str, Any]] = []
    for row in reader:
        try:
            ip = str(ipaddress.IPv4Address(row["IP"].strip()))
            config = base64.b64decode(row["OpenVPN_ConfigData_Base64"], validate=True).decode("utf-8", errors="replace")
            nodes.append(
                {
                    "ip": ip,
                    "country": row.get("CountryShort", "").upper(),
                    "ping": int(row.get("Ping") or 9999),
                    "score": int(row.get("Score") or 0),
                    "config": sanitize_openvpn_config(config, ip),
                    "harvested_at": time.time(),
                }
            )
        except (KeyError, ValueError, TypeError):
            continue
    return nodes


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
        attempts.append({"url": url, "code": code})
        if result.returncode == 0 and _probe_accepts(url, code):
            return True, {"attempts": attempts}
    return False, {"attempts": attempts}
