#!/usr/bin/env python3
"""Parse and validate bridge proxy nodes from URLs or subscription feeds.

Bridge nodes are used as the first hop in a client-side chain:

    client -> bridge node -> local Reality inbound -> OpenVPN exit

This module only parses public/self-provided proxy URLs. It does not
contain hard-coded third-party credentials or subscription addresses.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any


MAX_SUBSCRIPTION_BYTES = 2 * 1024 * 1024
MAX_NODES_PER_SOURCE = 64
FETCH_TIMEOUT = 20
CONNECT_TIMEOUT = 5
CHECK_TIMEOUT = 12
CHECK_WORKERS = 8
CHECK_TARGETS = [
    "https://chatgpt.com",
    "https://claude.com",
    "https://google.com",
    "https://tradingview.com",
]

# Module-level cache shared between the API handler and the background refresher.
_bridge_cache: dict[str, tuple[list[dict[str, Any]], float]] = {}
_bridge_lock = threading.Lock()


def _cache_key(manual_urls: list[str], subscription_urls: list[str], test_reachability: bool) -> str:
    parts = sorted(manual_urls) + ["|"] + sorted(subscription_urls) + ["|", str(test_reachability)]
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


def _get_cache(key: str, max_age: float) -> list[dict[str, Any]] | None:
    with _bridge_lock:
        entry = _bridge_cache.get(key)
        if entry and time.time() - entry[1] < max_age:
            return entry[0]
    return None


def _set_cache(key: str, nodes: list[dict[str, Any]]) -> None:
    with _bridge_lock:
        _bridge_cache[key] = (nodes, time.time())


def _first(values: list[str] | None) -> str:
    return (values or [""])[0]


def parse_vless_url(url: str) -> dict[str, Any] | None:
    """Parse a vless:// sharing URL into a Mihomo-compatible proxy dict."""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None
    if parsed.scheme.lower() != "vless":
        return None
    if not parsed.hostname or not parsed.port or not parsed.username:
        return None
    qs = urllib.parse.parse_qs(parsed.query)
    network = _first(qs.get("type")) or "tcp"
    security = _first(qs.get("security")) or "none"
    node: dict[str, Any] = {
        "protocol": "VLESS",
        "name": _clean_name(urllib.parse.unquote(parsed.fragment) or f"vless-{parsed.hostname}"),
        "type": "vless",
        "server": parsed.hostname,
        "address": parsed.hostname,
        "port": parsed.port,
        "uuid": parsed.username,
        "network": network,
        "tls": security in {"tls", "xtls"},
        "udp": True,
    }
    sni = _first(qs.get("sni"))
    if sni:
        node["servername"] = sni
    fp = _first(qs.get("fp"))
    if fp:
        node["client-fingerprint"] = fp
    if security == "reality":
        node["tls"] = True
        pbk = _first(qs.get("pbk"))
        sid = _first(qs.get("sid"))
        if pbk:
            node["reality-opts"] = {"public-key": pbk}
            if sid:
                node["reality-opts"]["short-id"] = sid
    flow = _first(qs.get("flow"))
    if flow:
        node["flow"] = flow
    if network == "ws":
        path = urllib.parse.unquote(_first(qs.get("path")) or "/")
        host = _first(qs.get("host"))
        node["ws-opts"] = {"path": path}
        if host:
            node["ws-opts"]["headers"] = {"Host": host}
    elif network == "grpc":
        node["grpc-opts"] = {"grpc-service-name": urllib.parse.unquote(_first(qs.get("serviceName")) or "")}
    return node


def parse_hysteria2_url(url: str) -> dict[str, Any] | None:
    """Parse a hysteria2:// or hy2:// URL into a Mihomo-compatible proxy dict."""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None
    if parsed.scheme.lower() not in {"hysteria2", "hy2"}:
        return None
    if not parsed.hostname or not parsed.port:
        return None
    qs = urllib.parse.parse_qs(parsed.query)
    node: dict[str, Any] = {
        "protocol": "HYSTERIA2",
        "name": _clean_name(urllib.parse.unquote(parsed.fragment) or f"hysteria2-{parsed.hostname}"),
        "type": "hysteria2",
        "server": parsed.hostname,
        "address": parsed.hostname,
        "port": parsed.port,
        "password": parsed.username or "",
        "udp": True,
    }
    sni = _first(qs.get("sni"))
    if sni:
        node["sni"] = sni
    if _first(qs.get("insecure")) == "1":
        node["skip-cert-verify"] = True
    return node


def parse_vmess_url(url: str) -> dict[str, Any] | None:
    """Parse a vmess:// sharing URL."""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None
    if parsed.scheme.lower() != "vmess":
        return None
    try:
        raw = base64.b64decode(parsed.netloc + "==").decode("utf-8", errors="ignore")
        data = json.loads(raw)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    add = data.get("add") or data.get("host", "")
    port = int(data.get("port", 0))
    if not add or not port:
        return None
    node: dict[str, Any] = {
        "protocol": "VMESS",
        "name": _clean_name(data.get("ps") or f"vmess-{add}"),
        "type": "vmess",
        "server": add,
        "address": add,
        "port": port,
        "uuid": data.get("id", ""),
        "alterId": int(data.get("aid", 0)),
        "cipher": data.get("scy") or "auto",
        "network": data.get("net") or "tcp",
        "tls": (data.get("tls") or "").lower() == "tls",
        "udp": True,
    }
    if node["tls"]:
        node["servername"] = data.get("sni") or data.get("host", "")
    if node["network"] == "ws":
        node["ws-opts"] = {"path": data.get("path", "/")}
        if data.get("host"):
            node["ws-opts"]["headers"] = {"Host": data["host"]}
    return node


def parse_trojan_url(url: str) -> dict[str, Any] | None:
    """Parse a trojan:// sharing URL."""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None
    if parsed.scheme.lower() != "trojan":
        return None
    if not parsed.hostname or not parsed.port or not parsed.username:
        return None
    qs = urllib.parse.parse_qs(parsed.query)
    node: dict[str, Any] = {
        "protocol": "TROJAN",
        "name": _clean_name(urllib.parse.unquote(parsed.fragment) or f"trojan-{parsed.hostname}"),
        "type": "trojan",
        "server": parsed.hostname,
        "address": parsed.hostname,
        "port": parsed.port,
        "password": parsed.username,
        "udp": True,
    }
    sni = _first(qs.get("sni"))
    if sni:
        node["sni"] = sni
    if _first(qs.get("allowInsecure")) == "1" or _first(qs.get("insecure")) == "1":
        node["skip-cert-verify"] = True
    return node


def parse_ss_url(url: str) -> dict[str, Any] | None:
    """Parse ss:// URL (SIP002/base64)."""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None
    if parsed.scheme.lower() != "ss":
        return None
    try:
        # Try SIP002: userinfo is base64(method:password)
        userinfo = base64.b64decode(parsed.username or "").decode("utf-8")
        method, password = userinfo.split(":", 1)
    except Exception:
        return None
    if not parsed.hostname or not parsed.port:
        return None
    return {
        "protocol": "SS",
        "name": _clean_name(urllib.parse.unquote(parsed.fragment) or f"ss-{parsed.hostname}"),
        "type": "ss",
        "server": parsed.hostname,
        "address": parsed.hostname,
        "port": parsed.port,
        "cipher": method,
        "password": password,
        "udp": True,
    }


_PROTOCOL_PARSERS = [
    parse_vless_url,
    parse_hysteria2_url,
    parse_vmess_url,
    parse_trojan_url,
    parse_ss_url,
]


def parse_proxy_url(url: str) -> dict[str, Any] | None:
    """Try to parse a single proxy sharing URL."""
    url = url.strip()
    if not url or not re.match(r"^[a-zA-Z0-9]+://", url):
        return None
    for parser in _PROTOCOL_PARSERS:
        try:
            node = parser(url)
            if node:
                return node
        except Exception:
            continue
    return None


def _clean_name(name: str) -> str:
    """Sanitize a proxy name for Mihomo/Clash."""
    name = re.sub(r"[\r\n\t]", " ", name).strip()
    name = re.sub(r"[^\w\s\-|./:()\[\]@]", "", name)
    return name[:64] or "bridge"


def _decode_subscription(text: str) -> str:
    """Try base64 decode; if fails, return raw text."""
    try:
        decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
        if "://" in decoded:
            return decoded
    except Exception:
        pass
    return text


def _parse_monosans_json(text: str) -> list[dict[str, Any]] | None:
    """Parse monosans/proxy-list proxies.json (hourly-verified, geo metadata).

    Returns None when the text is not that format. socks4 entries are skipped
    (mihomo has no socks4 outbound) and transparent proxies are dropped
    (exit_ip != host means the real client IP is forwarded).
    """
    stripped = text.lstrip()
    if not stripped.startswith("["):
        return None
    try:
        data = json.loads(stripped)
    except ValueError:
        return None
    if not isinstance(data, list) or not data or not isinstance(data[0], dict):
        return None
    if "protocol" not in data[0] or "host" not in data[0]:
        return None
    nodes: list[dict[str, Any]] = []
    for item in data:
        proto = str(item.get("protocol", "")).lower()
        if proto not in {"http", "socks5"}:
            continue
        host = str(item.get("host", ""))
        try:
            port = int(item.get("port", 0))
        except (TypeError, ValueError):
            continue
        if not host or not 1 <= port <= 65535:
            continue
        if item.get("exit_ip") and str(item["exit_ip"]) != host:
            continue
        iso = str(((item.get("geolocation") or {}).get("country") or {}).get("iso_code", ""))
        node: dict[str, Any] = {
            "protocol": proto.upper(),
            "type": proto,
            "name": _clean_name(f"{iso or 'ZZ'}-{proto}-{host}:{port}"),
            "server": host,
            "address": host,
            "port": port,
            "_country_hint": iso,
        }
        if item.get("username"):
            node["username"] = str(item["username"])
            node["password"] = str(item.get("password") or "")
        nodes.append(node)
    return nodes


def parse_subscription(text: str) -> list[dict[str, Any]]:
    """Parse a subscription text (base64 or plain) into node dicts."""
    text = _decode_subscription(text)
    monosans = _parse_monosans_json(text)
    if monosans is not None:
        return monosans[:150]
    nodes: list[dict[str, Any]] = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        node = parse_proxy_url(line)
        if not node:
            continue
        key = f"{node['type']}://{node.get('server')}:{node.get('port')}:{node.get('uuid', node.get('password', ''))}"
        if key in seen:
            continue
        seen.add(key)
        nodes.append(node)
        if len(nodes) >= MAX_NODES_PER_SOURCE:
            break
    return nodes


def _curl_proxy_arg(url: str) -> str | None:
    """Convert a proxy URL into a curl --proxy argument.

    curl supports http://, https://, socks5:// and socks5h://.
    Hysteria2 and other UDP-only protocols cannot be tested with curl.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return None
    scheme = parsed.scheme.lower()
    if scheme in {"http", "https", "socks5", "socks5h"}:
        return url
    return None


def check_proxy_url(
    url: str,
    targets: list[str] | None = None,
    timeout: int = CHECK_TIMEOUT,
) -> list[str]:
    """Test a proxy URL by running curl through it to the target sites.

    Returns the list of target URLs that returned HTTP 2xx/3xx.
    Hysteria2 and unsupported protocols return an empty list (skip).
    """
    proxy_arg = _curl_proxy_arg(url)
    if proxy_arg is None:
        return []
    ok: list[str] = []
    for target in (targets or CHECK_TARGETS):
        try:
            result = subprocess.run(
                [
                    "curl", "-fsS", "-L", "--max-time", str(timeout),
                    "--proxy", proxy_arg, "-o", "/dev/null",
                    "-w", "%{http_code}", target,
                ],
                capture_output=True,
                text=True,
                timeout=timeout + 2,
            )
            code = result.stdout.strip()
            if code.startswith(("2", "3")):
                ok.append(target)
        except Exception:
            pass
    return ok


def _sing_box_bin() -> str | None:
    """Return the path to the sing-box binary, or None if not found."""
    for candidate in (
        os.environ.get("KUI_SING_BOX_BIN", ""),
        "/usr/local/bin/kui-sing-box",
        "/usr/bin/sing-box",
        "/usr/local/bin/sing-box",
        "sing-box",
    ):
        if not candidate:
            continue
        if candidate == "sing-box" or os.path.isfile(candidate):
            return candidate
    return None


def _pick_free_port(host: str = "127.0.0.1", low: int = 30000, high: int = 50000) -> int:
    """Pick a random free TCP port in the given range."""
    for _ in range(20):
        port = random.randint(low, high)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind((host, port))
            return port
        except OSError:
            continue
    raise RuntimeError("unable to find a free port")


def _sing_box_outbound(node: dict[str, Any]) -> dict[str, Any] | None:
    """Convert a parsed bridge node into a sing-box outbound dict."""
    protocol = str(node.get("type", "")).lower()
    server = str(node.get("server", ""))
    port = int(node.get("port", 0))
    if not server or not port:
        return None

    if protocol == "vless":
        out: dict[str, Any] = {
            "type": "vless",
            "tag": "bridge",
            "server": server,
            "server_port": port,
            "uuid": str(node.get("uuid", "")),
        }
        flow = str(node.get("flow", ""))
        if flow:
            out["flow"] = flow
        if node.get("tls"):
            tls: dict[str, Any] = {"enabled": True, "server_name": str(node.get("servername") or node.get("sni", ""))}
            fp = str(node.get("client-fingerprint", ""))
            if fp:
                tls["utls"] = {"enabled": True, "fingerprint": fp}
            out["tls"] = tls
        network = str(node.get("network") or "tcp")
        if network == "ws":
            ws_opts = node.get("ws-opts") if isinstance(node.get("ws-opts"), dict) else {}
            headers = ws_opts.get("headers") if isinstance(ws_opts.get("headers"), dict) else {}
            out["transport"] = {
                "type": "ws",
                "path": str(ws_opts.get("path") or "/"),
                "headers": headers,
            }
        return out

    if protocol == "hysteria2":
        return {
            "type": "hysteria2",
            "tag": "bridge",
            "server": server,
            "server_port": port,
            "password": str(node.get("password", "")),
            "tls": {
                "enabled": True,
                "server_name": str(node.get("sni", "")),
                "insecure": bool(node.get("skip-cert-verify")),
            },
        }

    if protocol == "trojan":
        return {
            "type": "trojan",
            "tag": "bridge",
            "server": server,
            "server_port": port,
            "password": str(node.get("password", "")),
            "tls": {
                "enabled": True,
                "server_name": str(node.get("sni", "")),
                "insecure": bool(node.get("skip-cert-verify")),
            },
        }

    if protocol == "ss":
        return {
            "type": "shadowsocks",
            "tag": "bridge",
            "server": server,
            "server_port": port,
            "method": str(node.get("cipher", "aes-256-gcm")),
            "password": str(node.get("password", "")),
        }

    return None


def check_node_with_singbox(
    node: dict[str, Any],
    targets: list[str] | None = None,
    timeout: int = CHECK_TIMEOUT,
) -> list[str]:
    """Test a parsed proxy node by running a local sing-box client through it.

    Spawns a temporary sing-box process that listens on a local SOCKS5 port
    and uses the node as its outbound, then runs curl through that SOCKS5.
    """
    outbound = _sing_box_outbound(node)
    if outbound is None:
        return []
    listen_port = _pick_free_port()
    config = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "socks",
                "tag": "test",
                "listen": "127.0.0.1",
                "listen_port": listen_port,
            }
        ],
        "outbounds": [outbound],
        "route": {"final": "bridge"},
    }

    sing_box = _sing_box_bin()
    if sing_box is None:
        return []

    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        proc = subprocess.Popen(
            [sing_box, "run", "-c", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=tmpdir,
        )
        try:
            # Wait for the SOCKS5 inbound to be ready.
            deadline = time.time() + 5
            ready = False
            while time.time() < deadline:
                try:
                    with socket.create_connection(("127.0.0.1", listen_port), timeout=0.5):
                        ready = True
                        break
                except OSError:
                    if proc.poll() is not None:
                        break
                    time.sleep(0.1)
            if not ready:
                return []

            ok: list[str] = []
            curl_timeout = min(timeout, 4)
            failed_count = 0
            for target in (targets or CHECK_TARGETS):
                try:
                    result = subprocess.run(
                        [
                            "curl", "-fsS", "-L", "--max-time", str(curl_timeout),
                            "--socks5-hostname", f"127.0.0.1:{listen_port}",
                            "-o", "/dev/null", "-w", "%{http_code}", target,
                        ],
                        capture_output=True,
                        text=True,
                        timeout=curl_timeout + 1,
                    )
                    code = result.stdout.strip()
                    if code.startswith(("2", "3")):
                        ok.append(target)
                    else:
                        failed_count += 1
                except Exception:
                    failed_count += 1
                if failed_count >= 2 and not ok:
                    break
            return ok
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()


def fetch_subscription(url: str, timeout: int = FETCH_TIMEOUT) -> str:
    """Fetch a subscription URL and return decoded text."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/plain,application/json,*/*",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(MAX_SUBSCRIPTION_BYTES + 1)
        if len(data) > MAX_SUBSCRIPTION_BYTES:
            raise ValueError(f"subscription exceeds {MAX_SUBSCRIPTION_BYTES} bytes")
        return data.decode("utf-8", errors="ignore")


def _measure_speed_through_proxy(proxy_url: str, timeout: int = 15) -> float:
    """Measure download speed (KB/s) through an HTTP/SOCKS5 proxy URL."""
    url = "https://speed.cloudflare.com/__down?bytes=200000"
    try:
        result = subprocess.run(
            [
                "curl", "-fsS", "-L", "--max-time", str(timeout),
                "--proxy", proxy_url, "-o", "/dev/null",
                "-w", "%{size_download} %{time_total}", url,
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 2,
        )
        if result.returncode != 0:
            return 0.0
        parts = result.stdout.strip().split()
        if len(parts) != 2:
            return 0.0
        size = int(parts[0])
        elapsed = float(parts[1])
        if elapsed <= 0:
            return 0.0
        return round(size / 1024 / elapsed, 2)
    except Exception:
        return 0.0


def _measure_speed_with_singbox(node: dict[str, Any], timeout: int = 15) -> float:
    """Measure download speed (KB/s) by running a sing-box client for the node."""
    outbound = _sing_box_outbound(node)
    if outbound is None:
        return 0.0
    listen_port = _pick_free_port()
    config = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "socks",
                "tag": "test",
                "listen": "127.0.0.1",
                "listen_port": listen_port,
            }
        ],
        "outbounds": [outbound],
        "route": {"final": "bridge"},
    }
    url = "https://speed.cloudflare.com/__down?bytes=200000"
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        proc = subprocess.Popen(
            [_sing_box_bin() or "sing-box", "run", "-c", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=tmpdir,
        )
        try:
            deadline = time.time() + 5
            ready = False
            while time.time() < deadline:
                try:
                    with socket.create_connection(("127.0.0.1", listen_port), timeout=0.5):
                        ready = True
                        break
                except OSError:
                    if proc.poll() is not None:
                        break
                    time.sleep(0.1)
            if not ready:
                return 0.0
            try:
                result = subprocess.run(
                    [
                        "curl", "-fsS", "-L", "--max-time", str(timeout),
                        "--socks5-hostname", f"127.0.0.1:{listen_port}",
                        "-o", "/dev/null", "-w", "%{size_download} %{time_total}", url,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=timeout + 2,
                )
                if result.returncode != 0:
                    return 0.0
                parts = result.stdout.strip().split()
                if len(parts) != 2:
                    return 0.0
                size = int(parts[0])
                elapsed = float(parts[1])
                if elapsed <= 0:
                    return 0.0
                return round(size / 1024 / elapsed, 2)
            except Exception:
                return 0.0
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()


def measure_node_speed(node: dict[str, Any], timeout: int = 15) -> float:
    """Measure a node's download speed in KB/s."""
    proxy_url = _node_to_proxy_url(node)
    if proxy_url:
        return _measure_speed_through_proxy(proxy_url, timeout)
    return _measure_speed_with_singbox(node, timeout)


def load_bridge_nodes(
    manual_urls: list[str] | None = None,
    subscription_urls: list[str] | None = None,
    test_reachability: bool = True,
    max_workers: int = CHECK_WORKERS,
    force_refresh: bool = False,
    enable_speed_test: bool = False,
    max_age: float = 300,
    top_n: int = 16,
) -> list[dict[str, Any]]:
    """Load, de-duplicate and optionally test bridge nodes.

    Args:
        manual_urls: List of individual proxy sharing URLs (trusted, not tested).
        subscription_urls: List of subscription URLs to fetch and parse.
        test_reachability: If True, drop subscription nodes that fail the test.
        max_workers: Concurrency limit for tests to keep memory/CPU low.
        force_refresh: If True, ignore the cache and fetch/test again.
        enable_speed_test: If True, measure download speed for subscription nodes.
        max_age: Cache validity in seconds.
        top_n: When speed test is enabled, keep at most this many fastest nodes.
    """
    key = _cache_key(manual_urls or [], subscription_urls or [], test_reachability)
    if not force_refresh:
        cached = _get_cache(key, max_age)
        if cached is not None:
            return cached

    nodes: list[dict[str, Any]] = []
    seen: set[str] = set()

    # Manual URLs are trusted and added directly.
    for url in (manual_urls or []):
        node = parse_proxy_url(url)
        if node and node["name"] not in seen:
            seen.add(node["name"])
            node["_source_kind"] = "manual"
            nodes.append(node)

    # Subscription URLs are fetched, parsed and tested.
    candidate_urls: list[str] = []
    for sub_url in (subscription_urls or []):
        try:
            text = fetch_subscription(sub_url)
            country_match = re.search(r"(?:by-country|country)[^A-Za-z0-9]+(?:v2ray-base64-)?([A-Z]{2})(?:\.txt|/|$)", sub_url)
            source_country = country_match.group(1) if country_match else ""
            for node in parse_subscription(text):
                if node["name"] not in seen:
                    seen.add(node["name"])
                    node["_source_kind"] = "subscription"
                    name_match = re.match(r"^\s*([A-Z]{2})[-_ ]", str(node.get("name", "")))
                    node["_country_hint"] = (
                        node.get("_country_hint")
                        or source_country
                        or (name_match.group(1) if name_match else "")
                    )
                    candidate_urls.append(node)
        except Exception:
            continue

    if test_reachability and candidate_urls:
        tested: list[dict[str, Any]] = []
        lock = threading.Lock()
        priority_countries = {"TR", "VN", "TH", "PH"}
        ordered = sorted(
            candidate_urls,
            key=lambda n: 0 if n.get("_country_hint") in priority_countries else 1,
        )
        test_candidates = ordered[:150]
        max_workers = 24

        def _test_one(node: dict[str, Any]) -> dict[str, Any] | None:
            proxy_url = _node_to_proxy_url(node)
            if proxy_url:
                ok = check_proxy_url(proxy_url)
            else:
                ok = check_node_with_singbox(node)
            if len(ok) >= 1:
                if enable_speed_test:
                    speed = measure_node_speed(node)
                    node["bridge_speed_kbps"] = speed
                with lock:
                    node["bridge_ok_sites"] = ok
                return node
            return None

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_test_one, n) for n in candidate_urls]
            for future in as_completed(futures):
                node = future.result()
                if node is not None:
                    tested.append(node)
        if enable_speed_test:
            tested.sort(key=lambda n: float(n.get("bridge_speed_kbps", 0) or 0), reverse=True)
            tested = tested[:top_n]
        nodes.extend(tested)
    else:
        nodes.extend(candidate_urls)

    _set_cache(key, nodes)
    return nodes


def _node_to_proxy_url(node: dict[str, Any]) -> str | None:
    """Render a parsed node back to a curl-compatible proxy URL."""
    protocol = str(node.get("type", "")).lower()
    server = str(node.get("server", ""))
    port = int(node.get("port", 0))
    if not server or not port:
        return None
    if protocol == "http":
        return f"http://{server}:{port}"
    if protocol == "socks5":
        return f"socks5://{server}:{port}"
    # curl does not support vless/vmess/trojan/hysteria2 directly.
    return None


def mihomo_yaml_lines(node: dict[str, Any]) -> list[str]:
    """Render a parsed node dict as Mihomo YAML proxy lines."""
    lines = [f"  - name: {json.dumps(node['name'])}", f"    type: {node['type']}"]
    for key, value in node.items():
        if key in {"protocol", "name", "type"}:
            continue
        if isinstance(value, dict):
            lines.append(f"    {key}:")
            for sub_key, sub_value in value.items():
                if isinstance(sub_value, dict):
                    lines.append(f"      {sub_key}:")
                    for k2, v2 in sub_value.items():
                        lines.append(f"        {k2}: {json.dumps(v2, ensure_ascii=False)}")
                else:
                    lines.append(f"      {sub_key}: {json.dumps(sub_value, ensure_ascii=False)}")
        elif isinstance(value, bool):
            lines.append(f"    {key}: {'true' if value else 'false'}")
        elif isinstance(value, (int, float)):
            lines.append(f"    {key}: {value}")
        else:
            lines.append(f"    {key}: {json.dumps(value, ensure_ascii=False)}")
    return lines


def start_background_refresh(
    interval: int,
    manual_urls: list[str] | None = None,
    subscription_urls: list[str] | None = None,
    enable_speed_test: bool = False,
    top_n: int = 16,
    max_workers: int = CHECK_WORKERS,
) -> threading.Thread:
    """Start a daemon thread that periodically refreshes the bridge-node cache.

    Args:
        interval: Seconds between refreshes.
        manual_urls: Manual bridge URLs (trusted).
        subscription_urls: Subscription URLs to fetch and test.
        enable_speed_test: Whether to measure download speed.
        top_n: Maximum number of subscription nodes to keep when speed test is on.
        max_workers: Concurrency for testing.

    Returns:
        The started daemon thread.
    """

    def _loop() -> None:
        # Run an immediate refresh on startup to populate the cache.
        try:
            load_bridge_nodes(
                manual_urls=manual_urls,
                subscription_urls=subscription_urls,
                test_reachability=True,
                max_workers=max_workers,
                force_refresh=True,
                enable_speed_test=enable_speed_test,
                top_n=top_n,
            )
        except Exception:
            pass
        while True:
            time.sleep(interval)
            try:
                load_bridge_nodes(
                    manual_urls=manual_urls,
                    subscription_urls=subscription_urls,
                    test_reachability=True,
                    max_workers=max_workers,
                    force_refresh=True,
                    enable_speed_test=enable_speed_test,
                    top_n=top_n,
                )
            except Exception:
                pass

    thread = threading.Thread(target=_loop, daemon=True, name="bridge-refresh")
    thread.start()
    return thread
