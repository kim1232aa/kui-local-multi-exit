#!/usr/bin/env python3
"""CloudShell-compatible VLESS/WS origin and dynamic Clash subscription.

Runs inside Docker only. It joins the existing kui-local-multi-exit compose
network and exposes:

  * VLESS+WS ``/vless``      -> VPS direct egress
  * VLESS+WS ``/res-01..24`` -> kui per-slot residential SOCKS exits
  * HTTP  ``/<secret>``      -> dynamic Clash YAML in the legacy CloudShell format

Secrets (tunnel credentials, uuid, subscription path, front-node fragment)
are read from the external Docker volume ``kui-cloudshell-secrets``; nothing
is installed on the host.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

SECRETS_DIR = Path(os.environ.get("KUI_CLOUDSHELL_SECRETS", "/run/secrets"))
DATA_DIR = Path(os.environ.get("KUI_CLOUDSHELL_DATA", "/kui-data"))
RUNTIME_DIR = Path(os.environ.get("KUI_CLOUDSHELL_RUNTIME", "/run/origin"))
KUI_API = os.environ.get("KUI_CLOUDSHELL_API", "http://kui-local-multi-exit:8080/api/local/exits")
KUI_SOCKS_HOST = os.environ.get("KUI_CLOUDSHELL_SOCKS_HOST", "kui-local-multi-exit")
BASE_PORT = 38080
SUB_PORT = 38081
FIRST_RES_PORT = 38090
FIRST_SOCKS_PORT = 7920
CACHE_TTL = 20

ISP_SHORT = {
    "sony network communications": "SonyNURO",
    "so-net": "So-net",
    "kddi": "KDDI",
    "arteria networks": "ARTERIA",
    "korea telecom": "KT",
    "triple t": "TripleT",
    "ntt": "NTT",
    "asahi net": "ASAHI",
    "softbank": "SoftBank",
    "biglobe": "BIGLOBE",
    "ocn": "OCN",
    "plala": "Plala",
    "rakuten": "Rakuten",
    "k-opti": "K-Opti",
    "j:com": "JCOM",
    "nifty": "Nifty",
    "sonic telecom": "Sonic",
    "centurylink": "CenturyLink",
    "telus": "TELUS",
    "videotron": "Videotron",
    "virgin media": "Virgin",
    "proxad": "Proxad",
    "orange": "Orange",
    "ncnet": "NCNET",
    "ais-fibre": "AIS",
    "fpt telecom": "FPT",
}


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def load_runtime_inputs() -> dict[str, Any]:
    creds = json.loads((SECRETS_DIR / "cf-tunnel-creds.json").read_text(encoding="utf-8"))
    tunnel_id = str(creds.get("TunnelID") or creds.get("tunnel_id") or "")
    if not tunnel_id:
        raise RuntimeError("cf-tunnel-creds.json has no TunnelID")
    internal = json.loads((DATA_DIR / "internal_proxy.json").read_text(encoding="utf-8"))
    username = str(internal.get("username") or "")
    password = str(internal.get("password") or "")
    if not username or not password:
        raise RuntimeError("internal_proxy.json has no credentials")
    return {
        "tunnel_id": tunnel_id,
        "credentials_file": str(SECRETS_DIR / "cf-tunnel-creds.json"),
        "uuid": _read_text(SECRETS_DIR / "uuid"),
        "hostname": _read_text(SECRETS_DIR / "cf-hostname"),
        "sub_path": _read_text(SECRETS_DIR / "sub-path"),
        "front_yaml": (SECRETS_DIR / "sub-front.yaml").read_text(encoding="utf-8").rstrip(),
        "socks_user": username,
        "socks_pass": password,
    }


def res_domains() -> list[tuple[str, str]]:
    # Every active line is used: first entry = primary (joins url-test groups),
    # the rest = manual fallback variants (e.g. the tunnel hostname as 保底).
    path = SECRETS_DIR / "res-domains.txt"
    entries: list[tuple[str, str]] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if parts and not line.lstrip().startswith("#"):
                entries.append((parts[0], parts[1] if len(parts) > 1 else ""))
    if not entries:
        raise RuntimeError("res-domains.txt has no active entry")
    return entries


def slot_count(environ: dict[str, str] | None = None) -> int:
    env = os.environ if environ is None else environ
    raw = str(env.get("KUI_SLOT_COUNT") or "24").strip().lower()
    if raw == "auto" or not raw.isdigit():
        return 24
    return max(1, min(24, int(raw)))


def write_runtime_configs(slot_count_value: int, inputs: dict[str, Any]) -> None:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    uuid_value = inputs["uuid"]

    def vless_inbound(tag: str, port: int, path: str) -> dict[str, Any]:
        return {
            "tag": tag,
            "listen": "0.0.0.0",
            "port": port,
            "protocol": "vless",
            "settings": {"clients": [{"id": uuid_value}], "decryption": "none"},
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {"path": path},
            },
        }

    inbounds = [vless_inbound("vless-base", BASE_PORT, "/vless")]
    outbounds: list[dict[str, Any]] = [{"tag": "direct", "protocol": "freedom"}]
    rules = [{"inboundTag": ["vless-base"], "outboundTag": "direct"}]
    for index in range(1, slot_count_value + 1):
        tag = f"res-{index:02d}"
        inbounds.append(vless_inbound(tag, FIRST_RES_PORT + index - 1, f"/res-{index:02d}"))
        outbound_tag = f"socks-{tag}"
        outbounds.append({
            "tag": outbound_tag,
            "protocol": "socks",
            "settings": {
                "servers": [{
                    "address": KUI_SOCKS_HOST,
                    "port": FIRST_SOCKS_PORT + index - 1,
                    "users": [{"user": inputs["socks_user"], "pass": inputs["socks_pass"]}],
                }]
            },
        })
        rules.append({"inboundTag": [tag], "outboundTag": outbound_tag})

    xray_config = {
        "log": {"loglevel": os.environ.get("KUI_CLOUDSHELL_LOG", "warning")},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"rules": rules},
    }
    (RUNTIME_DIR / "xray.json").write_text(
        json.dumps(xray_config, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    origin_host = "kui-cloudshell-origin"
    ingress: list[dict[str, Any]] = [
        {"path": r"^/vless$", "service": f"http://{origin_host}:{BASE_PORT}"}
    ]
    for index in range(1, slot_count_value + 1):
        ingress.append({
            "path": rf"^/res-{index:02d}$",
            "service": f"http://{origin_host}:{FIRST_RES_PORT + index - 1}",
        })
    ingress.append({"path": f"^{inputs['sub_path']}$", "service": f"http://{origin_host}:{SUB_PORT}"})
    ingress.append({"service": "http_status:404"})
    cloudflared = {
        "tunnel": inputs["tunnel_id"],
        "credentials-file": inputs["credentials_file"],
        "protocol": "http2",
        "ingress": ingress,
    }
    (RUNTIME_DIR / "cloudflared.yml").write_text(
        json.dumps(cloudflared, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    _shared_readonly((RUNTIME_DIR / "xray.json"))
    _shared_readonly((RUNTIME_DIR / "cloudflared.yml"))


def _shared_readonly(path: Path) -> None:
    # cloudflared runs as a non-root user (65532) and must read the config
    # from the shared volume; the volume itself is only mounted read-only.
    try:
        path.chmod(0o644)
    except OSError:
        pass


def fetch_exits(timeout: float = 4.0) -> list[dict[str, Any]] | None:
    with urllib.request.urlopen(KUI_API, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    exits = payload.get("exits", []) if isinstance(payload, dict) else []
    return [slot for slot in exits if isinstance(slot, dict)]


def isp_short(raw: Any) -> str:
    if isinstance(raw, dict):
        raw = raw.get("org") or raw.get("asname") or raw.get("as") or ""
    low = str(raw or "").lower()
    for key, short in ISP_SHORT.items():
        if key in low:
            return short
    for token in str(raw or "").replace(",", " ").split():
        if token.lower() not in {"inc", "inc.", "corporation", "corp", "co", "co.", "ltd", "ltd.", "llc", "the"}:
            return token[:12]
    return "RESI"


def _slot_kind(slot: dict[str, Any]) -> tuple[str, bool]:
    egress_type = str(slot.get("egress_type") or "").lower()
    if egress_type == "residential":
        return "住宅", True
    if egress_type == "datacenter":
        return "机房", False
    return "未知", False


def _vless_node(name: str, domain: str, path: str, uuid_value: str, host: str) -> str:
    return "\n".join((
        f"  - name: {json.dumps(name, ensure_ascii=False)}",
        "    type: vless",
        f"    server: {domain}",
        "    port: 443",
        f"    uuid: {json.dumps(uuid_value)}",
        "    network: ws",
        "    tls: true",
        f"    servername: {json.dumps(host, ensure_ascii=False)}",
        '    client-fingerprint: "chrome"',
        "    udp: false",
        "    ws-opts:",
        f"      path: {json.dumps(path)}",
        "      headers:",
        f"        Host: {json.dumps(host, ensure_ascii=False)}",
    ))


def _slot_label(slot: dict[str, Any]) -> str:
    country = str(slot.get("detected_country") or slot.get("country") or "??").upper()
    kind, _ = _slot_kind(slot)
    check = slot.get("check_result") if isinstance(slot.get("check_result"), dict) else {}
    residential = check.get("residential") if isinstance(check.get("residential"), dict) else {}
    raw = residential.get("raw") if isinstance(residential.get("raw"), dict) else {}
    isp = raw.get("isp") if isinstance(raw.get("isp"), dict) else {}
    return f"{country}{kind}·{isp_short(isp)}·{slot.get('id', 'exit-??')}"


def build_subscription_yaml(
    exits: list[dict[str, Any]] | None,
    inputs: dict[str, Any],
    domains: list[tuple[str, str]],
) -> str:
    front = inputs["front_yaml"]
    front_names = [
        line.split('"', 2)[1]
        for line in front.splitlines()
        if line.strip().startswith("- name:") and '"' in line
    ]
    ready = [slot for slot in (exits or []) if slot.get("state") == "ready" and slot.get("egress_ip")]

    res_names: list[str] = []
    res_blocks: list[str] = []
    pure_names: list[str] = []
    for slot in ready:
        label = _slot_label(slot)
        slot_id = str(slot.get("id") or "")
        number = slot_id.split("-", 1)[-1] if "-" in slot_id else "??"
        _, is_residential = _slot_kind(slot)
        for index, (domain, tag) in enumerate(domains):
            name = label if not tag else f"{label}·{tag}"
            res_blocks.append(_vless_node(name, domain, f"/res-{number}", inputs["uuid"], inputs["hostname"]))
            res_names.append(name)
            if index == 0 and is_residential:
                pure_names.append(name)

    stamp = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    lines = [
        f"# Cloud Shell proxy subscription - generated {stamp} (dynamic)",
        f"# {len(front_names)} domain nodes (CF->VPS) + {len(res_names)} exit variants "
        f"({len(pure_names)} verified residential, live state)",
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: warning",
    ]
    if front or res_blocks:
        lines.append("proxies:")
        if front:
            lines.append(front)
        lines.extend(res_blocks)
    else:
        lines.append("proxies: []")

    def q(name: str) -> str:
        return json.dumps(name, ensure_ascii=False)

    def lst(items: list[str]) -> str:
        return "\n".join(f"      - {q(item)}" for item in items) if items else "      - DIRECT"

    groups = ["proxy-groups:"]
    groups.append(
        '  - name: "🚀 节点选择"\n    type: select\n    proxies:\n'
        + lst(["⚡ 自动选择", "🏠 住宅自动"] + front_names + res_names + ["DIRECT"])
    )
    groups.append(
        '  - name: "⚡ 自动选择"\n    type: url-test\n'
        '    url: "http://www.gstatic.com/generate_204"\n    interval: 300\n'
        '    tolerance: 100\n    proxies:\n' + lst(front_names)
    )
    if pure_names:
        groups.append(
            '  - name: "🏠 住宅自动"\n    type: url-test\n'
            '    url: "http://www.gstatic.com/generate_204"\n    interval: 300\n'
            '    tolerance: 150\n    proxies:\n' + lst(pure_names)
        )
    else:
        groups.append(
            '  - name: "🏠 住宅自动"\n    type: select\n    proxies:\n'
            '      - "🚀 节点选择"'
        )
    for group in ("🧠 Claude", "🤖 ChatGPT", "🔵 Google·Gemini"):
        groups.append(
            f'  - name: "{group}"\n    type: select\n    proxies:\n'
            + lst(["🏠 住宅自动", "🚀 节点选择", "⚡ 自动选择"] + pure_names)
        )
    groups.append(
        '  - name: "🌐 其他流量"\n    type: select\n    proxies:\n'
        + lst(["🚀 节点选择", "⚡ 自动选择", "🏠 住宅自动", "DIRECT"])
    )
    groups.append(
        '  - name: "🇨🇳 中国流量"\n    type: select\n    proxies:\n'
        + lst(["DIRECT", "🚀 节点选择"])
    )

    rules = ["rules:"]
    rules.extend(f"  - DOMAIN-SUFFIX,{domain},🧠 Claude" for domain in (
        "claude.ai", "claudeusercontent.com", "anthropic.com", "claude.com",
    ))
    rules.extend(f"  - DOMAIN-SUFFIX,{domain},🤖 ChatGPT" for domain in (
        "chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com",
        "chat.com", "openai-api.arkoselabs.io",
    ))
    rules.extend(f"  - DOMAIN-SUFFIX,{domain},🔵 Google·Gemini" for domain in (
        "gemini.google.com", "generativelanguage.googleapis.com", "bard.google.com",
        "deepmind.google", "aistudio.google.com",
    ))
    rules.append("  - GEOIP,CN,🇨🇳 中国流量,no-resolve")
    rules.append("  - MATCH,🌐 其他流量")
    return "\n".join(lines + groups + rules) + "\n"


class SubscriptionCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._yaml = ""
        self._at = 0.0

    def get(self, inputs: dict[str, Any], domains: list[tuple[str, str]]) -> str:
        now = time.time()
        with self._lock:
            if self._yaml and now - self._at < CACHE_TTL:
                return self._yaml
        try:
            exits = fetch_exits()
            body = build_subscription_yaml(exits, inputs, domains)
        except Exception:
            with self._lock:
                if self._yaml:
                    return self._yaml
            raise
        with self._lock:
            self._yaml = body
            self._at = time.time()
        return body


def make_handler(sub_path: str, cache: SubscriptionCache, inputs: dict[str, Any], domains: list[tuple[str, str]]) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/healthz":
                payload = b'{"ok":true}\n'
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if path != sub_path:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            try:
                body = cache.get(inputs, domains).encode("utf-8")
            except Exception as error:
                payload = json.dumps({"code": "upstream_error", "error": str(error)[:200]}).encode()
                self.send_response(HTTPStatus.BAD_GATEWAY)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/yaml; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Subscription-Userinfo", "upload=0; download=0; total=107374182400; expire=0")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            return

    return Handler


def main() -> int:
    inputs = load_runtime_inputs()
    domains = res_domains()
    count = slot_count()
    write_runtime_configs(count, inputs)
    print(
        f"origin ready: slots={count} front_domains={len(domains)} path={inputs['sub_path']}",
        flush=True,
    )

    xray_bin = os.environ.get("KUI_XRAY_BIN", "/usr/local/bin/xray")
    process: subprocess.Popen[bytes] | None = None
    stop = threading.Event()

    def supervise_xray() -> None:
        nonlocal process
        while not stop.is_set():
            process = subprocess.Popen(
                [xray_bin, "run", "-c", str(RUNTIME_DIR / "xray.json")],
                stdout=sys.stdout,
                stderr=sys.stderr,
            )
            code = process.wait()
            if stop.is_set():
                return
            print(f"xray exited rc={code}; restarting in 1s", flush=True)
            time.sleep(1)

    thread = threading.Thread(target=supervise_xray, name="xray-supervisor", daemon=True)
    thread.start()

    cache = SubscriptionCache()
    handler = make_handler(inputs["sub_path"], cache, inputs, domains)
    server = ThreadingHTTPServer(("0.0.0.0", SUB_PORT), handler)

    def stop_all(_signum: int, _frame: Any) -> None:
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop_all)
    signal.signal(signal.SIGINT, stop_all)
    try:
        server.serve_forever()
    finally:
        stop.set()
        server.server_close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
