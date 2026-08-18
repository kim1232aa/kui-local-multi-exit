from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import mimetypes
import os
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
from urllib.parse import quote, unquote, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .bridge_nodes import _cache_key, _get_cache, load_bridge_nodes, parse_proxy_url
from .exit_manager import ExitManager
from .proxy_server import set_additional_credentials
from .realm_manager import RealmManager, RealmUnavailable
from .store import LocalStore
from .subscriptions import generate_singbox_config, parse_subscription
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
COUNTRY_NAMES_ZH = {
    "AE": "阿联酋", "AT": "奥地利", "AU": "澳大利亚", "BE": "比利时", "BR": "巴西",
    "CA": "加拿大", "CH": "瑞士", "CZ": "捷克", "DE": "德国", "DK": "丹麦",
    "ES": "西班牙", "FI": "芬兰", "FR": "法国", "GB": "英国", "GR": "希腊",
    "HK": "香港", "HR": "克罗地亚", "HU": "匈牙利", "ID": "印度尼西亚",
    "IE": "爱尔兰", "IN": "印度", "IS": "冰岛", "IT": "意大利", "JP": "日本",
    "KR": "韩国", "LU": "卢森堡", "MY": "马来西亚", "NL": "荷兰", "NO": "挪威",
    "NZ": "新西兰", "PH": "菲律宾", "PL": "波兰", "PT": "葡萄牙", "RO": "罗马尼亚",
    "RU": "俄罗斯", "SE": "瑞典", "SG": "新加坡", "TH": "泰国", "TR": "土耳其",
    "TW": "台湾", "UA": "乌克兰", "US": "美国", "VN": "越南", "ZA": "南非",
}
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
        reality_nodes_file: Path | str | None = None,
    ):
        if not username or not password:
            raise ValueError("management username and password are required")
        self.store = store
        self.manager = manager
        self.realm_manager = realm_manager or RealmManager(store)
        self.web_root = Path(web_root).resolve()
        self.username = username
        self.password = password
        configured_reality_nodes = reality_nodes_file or os.environ.get("KUI_REALITY_NODES_FILE", "")
        self.reality_nodes_file = Path(configured_reality_nodes).resolve() if configured_reality_nodes else None
        self._countries_cache: tuple[float, list[str]] | None = None
        super().__init__(address, LocalAPIHandler)


# Name of the proxy group used only by the explicitly chained nodes.
_FRONT_GROUP = "🔗链式前置"
_DIRECT_GROUP = "直连节点"
_CHAIN_GROUP = "链式节点"
_PROXY_GROUP = "PROXY"


# Traffic-splitting rules following the user's Clash Verge template
# (OpenAI/ChatGPT, Claude, Google/Gemini groups, local + CN direct).
# Group names are resolved at render time in do_GET.
_CHATGPT_RULES: tuple[str, ...] = (
    "DOMAIN-SUFFIX,openai.com",
    "DOMAIN-SUFFIX,chatgpt.com",
    "DOMAIN-SUFFIX,oaistatic.com",
    "DOMAIN-SUFFIX,oaiusercontent.com",
    "DOMAIN-SUFFIX,oaistatsig.com",
    "DOMAIN-SUFFIX,openaimerge.com",
    "DOMAIN-SUFFIX,openai.org",
    "DOMAIN-SUFFIX,sora.com",
    "DOMAIN-KEYWORD,openai",
    "DOMAIN-KEYWORD,chatgpt",
    "DOMAIN-SUFFIX,grok.com",
    "DOMAIN-SUFFIX,x.ai",
    "DOMAIN-SUFFIX,api.x.ai",
    "DOMAIN-KEYWORD,grok",
    "DOMAIN-SUFFIX,perplexity.ai",
    "DOMAIN-SUFFIX,poe.com",
    "DOMAIN-SUFFIX,cursor.sh",
    "DOMAIN-SUFFIX,v0.dev",
    "DOMAIN-SUFFIX,openrouter.ai",
    "DOMAIN-SUFFIX,huggingface.co",
    "DOMAIN-SUFFIX,hf.space",
    "DOMAIN-SUFFIX,replicate.com",
    "DOMAIN-SUFFIX,workers.dev",
    "DOMAIN-SUFFIX,character.ai",
    "DOMAIN-SUFFIX,pi.ai",
    "DOMAIN-SUFFIX,inflection.ai",
    "DOMAIN-SUFFIX,you.com",
    "DOMAIN-SUFFIX,copy.ai",
    "DOMAIN-SUFFIX,jasper.ai",
    "DOMAIN-SUFFIX,writesonic.com",
    "DOMAIN-SUFFIX,rytr.me",
    "DOMAIN-SUFFIX,quillbot.com",
    "DOMAIN-SUFFIX,grammarly.com",
    "DOMAIN-SUFFIX,codeium.com",
    "DOMAIN-SUFFIX,windsurf.com",
    "DOMAIN-SUFFIX,replit.com",
    "DOMAIN-SUFFIX,bolt.new",
    "DOMAIN-SUFFIX,lovable.dev",
    "DOMAIN-SUFFIX,tempo.new",
    "DOMAIN-SUFFIX,devin.ai",
    "DOMAIN-SUFFIX,t3.chat",
    "DOMAIN-SUFFIX,githubcopilot.com",
    "DOMAIN-SUFFIX,copilot.microsoft.com",
    "DOMAIN-SUFFIX,copilot.cloud.microsoft",
    "DOMAIN-SUFFIX,midjourney.com",
    "DOMAIN-SUFFIX,stability.ai",
    "DOMAIN-SUFFIX,dreamstudio.ai",
    "DOMAIN-SUFFIX,leonardo.ai",
    "DOMAIN-SUFFIX,d-id.com",
    "DOMAIN-SUFFIX,heygen.com",
    "DOMAIN-SUFFIX,runwayml.com",
    "DOMAIN-SUFFIX,pika.art",
    "DOMAIN-SUFFIX,pikalabs.net",
    "DOMAIN-SUFFIX,lumalabs.ai",
    "DOMAIN-SUFFIX,suno.ai",
    "DOMAIN-SUFFIX,suno.com",
    "DOMAIN-SUFFIX,udio.com",
    "DOMAIN-SUFFIX,elevenlabs.io",
    "DOMAIN-SUFFIX,elevenlabs.com",
    "DOMAIN-SUFFIX,play.ht",
    "DOMAIN-SUFFIX,descript.com",
    "DOMAIN-SUFFIX,kaiber.ai",
    "DOMAIN-SUFFIX,krea.ai",
    "DOMAIN-SUFFIX,clipdrop.co",
    "DOMAIN-SUFFIX,ideogram.ai",
    "DOMAIN-SUFFIX,flux.ai",
    "DOMAIN-SUFFIX,together.xyz",
    "DOMAIN-SUFFIX,mistral.ai",
    "DOMAIN-SUFFIX,cohere.com",
    "DOMAIN-SUFFIX,ai21.com",
    "DOMAIN-SUFFIX,groq.com",
    "DOMAIN-SUFFIX,fireworks.ai",
    "DOMAIN-SUFFIX,deepinfra.com",
    "DOMAIN-SUFFIX,baseten.co",
    "DOMAIN-SUFFIX,predibase.com",
    "DOMAIN-SUFFIX,anyscale.com",
    "DOMAIN-SUFFIX,lambdalabs.com",
    "DOMAIN-SUFFIX,runpod.io",
    "DOMAIN-SUFFIX,vast.ai",
    "DOMAIN-SUFFIX,salad.com",
    "DOMAIN-SUFFIX,coreweave.com",
    "DOMAIN-SUFFIX,phind.com",
    "DOMAIN-SUFFIX,exa.ai",
    "DOMAIN-SUFFIX,kagi.com",
    "DOMAIN-SUFFIX,andisearch.com",
    "DOMAIN-SUFFIX,elicit.org",
    "DOMAIN-SUFFIX,consensus.app",
    "DOMAIN-SUFFIX,notion.so",
    "DOMAIN-SUFFIX,mem.ai",
    "DOMAIN-SUFFIX,otter.ai",
    "DOMAIN-SUFFIX,fireflies.ai",
    "DOMAIN-SUFFIX,reflect.app",
    "DOMAIN-SUFFIX,readwise.io",
    "DOMAIN-SUFFIX,ai.cloudflare.com",
    "DOMAIN-SUFFIX,workers.ai",
    "DOMAIN-SUFFIX,gateway.ai.cloudflare.com",
    "DOMAIN-SUFFIX,pollen-optimization.googleapis.com",
    "DOMAIN-SUFFIX,meta.ai",
    "DOMAIN-SUFFIX,machinelearning.apple.com",
    "DOMAIN-SUFFIX,pinecone.io",
    "DOMAIN-SUFFIX,weaviate.io",
    "DOMAIN-SUFFIX,qdrant.tech",
    "DOMAIN-SUFFIX,chroma.db",
)

_CLAUDE_RULES: tuple[str, ...] = (
    "DOMAIN-SUFFIX,anthropic.com",
    "DOMAIN-SUFFIX,claude.ai",
    "DOMAIN-SUFFIX,claude.com",
    "DOMAIN-SUFFIX,clau.de",
    "DOMAIN-SUFFIX,claudemcpclient.com",
    "DOMAIN-SUFFIX,claudeusercontent.com",
    "DOMAIN-SUFFIX,modelcontextprotocol.io",
    "DOMAIN,anthropic.com.cdn.cloudflare.net",
    "DOMAIN,servd-anthropic-website.b-cdn.net",
    "DOMAIN,anthropic.auth0.com",
    "DOMAIN-KEYWORD,claude",
    "DOMAIN-KEYWORD,anthropic",
)

_GEMINI_RULES: tuple[str, ...] = (
    "DOMAIN-SUFFIX,aistudio.google.com",
    "DOMAIN-SUFFIX,makersuite.google.com",
    "DOMAIN-SUFFIX,generativelanguage.googleapis.com",
    "DOMAIN-SUFFIX,cloudcode-pa.googleapis.com",
    "DOMAIN-SUFFIX,ai.google.dev",
    "DOMAIN-SUFFIX,antigravity.google",
    "DOMAIN-SUFFIX,gemini.google.com",
    "DOMAIN-SUFFIX,vertexai.googleapis.com",
    "DOMAIN-SUFFIX,aiplatform.googleapis.com",
    "DOMAIN-SUFFIX,googleapis.com",
)

_LOCAL_DIRECT_RULES: tuple[str, ...] = (
    "DOMAIN-SUFFIX,local,DIRECT",
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
    "IP-CIDR,198.18.0.0/15,DIRECT,no-resolve",
)


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

    def _send_text(
        self,
        status: int,
        body: str,
        *,
        content_type: str = "text/plain; charset=utf-8",
    ) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
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
        return re.fullmatch(rf"/api/local/exits/(exit-\d+){suffix}", path)

    def _require_managed_slot(self, slot_id: str) -> None:
        if not self.server.manager.is_managed_slot(slot_id):
            raise KeyError(slot_id)

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
            egress_type, egress_type_label = self._slot_egress_type_info(slot)
            projected.append(
                {
                    **slot,
                    "listener_ready": listener_ready,
                    "egress_type": egress_type,
                    "egress_type_label": egress_type_label,
                    "last_updated": updated_at * 1000,
                    "name": slot["id"],
                    "region": slot["country"],
                    "country_code": slot["country"],
                    "detected_country": self._slot_country_code(slot),
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
                "egress_type": self._slot_egress_type_info(slot)[0],
                "egress_type_label": self._slot_egress_type_info(slot)[1],
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

    def _socks5_public_host(self) -> str:
        configured = os.environ.get("KUI_SOCKS5_PUBLIC_HOST", "").strip()
        if configured:
            if configured.startswith("[") and "]" in configured:
                return configured[1:configured.index("]")]
            return configured
        for node in self._local_reality_nodes().values():
            address = str(node.get("address") or "").strip()
            if address and address not in {"127.0.0.1", "0.0.0.0", "::1", "::"}:
                return address.strip("[]")
        return self._request_proxy_host()

    @staticmethod
    def _socks5_uri_host(host: str) -> str:
        host = str(host).strip().strip("[]")
        try:
            if ipaddress.ip_address(host).version == 6:
                return f"[{host}]"
        except ValueError:
            pass
        return host

    @staticmethod
    def _subscription_extra(node: dict[str, Any]) -> dict[str, Any]:
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

    @classmethod
    def _subscription_value(cls, node: dict[str, Any], key: str, default: Any = "") -> Any:
        value = node.get(key)
        if value not in (None, ""):
            return value
        return cls._subscription_extra(node).get(key, default)

    @classmethod
    def _subscription_bool(cls, node: dict[str, Any], key: str) -> bool:
        value = cls._subscription_value(node, key, False)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def _subscription_link(node: dict[str, Any]) -> str:
        try:
            address = str(node.get("address") or node.get("server") or "").strip()
            port = int(node.get("port") or node.get("server_port") or 0)
        except (TypeError, ValueError):
            return ""
        if not address or not 1 <= port <= 65535:
            return ""
        display_address = f"[{address}]" if ":" in address and not address.startswith("[") else address
        protocol = str(node.get("protocol") or node.get("type") or "").strip().lower().replace("_", "-")
        name_text = str(node.get("name") or f"TP_{protocol or 'node'}_{port}")
        name = quote(name_text, safe="")
        raw_extra = str(node.get("extra") or "").strip()

        def parameter(key: str, value: Any) -> str:
            return f"{quote(key, safe='')}={quote(str(value), safe='')}"

        if protocol == "vmess":
            if raw_extra.lower().startswith("vmess://"):
                return raw_extra
            uuid = str(node.get("uuid") or "")
            if not uuid:
                return ""
            vmess = {
                "v": "2",
                "ps": name_text,
                "add": address,
                "port": str(port),
                "id": uuid,
                "aid": "0",
                "scy": "auto",
                "net": str(node.get("network") or "tcp"),
            }
            security = str(LocalAPIHandler._subscription_value(node, "security", "") or "").lower()
            if security in {"tls", "xtls"} or LocalAPIHandler._subscription_bool(node, "tls"):
                vmess["tls"] = "tls"
                vmess["sni"] = str(node.get("sni") or address)
            if node.get("host"):
                vmess["host"] = str(node["host"])
            if node.get("path"):
                vmess["path"] = str(node["path"])
            encoded = base64.b64encode(json.dumps(vmess, ensure_ascii=False, separators=(",", ":")).encode()).decode().rstrip("=")
            return f"vmess://{encoded}"

        if protocol in {"vless", "reality", "xtls-reality", "h2-reality", "grpc-reality"}:
            uuid = str(node.get("uuid") or "")
            if not uuid:
                return ""
            public_key = str(node.get("public_key") or "")
            security = str(LocalAPIHandler._subscription_value(node, "security", "none") or "none").lower()
            is_reality = protocol != "vless" or bool(public_key) or security == "reality"
            if is_reality and not public_key:
                return ""
            query = [parameter("encryption", "none")]
            if is_reality:
                query.extend((
                    parameter("security", "reality"),
                    parameter("sni", node.get("sni") or address),
                    parameter("fp", node.get("client-fingerprint") or LocalAPIHandler._subscription_value(node, "fingerprint", "chrome") or "chrome"),
                ))
                if public_key:
                    query.append(parameter("pbk", public_key))
                if node.get("short_id"):
                    query.append(parameter("sid", node["short_id"]))
            else:
                tls = security in {"tls", "xtls"} or LocalAPIHandler._subscription_bool(node, "tls")
                query.append(parameter("security", "tls" if tls else "none"))
                if tls:
                    query.append(parameter("sni", node.get("sni") or address))
                    fingerprint = LocalAPIHandler._subscription_value(node, "fingerprint", "")
                    if fingerprint:
                        query.append(parameter("fp", fingerprint))
            if node.get("flow"):
                query.append(parameter("flow", node["flow"]))
            network = str(node.get("network") or ("http" if protocol == "h2-reality" else "grpc" if protocol == "grpc-reality" else "tcp"))
            query.append(parameter("type", network))
            if node.get("host"):
                query.append(parameter("host", node["host"]))
            if node.get("path"):
                query.append(parameter("path", node["path"]))
            service_name = LocalAPIHandler._subscription_value(node, "service_name", "")
            if service_name:
                query.append(parameter("serviceName", service_name))
            return f"vless://{quote(uuid, safe='')}@{display_address}:{port}?{'&'.join(query)}#{name}"

        if protocol == "trojan":
            password = str(node.get("password") or node.get("private_key") or "")
            if not password:
                return ""
            query = [parameter("security", "tls"), parameter("sni", node.get("sni") or address)]
            if LocalAPIHandler._subscription_bool(node, "insecure"):
                query.append(parameter("allowInsecure", "1"))
            return f"trojan://{quote(password, safe='')}@{display_address}:{port}?{'&'.join(query)}#{name}"

        if protocol in {"hysteria2", "hy2", "hysteria"}:
            password = str(node.get("password") or node.get("uuid") or node.get("private_key") or "")
            if not password:
                return ""
            query = [parameter("insecure", "1"), parameter("sni", node.get("sni") or address)]
            return f"hysteria2://{quote(password, safe='')}@{display_address}:{port}?{'&'.join(query)}#{name}"

        if protocol == "tuic":
            uuid = str(node.get("uuid") or "")
            password = str(node.get("password") or node.get("private_key") or "")
            if not uuid or not password:
                return ""
            query = [parameter("sni", node.get("sni") or address)]
            if LocalAPIHandler._subscription_bool(node, "insecure"):
                query.append(parameter("allow_insecure", "1"))
            return f"tuic://{quote(uuid, safe='')}:{quote(password, safe='')}@{display_address}:{port}?{'&'.join(query)}#{name}"

        if protocol == "naive":
            username = str(node.get("uuid") or node.get("username") or "")
            password = str(node.get("password") or node.get("private_key") or "")
            if not username or not password:
                return ""
            return f"naive+https://{quote(username, safe='')}:{quote(password, safe='')}@{display_address}:{port}?{parameter('sni', node.get('sni') or address)}#{name}"

        if protocol == "anytls":
            password = str(node.get("password") or node.get("private_key") or "")
            if not password:
                return ""
            query = [parameter("sni", node.get("sni") or address)]
            if LocalAPIHandler._subscription_bool(node, "insecure"):
                query.append(parameter("insecure", "1"))
            return f"anytls://{quote(password, safe='')}@{display_address}:{port}?{'&'.join(query)}#{name}"

        if protocol in {"socks", "socks5", "socks-5"}:
            extra = LocalAPIHandler._subscription_extra(node)
            username = str(node.get("username") or extra.get("username") or node.get("uuid") or "")
            password = str(node.get("password") or "")
            credentials = f"{quote(username, safe='')}:{quote(password, safe='')}@" if username or password else ""
            return f"socks5://{credentials}{display_address}:{port}#{name}"

        if protocol in {"ss", "shadowsocks"}:
            extra = LocalAPIHandler._subscription_extra(node)
            method = str(node.get("cipher") or node.get("uuid") or extra.get("method") or "")
            password = str(node.get("password") or "")
            if not method or not password:
                return ""
            credentials = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
            return f"ss://{credentials}@{display_address}:{port}#{name}"

        if protocol == "ssr" and raw_extra.lower().startswith("ssr://"):
            return raw_extra
        return ""

    @staticmethod
    def _ws_path(node: dict[str, Any]) -> str:
        ws_opts = node.get("ws-opts") if isinstance(node.get("ws-opts"), dict) else {}
        return str(ws_opts.get("path") or node.get("path") or "/")

    @staticmethod
    def _ws_host(node: dict[str, Any]) -> str:
        ws_opts = node.get("ws-opts") if isinstance(node.get("ws-opts"), dict) else {}
        headers = ws_opts.get("headers") if isinstance(ws_opts.get("headers"), dict) else {}
        return str(
            headers.get("Host")
            or node.get("host")
            or node.get("sni")
            or node.get("address")
            or node.get("server")
            or ""
        )

    @classmethod
    def _clash_proxy(cls, node: dict[str, Any]) -> tuple[str, str] | None:
        try:
            address_value = str(node.get("address") or node.get("server") or "").strip()
            port = int(node.get("port") or node.get("server_port") or 0)
        except (TypeError, ValueError):
            return None
        if not address_value or not 1 <= port <= 65535:
            return None
        protocol = str(node.get("protocol") or node.get("type") or "").strip().lower().replace("_", "-")
        name = str(node.get("name") or f"TP_{protocol or 'node'}_{port}")
        quoted_name = json.dumps(name, ensure_ascii=False)
        address = json.dumps(address_value, ensure_ascii=False)
        lines = [
            f"  - name: {quoted_name}",
            f"    type: {protocol}",
            f"    server: {address}",
            f"    port: {port}",
        ]
        extra = cls._subscription_extra(node)

        if protocol in {"vless", "reality", "xtls-reality", "h2-reality", "grpc-reality"}:
            uuid = str(node.get("uuid") or "")
            if not uuid:
                return None
            lines[1] = "    type: vless"
            lines.extend((f"    uuid: {json.dumps(uuid)}", "    udp: true"))
            network = str(node.get("network") or "tcp").lower()
            if protocol == "h2-reality" or network == "http":
                network = "h2"
            elif protocol == "grpc-reality":
                network = "grpc"
            if network != "h2":
                lines.append(f"    network: {json.dumps(network)}")
            public_key = str(node.get("public_key") or "")
            security = str(cls._subscription_value(node, "security", "none") or "none").lower()
            is_reality = protocol != "vless" or bool(public_key) or security == "reality"
            if is_reality:
                if not public_key:
                    return None
                lines.extend((
                    "    tls: true",
                    f"    servername: {json.dumps(str(node.get('sni') or address_value))}",
                    f"    client-fingerprint: {json.dumps(str(node.get('client-fingerprint') or extra.get('fingerprint') or 'chrome'))}",
                    "    reality-opts:",
                    f"      public-key: {json.dumps(public_key)}",
                    f"      short-id: {json.dumps(str(node.get('short_id') or ''))}",
                ))
                flow = str(node.get("flow") or "")
                if flow:
                    lines.append(f"    flow: {json.dumps(flow)}")
            elif security in {"tls", "xtls"} or cls._subscription_bool(node, "tls"):
                lines.extend((
                    "    tls: true",
                    f"    servername: {json.dumps(str(node.get('servername') or node.get('sni') or address_value))}",
                    f"    client-fingerprint: {json.dumps(str(node.get('client-fingerprint') or extra.get('fingerprint') or 'chrome'))}",
                ))
            if network in {"ws", "websocket"}:
                lines.extend((
                    "    ws-opts:",
                    f"      path: {json.dumps(cls._ws_path(node))}",
                    "      headers:",
                    f"        Host: {json.dumps(cls._ws_host(node))}",
                ))
            elif network == "grpc":
                service_name = str(node.get("service_name") or extra.get("service_name") or node.get("path") or "grpc").lstrip("/")
                lines.extend(("    grpc-opts:", f"      grpc-service-name: {json.dumps(service_name or 'grpc')}"))
            elif network in {"http", "h2"}:
                lines.extend((
                    "    network: h2",
                    "    h2-opts:",
                    "      host:",
                    f"        - {json.dumps(str(node.get('host') or node.get('sni') or address_value))}",
                    f"      path: {json.dumps(str(node.get('path') or '/'))}",
                ))
        elif protocol == "http":
            lines[1] = "    type: http"
            username = str(node.get("username") or extra.get("username") or "")
            password = str(node.get("password") or "")
            if username:
                lines.append(f"    username: {json.dumps(username)}")
                lines.append(f"    password: {json.dumps(password)}")
        elif protocol in {"socks", "socks5", "socks-5"}:
            lines[1] = "    type: socks5"
            username = str(node.get("username") or extra.get("username") or node.get("uuid") or "")
            password = str(node.get("password") or "")
            if username:
                lines.append(f"    username: {json.dumps(username)}")
                lines.append(f"    password: {json.dumps(password)}")
            lines.append("    udp: true")
        elif protocol == "trojan":
            password = str(node.get("password") or node.get("private_key") or "")
            if not password:
                return None
            lines.extend((
                f"    password: {json.dumps(password)}",
                f"    sni: {json.dumps(str(node.get('sni') or address_value))}",
                "    udp: true",
            ))
        elif protocol in {"hysteria2", "hy2", "hysteria"}:
            password = str(node.get("password") or node.get("uuid") or node.get("private_key") or "")
            if not password:
                return None
            lines[1] = "    type: hysteria2"
            lines.extend((
                f"    password: {json.dumps(password)}",
                f"    sni: {json.dumps(str(node.get('sni') or address_value))}",
                "    skip-cert-verify: true",
            ))
        elif protocol == "tuic":
            uuid = str(node.get("uuid") or "")
            password = str(node.get("password") or node.get("private_key") or "")
            if not uuid or not password:
                return None
            lines.extend((
                f"    uuid: {json.dumps(uuid)}",
                f"    password: {json.dumps(password)}",
                f"    sni: {json.dumps(str(node.get('sni') or address_value))}",
                "    skip-cert-verify: true",
                "    udp-relay-mode: native",
            ))
        elif protocol in {"ss", "shadowsocks"}:
            method = str(node.get("cipher") or node.get("uuid") or extra.get("method") or "")
            password = str(node.get("password") or "")
            if not method or not password:
                return None
            lines[1] = "    type: ss"
            lines.extend((
                f"    cipher: {json.dumps(method)}",
                f"    password: {json.dumps(password)}",
                "    udp: true",
            ))
        elif protocol in {"HTTP", "http"}:
            lines[1] = "    type: http"
            if node.get("username"):
                lines.extend((
                    f"    username: {json.dumps(str(node['username']))}",
                    f"    password: {json.dumps(str(node.get('password', '')))}",
                ))
        elif protocol in {"SOCKS5", "socks5"}:
            lines[1] = "    type: socks5"
            lines.append("    udp: true")
            if node.get("username"):
                lines.extend((
                    f"    username: {json.dumps(str(node['username']))}",
                    f"    password: {json.dumps(str(node.get('password', '')))}",
                ))
        elif protocol in {"VMESS", "vmess"}:
            uuid = str(node.get("uuid") or "")
            if not uuid:
                return None
            lines[1] = "    type: vmess"
            network = str(node.get("network") or "tcp").lower()
            lines.extend((
                f"    uuid: {json.dumps(uuid)}",
                "    alterId: 0",
                "    cipher: auto",
                "    udp: true",
                f"    network: {json.dumps(network)}",
            ))
            if network in {"ws", "websocket"}:
                lines.extend((
                    "    ws-opts:",
                    f"      path: {json.dumps(cls._ws_path(node))}",
                    "      headers:",
                    f"        Host: {json.dumps(cls._ws_host(node))}",
                ))
        elif protocol == "anytls":
            password = str(node.get("password") or node.get("private_key") or "")
            if not password:
                return None
            lines[1] = "    type: anytls"
            lines.extend((
                f"    password: {json.dumps(password)}",
                f"    sni: {json.dumps(str(node.get('sni') or address_value))}",
                "    skip-cert-verify: true",
            ))
        else:
            return None
        if node.get("dialer-proxy"):
            lines.append(f"    dialer-proxy: {json.dumps(str(node['dialer-proxy']), ensure_ascii=False)}")
        return name, "\n".join(lines)

    def _local_reality_nodes(self) -> dict[str, dict[str, Any]]:
        path = self.server.reality_nodes_file
        if not path:
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return {}
        raw_nodes = payload.get("nodes", []) if isinstance(payload, dict) else []
        if not isinstance(raw_nodes, list):
            return {}
        nodes: dict[str, dict[str, Any]] = {}
        for raw in raw_nodes:
            if not isinstance(raw, dict):
                continue
            slot_id = str(raw.get("slot_id", ""))
            address = str(raw.get("address", ""))
            uuid = str(raw.get("uuid", ""))
            public_key = str(raw.get("public_key", ""))
            short_id = str(raw.get("short_id", ""))
            sni = str(raw.get("sni", ""))
            try:
                port = int(raw.get("port", 0))
            except (TypeError, ValueError):
                continue
            if not (
                re.fullmatch(r"exit-(?:0[1-9]|1[0-9]|2[0-4])", slot_id)
                or re.fullmatch(r"tr-\d+", slot_id)
            ):
                continue
            if not address or len(address) > 253 or not 1 <= port <= 65535:
                continue
            if not re.fullmatch(r"[0-9a-fA-F-]{36}", uuid):
                continue
            if not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", public_key):
                continue
            if not re.fullmatch(r"[0-9a-fA-F]{2,32}", short_id):
                continue
            if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", sni):
                continue
            nodes[slot_id] = {
                "protocol": "Reality",
                "address": address,
                "port": port,
                "uuid": uuid,
                "sni": sni,
                "public_key": public_key,
                "short_id": short_id,
                "flow": "xtls-rprx-vision",
                "network": "tcp",
            }
        return nodes

    @staticmethod
    def _useful_label(value: Any) -> str:
        text = re.sub(r"\s+", " ", str(value or "")).strip(" .|_-")
        if text.lower() in {"", "unknown", "none", "n/a", "na", "null", "-", "未知"}:
            return ""
        return text[:48]

    @classmethod
    def _short_isp_name(cls, value: Any) -> str:
        name = cls._useful_label(value)
        aliases = (
            ("KDDI", "KDDI"),
            ("SoftBank", "SoftBank"),
            ("ARTERIA", "ARTERIA"),
            ("TOKAI", "TOKAI"),
            ("EHIME CATV", "EHIME CATV"),
            ("Triple T", "Triple T"),
            ("NTT DOCOMO", "NTT DOCOMO"),
            ("Korea Telecom", "KT"),
        )
        for marker, alias in aliases:
            if marker.lower() in name.lower():
                return alias
        name = re.sub(
            r"(?i)\b(?:public company limited|communications corporation|corporation|corp\.?|company|co\.?,?\s*ltd\.?|inc\.?)\b",
            "",
            name,
        )
        return re.sub(r"\s+", " ", name).strip(" ,.-")[:32]

    @classmethod
    def _slot_geo(cls, slot: dict[str, Any]) -> dict[str, Any]:
        check_result = slot.get("check_result") if isinstance(slot.get("check_result"), dict) else {}
        residential = check_result.get("residential") if isinstance(check_result.get("residential"), dict) else {}
        raw = residential.get("raw") if isinstance(residential.get("raw"), dict) else {}
        return raw.get("geo") if isinstance(raw.get("geo"), dict) else {}

    @classmethod
    def _slot_isp(cls, slot: dict[str, Any]) -> dict[str, Any]:
        check_result = slot.get("check_result") if isinstance(slot.get("check_result"), dict) else {}
        residential = check_result.get("residential") if isinstance(check_result.get("residential"), dict) else {}
        raw = residential.get("raw") if isinstance(residential.get("raw"), dict) else {}
        return raw.get("isp") if isinstance(raw.get("isp"), dict) else {}

    @classmethod
    def _slot_egress_type_info(cls, slot: dict[str, Any]) -> tuple[str, str]:
        check_result = slot.get("check_result") if isinstance(slot.get("check_result"), dict) else {}
        residential = check_result.get("residential") if isinstance(check_result.get("residential"), dict) else {}
        egress_type = residential.get("egress_type")
        egress_type_label = residential.get("egress_type_label")
        if egress_type and egress_type_label:
            return str(egress_type), str(egress_type_label)

        raw_isp = residential.get("raw", {}).get("isp", {}) if isinstance(residential.get("raw"), dict) else {}
        flag = str(raw_isp.get("flag", "")).strip().lower()
        isp_type = str(raw_isp.get("type", "")).strip().lower()
        warning = str(raw_isp.get("warning", "")).strip().lower()
        is_res = residential.get("is_residential") if "is_residential" in residential else check_result.get("is_residential")
        explicit_non_residential_flags = {
            "datacenter",
            "hosting",
            "business",
            "corporate",
            "enterprise",
            "government",
            "education",
        }
        non_residential_markers = (
            "datacenter",
            "data center",
            "hosting",
            "business",
            "corporate",
            "enterprise",
            "government",
            "education",
            "vpn",
            "proxy",
        )
        explicitly_non_residential = (
            flag in explicit_non_residential_flags
            or any(marker in value for value in (isp_type, warning) for marker in non_residential_markers)
        )

        if is_res is True or flag == "residential":
            return "residential", "住宅IP"
        if explicitly_non_residential:
            return "datacenter", "机房IP"
        return "unknown", "未知IP类型"

    @classmethod
    def _slot_country_code(cls, slot: dict[str, Any]) -> str:
        current_node = slot.get("current_node") if isinstance(slot.get("current_node"), dict) else {}
        geo_code = cls._useful_label(cls._slot_geo(slot).get("country_code")).upper()
        node_code = cls._useful_label(current_node.get("country")).upper()
        target_code = cls._useful_label(slot.get("country")).upper()
        return next(
            (code for code in (geo_code, node_code, target_code) if re.fullmatch(r"[A-Z]{2}", code) and code != "XX"),
            "XX",
        )

    @classmethod
    def _slot_label_country(cls, slot: dict[str, Any]) -> str:
        """Show the target country, or both actual/target for a fallback exit."""
        target = str(slot.get("country") or "").upper()
        current_node = slot.get("current_node") if isinstance(slot.get("current_node"), dict) else {}
        if current_node.get("country_fallback"):
            actual = cls._slot_country_code(slot)
            if actual not in {"XX", target}:
                return f"{actual}-FB-{target}"
        if target and target not in {"ANY", "XX"}:
            return target
        return cls._slot_country_code(slot)

    @classmethod
    def _friendly_slot_name(cls, slot: dict[str, Any]) -> str:
        geo = cls._slot_geo(slot)
        isp = cls._slot_isp(slot)
        country_code = cls._slot_country_code(slot)
        country_name = COUNTRY_NAMES_ZH.get(country_code) or cls._useful_label(geo.get("country"))
        location = f"{country_code}-{country_name}" if country_name else country_code
        city = cls._useful_label(geo.get("city"))
        if city and city.lower() not in {country_name.lower(), location.lower()}:
            location = f"{location}-{city}"

        parts = [location]
        egress_type, egress_type_label = cls._slot_egress_type_info(slot)
        if egress_type_label:
            parts.append(egress_type_label)
        provider = cls._short_isp_name(isp.get("org"))
        if provider:
            parts.append(provider)
        egress_ip = cls._useful_label(slot.get("egress_ip") or slot.get("entry_ip"))
        if egress_ip:
            parts.append(egress_ip)
        parts.append(str(slot["id"]))
        return " | ".join(parts)

    def _bridge_nodes(self) -> list[dict[str, Any]]:
        """Load bridge proxy nodes from environment.

        A background thread (started by entrypoint.py) refreshes subscription
        nodes periodically. The API shares the same module-level cache, so
        subscription requests are fast and do not block on network tests.

        When the cache is empty (first boot or refresh still running) the API
        returns only trusted manual nodes instead of blocking a request on
        live testing; the background refresher fills the cache shortly after.
        """
        manual = [u.strip() for u in (os.environ.get("KUI_BRIDGE_NODES", "") or "").split(",") if u.strip()]
        subs = [u.strip() for u in (os.environ.get("KUI_BRIDGE_SUB_URLS", "") or "").split(",") if u.strip()]
        if not subs:
            return load_bridge_nodes(manual_urls=manual, test_reachability=False)
        key = _cache_key(manual, subs, True)
        cached = _get_cache(key, max_age=300)
        if cached is not None:
            return cached
        return load_bridge_nodes(manual_urls=manual, test_reachability=False)

    def _local_subscription_nodes(self, *, include_dialer_proxy: bool = False) -> list[dict[str, Any]]:
        reality_nodes = self._local_reality_nodes()
        publishable = {slot["id"]: slot for slot in self._publishable_slots()}
        nodes = []
        for slot_id, node in reality_nodes.items():
            if slot_id in publishable:
                # The 24 OpenVPN slots are direct exits and never use a
                # client-side dialer proxy.
                nodes.append({
                    **node,
                    "name": self._friendly_slot_name(publishable[slot_id]),
                    "country": self._slot_country_code(publishable[slot_id]),
                    "_subscription_group": "direct",
                })
            elif slot_id.startswith("tr-"):
                # tr-01 already exits through the Turkish upstream proxy on
                # the VPS, so it is the single chained exit.
                base_name = str(node.get("name") or f"TR-土耳其 | ProxyScrape | {slot_id}")
                chained = {
                    **node,
                    "name": f"{base_name} | 链式",
                    "country": str(node.get("country") or "TR"),
                    "_subscription_group": "chain",
                }
                if include_dialer_proxy:
                    chained["dialer-proxy"] = _FRONT_GROUP
                nodes.append(chained)
        if self.server.reality_nodes_file:
            return nodes
        if not nodes:
            host = self._socks5_public_host()
            for slot in publishable.values():
                # Local-only deployments without a configured Reality manifest
                # may still consume the loopback SOCKS subscription.
                nodes.append({
                    "name": self._friendly_slot_name(slot),
                    "country": self._slot_country_code(slot),
                    "protocol": "socks",
                    "address": host,
                    "port": slot["proxy_port"],
                    "username": self.server.username,
                    "password": self.server.password,
                    "_subscription_group": "direct",
                })
        return nodes

    def _local_socks5_links(self) -> list[str]:
        host = self._socks5_uri_host(self._socks5_public_host())
        username = quote(self.server.username, safe="")
        password = quote(self.server.password, safe="")
        links = []
        for slot in self._publishable_slots():
            name = quote(f"{self._slot_label_country(slot)}_{slot['id']}_{slot['state']}", safe="")
            links.append(f"socks5://{username}:{password}@{host}:{slot['proxy_port']}#{name}")
        return links

    def _subscription_user(self) -> dict[str, Any] | None:
        username = self._query_param("user") or ""
        token = self._query_param("token") or ""
        user = self.server.store.get_user(username)
        if not user or not user.get("enable") or not token or not hmac.compare_digest(token, str(user.get("sub_token", ""))):
            return None
        return user

    def _socks5_subscription_links(self) -> list[str]:
        links = self._local_socks5_links()
        thirdparty_nodes = self.server.store.list_enabled_thirdparty_nodes()
        links.extend(
            link
            for node in thirdparty_nodes
            if (link := self._subscription_link(node)) and link.startswith("socks5://")
        )
        return links

    def _socks5_json_export(self) -> dict[str, Any]:
        proxies = []
        seen = set()
        for link in self._socks5_subscription_links():
            try:
                parsed = urlsplit(link)
                if parsed.scheme.lower() not in {"socks", "socks5"} or not parsed.hostname:
                    continue
                host = parsed.hostname
                port = parsed.port or 1080
                username = unquote(parsed.username or "")
                password = unquote(parsed.password or "")
            except (TypeError, ValueError):
                continue
            proxy_key = f"socks5|{host}|{port}|{username}|{password}"
            if proxy_key in seen:
                continue
            seen.add(proxy_key)
            proxy = {
                "proxy_key": proxy_key,
                "name": unquote(parsed.fragment) or f"{host}:{port}",
                "protocol": "socks5",
                "host": host,
                "port": port,
            }
            if username:
                proxy["username"] = username
            if password:
                proxy["password"] = password
            proxy.update({"status": "active", "fallback_mode": "none"})
            proxies.append(proxy)
        return {
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "proxies": proxies,
            "accounts": [],
        }

    def _local_subscription_links(self) -> list[str]:
        if self.server.reality_nodes_file:
            return [
                link
                for node in self._local_subscription_nodes()
                if (link := self._subscription_link(node))
            ]
        return self._local_socks5_links()

    @classmethod
    def _subscription_country_code(cls, node: dict[str, Any]) -> str:
        known = set(COUNTRY_PRESETS)
        for key in ("country_code", "country", "_country_hint"):
            value = str(node.get(key) or "").upper().strip()
            if value in known:
                return value
        name = str(node.get("name") or "")
        flag = re.search(r"[\U0001F1E6-\U0001F1FF]{2}", name)
        if flag:
            code = "".join(chr(ord(char) - 0x1F1E6 + ord("A")) for char in flag.group(0))
            if code in known:
                return code
        for match in re.finditer(r"(?<![A-Za-z])([A-Za-z]{2})(?![A-Za-z])", name):
            code = match.group(1).upper()
            if code in known:
                return code
        return "OTHER"

    @staticmethod
    def _unique_clash_node(node: dict[str, Any], used_names: set[str]) -> dict[str, Any]:
        protocol = str(node.get("protocol") or node.get("type") or "node")
        port = node.get("port") or node.get("server_port") or 0
        base = str(node.get("name") or f"TP_{protocol}_{port}").strip() or f"TP_{protocol}_{port}"
        candidate = base
        suffix = 2
        while candidate in used_names:
            candidate = f"{base} ({suffix})"
            suffix += 1
        used_names.add(candidate)
        return {**node, "name": candidate}

    def _local_clash_proxies(self) -> dict[str, Any]:
        bridges: list[tuple[str, str]] = []
        direct: list[tuple[str, str]] = []
        chain: list[tuple[str, str]] = []
        front: list[str] = []
        country_by_name: dict[str, str] = {}
        used_names = {
            _FRONT_GROUP,
            _DIRECT_GROUP,
            _CHAIN_GROUP,
            _PROXY_GROUP,
            "⚡ 自动选择",
            "🔵 Google / Gemini",
            "🤖 ChatGPT",
            "🧠 Claude",
            "🌐 其他流量",
            "🇨🇳 中国流量",
            "DIRECT",
        }

        def add_entry(target: list[tuple[str, str]], node: dict[str, Any]) -> tuple[str, str] | None:
            normalized = self._unique_clash_node(node, used_names)
            entry = self._clash_proxy(normalized)
            if entry:
                target.append(entry)
                country_by_name[entry[0]] = self._subscription_country_code(normalized)
            return entry

        if self.server.reality_nodes_file:
            all_bridge_nodes = self._bridge_nodes()
            # Only explicitly configured bridge URLs are first-hop candidates.
            # Subscription-fed nodes are final exits and are handled below.
            for bridge in all_bridge_nodes:
                if bridge.get("_source_kind", "manual") != "manual":
                    continue
                add_entry(bridges, bridge)
            local_nodes = self._local_subscription_nodes(include_dialer_proxy=False)
            for node in local_nodes:
                if node.get("_subscription_group") == "chain":
                    node = {**node, "dialer-proxy": _FRONT_GROUP}
                    add_entry(chain, node)
                elif entry := add_entry(direct, node):
                    front.append(entry[0])
            # Public subscription nodes are additional final exits. They use
            # the selected first-hop node from the front group.
            for node in all_bridge_nodes:
                if node.get("_source_kind") != "subscription":
                    continue
                raw_name = str(node.get("name") or "订阅节点")
                country_hint = str(node.get("_country_hint") or "")
                node = {
                    **node,
                    "name": (
                        f"自动链式 | {country_hint} | {raw_name}"
                        if country_hint in {"TR", "VN", "TH", "PH"}
                        and not raw_name.startswith(country_hint + "-")
                        else f"自动链式 | {raw_name}"
                    ),
                    "country": country_hint or node.get("country", ""),
                    "dialer-proxy": _FRONT_GROUP,
                    "_subscription_group": "chain",
                }
                add_entry(chain, node)
            front.extend(name for name, _ in bridges)
            return {
                "bridges": bridges,
                "direct": direct,
                "chain": chain,
                "front": front,
                "country_by_name": country_by_name,
            }

        host = self._socks5_public_host()
        for slot in self._publishable_slots():
            name = f"{self._slot_label_country(slot)}_{slot['id']}_{slot['state']}"
            proxy = "\n".join((
                f"  - name: {json.dumps(name, ensure_ascii=False)}",
                "    type: socks5",
                f"    server: {host}",
                f"    port: {slot['proxy_port']}",
                f"    username: {json.dumps(self.server.username)}",
                f"    password: {json.dumps(self.server.password)}",
                "    udp: true",
            ))
            direct.append((name, proxy))
            country_by_name[name] = self._slot_country_code(slot)
        return {
            "bridges": bridges,
            "direct": direct,
            "chain": chain,
            "front": front,
            "country_by_name": country_by_name,
        }

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
                {
                    **slot,
                    "listener_ready": bool(self.server.manager.listener_ready(slot["id"])),
                    "egress_type": self._slot_egress_type_info(slot)[0],
                    "egress_type_label": self._slot_egress_type_info(slot)[1],
                    "detected_country": self._slot_country_code(slot),
                }
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
                {
                    **slot,
                    "listener_ready": bool(self.server.manager.listener_ready(slot["id"])),
                    "egress_type": self._slot_egress_type_info(slot)[0],
                    "egress_type_label": self._slot_egress_type_info(slot)[1],
                    "detected_country": self._slot_country_code(slot),
                }
                for slot in self.server.manager.snapshot()
            ]
            self._send_json(HTTPStatus.OK, {"exits": slots})
            return
        path = self.path.split("?", 1)[0]
        if path.startswith("/api/local/events"):
            self._send_json(HTTPStatus.OK, {"events": self.server.store.list_events(limit=200)})
            return
        if path == "/api/data":
            my_sub_token = self._ensure_admin_subscription_token()
            servers = self.server.store.list_vps()
            nodes = self.server.store.list_nodes()
            users = self.server.store.list_users()
            safe_users = [{**u, "password": ""} for u in users]
            site_title = self.server.store.get_setting("site_title", "")
            self._send_json(HTTPStatus.OK, {
                "mode": "local",
                "servers": servers,
                "nodes": nodes,
                "users": safe_users,
                "exits": [
                    {**slot, "detected_country": self._slot_country_code(slot)}
                    for slot in self.server.manager.snapshot()
                ],
                "siteTitle": site_title,
                "mySubUser": self.server.username,
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
            host = self._socks5_uri_host(self._socks5_public_host())
            lines = [
                f"socks5://{username}:{password}@{host}:{slot['proxy_port']}#{self._slot_label_country(slot)}_{slot['id']}_{slot['state']}"
                for slot in self._publishable_slots()
            ]
            self._send_text(HTTPStatus.OK, "\n".join(lines) + ("\n" if lines else ""))
            return
        if path in {"/socks5.txt", "/socks5-b64.txt", "/socks5.json"}:
            if self.server.store.get_setting("probe_subscription_protection") == "true":
                self._send_text(HTTPStatus.OK, "K-UI Local Multi-Exit")
                return
            if not self._subscription_user():
                self._send_json(HTTPStatus.NOT_FOUND, {"code": "not_found", "error": "subscription not found"})
                return
            if path == "/socks5.json":
                self._send_json(HTTPStatus.OK, self._socks5_json_export())
                return
            payload = "\n".join(self._socks5_subscription_links())
            payload = payload + ("\n" if payload else "")
            if path == "/socks5.txt":
                self._send_text(HTTPStatus.OK, payload)
            else:
                encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
                self._send_text(HTTPStatus.OK, encoded)
            return
        if path == "/api/sub":
            if self.server.store.get_setting("probe_subscription_protection") == "true":
                self._send_text(HTTPStatus.OK, "K-UI Local Multi-Exit")
                return
            user = self._subscription_user()
            if not user:
                self._send_json(HTTPStatus.NOT_FOUND, {"code": "not_found", "error": "subscription not found"})
                return
            links = [link for link in self._local_subscription_links() if link]
            thirdparty_nodes = self.server.store.list_enabled_thirdparty_nodes()
            links.extend(
                link
                for node in thirdparty_nodes
                if (link := self._subscription_link(node))
            )
            fmt = (self._query_param("format") or "").strip().lower()
            if fmt == "sing-box":
                singbox_nodes = list(self._local_subscription_nodes())
                singbox_nodes.extend(thirdparty_nodes)
                self._send_text(
                    HTTPStatus.OK,
                    generate_singbox_config(singbox_nodes),
                    content_type="application/json; charset=utf-8",
                )
                return
            if fmt in {"v2ray", "shadowrocket"}:
                encoded = base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")
                self._send_text(HTTPStatus.OK, encoded)
                return
            if fmt == "socks5":
                # Per-slot SOCKS5 links stay available even when the Reality
                # gateway shapes the default subscription as VLESS.
                socks_links = self._socks5_subscription_links()
                encoded = base64.b64encode("\n".join(socks_links).encode("utf-8")).decode("ascii")
                self._send_text(HTTPStatus.OK, encoded)
                return
            if fmt in {"clash", "clash-meta"}:
                groups = self._local_clash_proxies()
                used_names = {
                    _FRONT_GROUP,
                    _DIRECT_GROUP,
                    _CHAIN_GROUP,
                    _PROXY_GROUP,
                    "⚡ 自动选择",
                    "🔵 Google / Gemini",
                    "🤖 ChatGPT",
                    "🧠 Claude",
                    "🌐 其他流量",
                    "🇨🇳 中国流量",
                    "DIRECT",
                }
                used_names.update(
                    name
                    for group_name in ("bridges", "direct", "chain")
                    for name, _ in groups[group_name]
                )
                country_by_name = groups.setdefault("country_by_name", {})
                for node in thirdparty_nodes:
                    normalized = self._unique_clash_node(node, used_names)
                    if entry := self._clash_proxy(normalized):
                        groups["direct"].append(entry)
                        country_by_name[entry[0]] = self._subscription_country_code(normalized)

                all_entries = groups["bridges"] + groups["direct"] + groups["chain"]
                proxy_lines = [entry for _, entry in all_entries]

                def _list_yaml(items: list[str]) -> str:
                    return "\n".join(f"      - {json.dumps(n, ensure_ascii=False)}" for n in items)

                direct_names = [name for name, _ in groups["direct"]]
                chain_names = [name for name, _ in groups["chain"]]
                front_names = list(dict.fromkeys(groups.get("front", [])))

                country_group_names: list[str] = []
                country_group_lines: list[str] = []
                if fmt == "clash-meta":
                    country_buckets: dict[str, list[str]] = {}
                    for name, _ in all_entries:
                        cc = str(country_by_name.get(name, "OTHER") or "OTHER").upper()
                        if cc not in set(COUNTRY_PRESETS):
                            cc = "OTHER"
                        country_buckets.setdefault(cc, []).append(name)

                    for cc in sorted(country_buckets):
                        node_list = list(dict.fromkeys(country_buckets[cc]))
                        if not node_list:
                            continue
                        if cc != "OTHER":
                            flag = "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc)
                            g_name = f"{flag} {cc}"
                        else:
                            g_name = "🌐 其他节点"
                        while g_name in used_names or g_name in country_group_names:
                            g_name = f"{g_name} 组"
                        country_group_names.append(g_name)
                        country_group_lines.extend([
                            f"  - name: {json.dumps(g_name, ensure_ascii=False)}",
                            "    type: url-test",
                            "    url: https://www.gstatic.com/generate_204",
                            "    interval: 300",
                            "    tolerance: 50",
                            "    lazy: true",
                            "    proxies:",
                            _list_yaml(node_list),
                        ])

                direct_yaml = _list_yaml(direct_names) if direct_names else "      - DIRECT"
                chain_yaml = _list_yaml(chain_names) if chain_names else "      - DIRECT"
                front_yaml = _list_yaml(front_names) if front_names else "      - DIRECT"
                # The site groups expose PROXY plus the leaf nodes for manual
                # selection, while PROXY itself stays as the two-level entry.
                site_candidates = [_PROXY_GROUP, "⚡ 自动选择"] + direct_names + chain_names + country_group_names + ["DIRECT"]
                defined_names = {
                    _PROXY_GROUP,
                    _DIRECT_GROUP,
                    _CHAIN_GROUP,
                    _FRONT_GROUP,
                    "⚡ 自动选择",
                    "🔵 Google / Gemini",
                    "🤖 ChatGPT",
                    "🧠 Claude",
                    "🌐 其他流量",
                    "🇨🇳 中国流量",
                    "DIRECT",
                    *{name for name, _ in all_entries},
                    *country_group_names,
                }
                site_items = list(dict.fromkeys(item for item in site_candidates if item in defined_names))
                site_yaml = _list_yaml(site_items)
                group_lines = [
                    "  - name: " + _PROXY_GROUP,
                    "    type: select",
                    "    proxies:",
                    "      - " + json.dumps(_DIRECT_GROUP, ensure_ascii=False),
                    "      - " + json.dumps(_CHAIN_GROUP, ensure_ascii=False),
                    "  - name: " + _DIRECT_GROUP,
                    "    type: select",
                    "    proxies:",
                    direct_yaml,
                    "  - name: " + _CHAIN_GROUP,
                    "    type: select",
                    "    proxies:",
                    chain_yaml,
                    f"  - name: {_FRONT_GROUP}",
                    "    type: select",
                    "    proxies:",
                    front_yaml,
                ]
                group_lines.extend(country_group_lines)
                group_lines.extend([
                    "  - name: ⚡ 自动选择",
                    "    type: url-test",
                    "    hidden: true",
                    "    url: https://www.gstatic.com/generate_204",
                    "    interval: 300",
                    "    tolerance: 50",
                    "    lazy: true",
                    "    proxies:",
                    direct_yaml,
                    "  - name: 🔵 Google / Gemini",
                    "    type: select",
                    "    proxies:",
                    site_yaml,
                    "  - name: 🤖 ChatGPT",
                    "    type: select",
                    "    proxies:",
                    site_yaml,
                    "  - name: 🧠 Claude",
                    "    type: select",
                    "    proxies:",
                    site_yaml,
                    "  - name: 🌐 其他流量",
                    "    type: select",
                    "    proxies:",
                    site_yaml,
                    "  - name: 🇨🇳 中国流量",
                    "    type: select",
                    "    proxies:",
                    "      - DIRECT",
                    "      - 🌐 其他流量",
                ])
                rule_lines = ["  - DOMAIN-SUFFIX,alibb123.ccwu.cc,DIRECT"]
                rule_lines.extend(f"  - {rule},🤖 ChatGPT" for rule in _CHATGPT_RULES)
                rule_lines.extend(f"  - {rule},🧠 Claude" for rule in _CLAUDE_RULES)
                rule_lines.extend(f"  - {rule},🔵 Google / Gemini" for rule in _GEMINI_RULES)
                rule_lines.extend(f"  - {rule}" for rule in _LOCAL_DIRECT_RULES)
                rule_lines.extend((
                    "  - GEOSITE,CN,🇨🇳 中国流量",
                    "  - GEOIP,CN,🇨🇳 中国流量,no-resolve",
                    "  - MATCH,🌐 其他流量",
                ))
                body = (
                    "port: 7890\nsocks-port: 7891\nallow-lan: true\nmode: rule\n"
                    + ("proxies:\n" + "\n".join(proxy_lines) if proxy_lines else "proxies: []")
                    + "\nproxy-groups:\n"
                    + "\n".join(group_lines)
                    + "\nrules:\n"
                    + "\n".join(rule_lines)
                    + "\n"
                )
                self._send_text(HTTPStatus.OK, body, content_type="text/yaml; charset=utf-8")
                return
            encoded = base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")
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
                self._require_managed_slot(slot_id)
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
                set_additional_credentials([(self.server.username, new_password)])
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
                    self._require_managed_slot(server_id)
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
                self._require_managed_slot(connect_match.group(1))
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
                self._require_managed_slot(match.group(1))
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
                self._require_managed_slot(server_id)
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
