#!/usr/bin/env python3
from __future__ import annotations

import base64
import hmac
import http.client
import ipaddress
import json
import os
import select
import socket
import ssl
import threading
import time
import urllib.parse
from typing import Any


def env_secret(name: str) -> str:
    encoded = os.environ.get(name + "_B64")
    if encoded:
        try:
            return base64.b64decode(encoded).decode("utf-8")
        except Exception:
            return ""
    return os.environ.get(name, "")


_PROXY_USER = env_secret("PROXY_USER")
_PROXY_PASS = env_secret("PROXY_PASS")
PROXY_USER = _PROXY_USER.encode()
PROXY_PASS = _PROXY_PASS.encode()
SO_MARK = getattr(socket, "SO_MARK", 36)
MAX_CONNECTIONS = max(16, int(os.environ.get("PROXY_MAX_CONNECTIONS", "256")))
RELAY_IDLE_TIMEOUT = max(60, int(os.environ.get("PROXY_IDLE_TIMEOUT", "600")))
CONNECTION_SLOTS = threading.BoundedSemaphore(MAX_CONNECTIONS)
DOH_HOST = "cloudflare-dns.com"
DOH_ADDRESSES = ("1.1.1.1", "1.0.0.1")
DNS_CACHE: dict[tuple[int, str], tuple[float, list[str]]] = {}
DNS_CACHE_LOCK = threading.RLock()


def set_credentials(user: str, passwd: str) -> None:
    global _PROXY_USER, _PROXY_PASS, PROXY_USER, PROXY_PASS
    _PROXY_USER = user
    _PROXY_PASS = passwd
    PROXY_USER = user.encode()
    PROXY_PASS = passwd.encode()


def set_enabled(enabled: bool) -> None:
    if not enabled:
        set_credentials("", "")


def parse_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Unexpected disconnect.")
        data += chunk
    return data


def parse_addr_port(raw: str):
    if not raw:
        return None
    if raw.startswith("["):
        index = raw.find("]")
        if index == -1:
            return None
        host = raw[1:index]
        port_text = raw[index + 2 :] if len(raw) > index + 1 and raw[index + 1] == ":" else ""
        return host, parse_int(port_text) or 443
    if ":" in raw:
        host, port_text = raw.rsplit(":", 1)
        return host, parse_int(port_text) or 443
    return raw, 443


def _query_doh(host: str, mark: int, timeout: float) -> tuple[list[str], int]:
    error = None
    for address in DOH_ADDRESSES:
        raw = None
        tls = None
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(timeout)
            raw.setsockopt(socket.SOL_SOCKET, SO_MARK, int(mark))
            raw.connect((address, 443))
            tls = ssl.create_default_context().wrap_socket(raw, server_hostname=DOH_HOST)
            path = "/dns-query?" + urllib.parse.urlencode({"name": host, "type": "A"})
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {DOH_HOST}\r\n"
                "Accept: application/dns-json\r\n"
                "Connection: close\r\n\r\n"
            )
            tls.sendall(request.encode("ascii"))
            response = http.client.HTTPResponse(tls)
            response.begin()
            if response.status != 200:
                raise OSError(f"DoH returned HTTP {response.status}")
            payload = json.loads(response.read().decode("utf-8"))
            answers = payload.get("Answer") or []
            addresses = []
            ttls = []
            for answer in answers:
                if answer.get("type") != 1:
                    continue
                try:
                    candidate = str(ipaddress.IPv4Address(answer.get("data", "")))
                except ipaddress.AddressValueError:
                    continue
                if candidate not in addresses:
                    addresses.append(candidate)
                ttls.append(parse_int(answer.get("TTL")))
            if addresses:
                valid_ttls = [ttl for ttl in ttls if ttl > 0]
                return addresses, min(valid_ttls) if valid_ttls else 60
            raise OSError(f"DoH returned no A records for {host}")
        except (OSError, ssl.SSLError, ValueError, json.JSONDecodeError) as caught:
            error = caught
        finally:
            try:
                (tls or raw).close()
            except (AttributeError, OSError):
                pass
    raise error or OSError(f"DoH failed for {host}")


def resolve_host(host: str, mark: int, timeout: float = 20) -> list[str]:
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    normalized = host.rstrip(".").lower()
    key = (int(mark), normalized)
    now = time.monotonic()
    with DNS_CACHE_LOCK:
        cached = DNS_CACHE.get(key)
        if cached and cached[0] > now:
            return list(cached[1])
    addresses, ttl = _query_doh(normalized, mark, timeout)
    with DNS_CACHE_LOCK:
        DNS_CACHE[key] = (now + max(5, min(ttl, 300)), list(addresses))
    return addresses


def create_connection(address: tuple[str, int], mark: int, timeout: float = 20) -> socket.socket:
    host, port = address
    error = None
    addresses = resolve_host(host, mark, timeout=timeout)
    for resolved in addresses:
        upstream = None
        parsed = ipaddress.ip_address(resolved)
        family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
        socket_address = (resolved, port, 0, 0) if family == socket.AF_INET6 else (resolved, port)
        try:
            upstream = socket.socket(family, socket.SOCK_STREAM)
            upstream.settimeout(timeout)
            upstream.setsockopt(socket.SOL_SOCKET, SO_MARK, int(mark))
            upstream.connect(socket_address)
            upstream.settimeout(None)
            return upstream
        except OSError as caught:
            error = caught
            if upstream:
                upstream.close()
    raise error or OSError("trusted DNS returned no reachable address")


def relay(left: socket.socket, right: socket.socket) -> None:
    def pump(source: socket.socket, target: socket.socket) -> None:
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    break
                target.sendall(data)
        except OSError:
            pass
        finally:
            try:
                target.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    upload = threading.Thread(target=pump, args=(left, right), daemon=True)
    upload.start()
    pump(right, left)
    upload.join(timeout=5)


class ProxyListener:
    def __init__(self, slot_id: str, host: str, port: int, interface: str, mark: int):
        self.slot_id = slot_id
        self.host = host
        self.port = port
        self.interface = interface
        self.mark = mark
        self.ready = threading.Event()
        self._stop = threading.Event()
        self._servers: list[socket.socket] = []
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self.serve_forever, name=f"proxy-{self.slot_id}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.ready.clear()
        for server in self._servers:
            try:
                server.close()
            except OSError:
                pass
        self._servers.clear()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=3)

    def _socks5_client(self, client: socket.socket) -> None:
        if not PROXY_USER or not PROXY_PASS:
            client.sendall(b"\x05\xff")
            return
        upstream = None
        try:
            methods_count = recv_exact(client, 1)[0]
            methods = recv_exact(client, methods_count)
            if b"\x02" not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x02")
            auth_request = recv_exact(client, 2)
            if auth_request[0] != 1:
                return
            username = recv_exact(client, auth_request[1])
            password = recv_exact(client, recv_exact(client, 1)[0])
            if not hmac.compare_digest(username, PROXY_USER) or not hmac.compare_digest(password, PROXY_PASS):
                client.sendall(b"\x01\x01")
                return
            client.sendall(b"\x01\x00")
            version, command, _, address_type = recv_exact(client, 4)
            if version != 5:
                return
            if command != 1:
                client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            if address_type == 1:
                host = socket.inet_ntoa(recv_exact(client, 4))
            elif address_type == 3:
                host = recv_exact(client, recv_exact(client, 1)[0]).decode("ascii")
            elif address_type == 4:
                host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
            else:
                return
            port = int.from_bytes(recv_exact(client, 2), "big")
            upstream = create_connection((host, port), self.mark, timeout=20)
            upstream.settimeout(RELAY_IDLE_TIMEOUT)
            client.settimeout(RELAY_IDLE_TIMEOUT)
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            relay(client, upstream)
        except (OSError, ValueError, ConnectionError, UnicodeError):
            pass
        finally:
            if upstream:
                upstream.close()

    def _http_client(self, client: socket.socket, first_byte: bytes) -> None:
        if not PROXY_USER or not PROXY_PASS:
            client.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n")
            return
        upstream = None
        try:
            data = first_byte
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = client.recv(4096)
                if not chunk:
                    break
                data += chunk
            head, rest = data.split(b"\r\n\r\n", 1)
            lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
            expected = "Basic " + base64.b64encode(PROXY_USER + b":" + PROXY_PASS).decode("ascii")
            authenticated = any(
                line.lower().startswith("proxy-authorization:")
                and hmac.compare_digest(line.split(":", 1)[1].strip(), expected)
                for line in lines[1:]
            )
            if not authenticated:
                client.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\n\r\n')
                return
            method, target, version = lines[0].split(" ", 2)
            if method.upper() == "CONNECT":
                parsed = parse_addr_port(target)
                if not parsed:
                    return
                upstream = create_connection(parsed, self.mark, timeout=20)
                upstream.settimeout(RELAY_IDLE_TIMEOUT)
                client.settimeout(RELAY_IDLE_TIMEOUT)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if rest:
                    upstream.sendall(rest)
                relay(client, upstream)
                return
            parsed_url = urllib.parse.urlsplit(target)
            if not parsed_url.hostname:
                return
            port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
            path = urllib.parse.urlunsplit(("", "", parsed_url.path or "/", parsed_url.query, ""))
            headers = [
                line
                for line in lines[1:]
                if not line.lower().startswith(("proxy-connection:", "connection:", "proxy-authorization:"))
            ]
            request = f"{method} {path} {version}\r\n" + "\r\n".join(headers) + "\r\nConnection: close\r\n\r\n"
            upstream = create_connection((parsed_url.hostname, port), self.mark, timeout=20)
            upstream.settimeout(RELAY_IDLE_TIMEOUT)
            client.settimeout(RELAY_IDLE_TIMEOUT)
            upstream.sendall(request.encode("iso-8859-1") + rest)
            relay(client, upstream)
        except (OSError, ValueError, ConnectionError, UnicodeError):
            pass
        finally:
            if upstream:
                upstream.close()

    def _proxy_client(self, client: socket.socket) -> None:
        try:
            client.settimeout(30)
            first = recv_exact(client, 1)
            if first == b"\x05":
                self._socks5_client(client)
            else:
                self._http_client(client, first)
        except (OSError, ConnectionError):
            pass
        finally:
            try:
                client.close()
            finally:
                CONNECTION_SLOTS.release()

    def serve_forever(self) -> None:
        servers: list[socket.socket] = []
        try:
            server4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server4.bind((self.host if ":" not in self.host else "0.0.0.0", self.port))
            server4.listen(256)
            server4.setblocking(False)
            servers.append(server4)
            if self.host in {"::", "0.0.0.0", ""}:
                try:
                    server6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    server6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    server6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    server6.bind(("::", self.port))
                    server6.listen(256)
                    server6.setblocking(False)
                    servers.append(server6)
                except OSError:
                    try:
                        server6.close()
                    except (NameError, OSError):
                        pass
            self._servers = servers
            self.ready.set()
            while not self._stop.is_set():
                try:
                    readable, _, _ = select.select(servers, [], [], 0.5)
                except (OSError, ValueError):
                    break
                for server in readable:
                    try:
                        client, _ = server.accept()
                    except OSError:
                        continue
                    if not CONNECTION_SLOTS.acquire(blocking=False):
                        client.close()
                        continue
                    try:
                        threading.Thread(target=self._proxy_client, args=(client,), daemon=True).start()
                    except Exception:
                        CONNECTION_SLOTS.release()
                        client.close()
        finally:
            self.ready.clear()
            for server in servers:
                try:
                    server.close()
                except OSError:
                    pass
            self._servers.clear()


def start_proxy_server(host: str, port: int, interface: str = "tun_main", mark: int = 101) -> None:
    listener = ProxyListener("legacy", host, port, interface, mark)
    listener.serve_forever()
