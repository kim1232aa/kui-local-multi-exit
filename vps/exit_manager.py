from __future__ import annotations

import os
import re
import socket
import subprocess
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import ExitSlotSnapshot
from .proxy_server import ProxyListener
from .routing import RouteManager
from .store import LocalStore
from .vpngate import STREAM_URLS, NodePool, check_residential, detect_egress, fetch_nodes, probe_targets


@dataclass
class SlotRuntime:
    process: subprocess.Popen | None = None
    listener: ProxyListener | None = None
    worker: threading.Thread | None = None
    retry_timer: threading.Timer | None = None
    stop: threading.Event | None = None
    lock: threading.RLock | None = None
    preferred_node_ip: str = ""


class ExitManager:
    def __init__(
        self,
        store: LocalStore,
        *,
        routing: RouteManager | None = None,
        listener_factory=ProxyListener,
        workspace: Path | str = "/opt/kui-local",
        start_workers: bool = True,
        run=subprocess.run,
        popen=subprocess.Popen,
        sleep=time.sleep,
    ):
        self.store = store
        self.routing = routing or RouteManager(run=run)
        self.listener_factory = listener_factory
        self.workspace = Path(workspace)
        self.config_dir = self.workspace / "configs"
        self.auth_file = self.workspace / "auth.txt"
        self.node_pool = NodePool()
        self.start_workers = start_workers
        self._run = run
        self._popen = popen
        self._sleep = sleep
        self._shutdown = threading.Event()
        self._runtimes = {
            slot.id: SlotRuntime(stop=threading.Event(), lock=threading.RLock())
            for slot in self.store.list_slots()
        }
        self._selection_lock = threading.RLock()
        self._reserved_nodes: dict[str, str] = {}
        self._refresh_thread: threading.Thread | None = None

    def runtime(self, slot_id: str) -> SlotRuntime:
        try:
            return self._runtimes[slot_id]
        except KeyError as error:
            raise KeyError(slot_id) from error

    def listener_ready(self, slot_id: str) -> bool:
        listener = self.runtime(slot_id).listener
        if listener is None:
            return False
        checker = getattr(listener, "is_ready", None)
        if callable(checker):
            return bool(checker())
        return bool(getattr(listener, "started", False) and not getattr(listener, "stopped", False))

    def initialize(self) -> None:
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        for slot in self.store.list_slots():
            self.routing.cleanup(slot)
            if slot.state not in {"idle", "disabled"}:
                self.store.set_runtime(slot.id, state="idle", entry_ip="", egress_ip="", current_node={}, check_result={})
        self.refresh_nodes()
        if self.start_workers:
            self._refresh_thread = threading.Thread(target=self._refresh_loop, name="vpngate-refresh", daemon=True)
            self._refresh_thread.start()
        for slot in self.store.list_slots():
            if slot.enabled:
                self.start_slot(slot.id)

    def refresh_nodes(self) -> int:
        try:
            nodes = fetch_nodes(timeout=60)
        except Exception as error:
            self.store.record_event(None, "vpngate_refresh_failed", str(error))
            return 0
        if nodes:
            self.node_pool.replace(nodes)
            self.store.record_event(None, "vpngate_refreshed", f"loaded {len(nodes)} nodes")
        return len(nodes)

    def _refresh_loop(self) -> None:
        while not self._shutdown.wait(600):
            count = self.refresh_nodes()
            # 节点刷新成功后，重启因自动失败限制而停用的槽位
            if count > 0:
                self._try_recover_auto_disabled_slots()

    def _try_recover_auto_disabled_slots(self) -> None:
        """尝试恢复因连续失败自动停用的槽位"""
        for slot in self.store.list_slots():
            if not slot.enabled and slot.disabled_reason == "automatic_failure_limit":
                # 重置失败计数并启用
                updated = self.store.enable_slot(slot.id)
                self.store.record_event(slot.id, "auto_recovery", "recovered after node pool refresh")
                self.start_slot(updated.id)

    def active_entry_ips(self, excluding: str | None = None) -> set[str]:
        with self._selection_lock:
            reserved = {
                ip for slot_id, ip in self._reserved_nodes.items() if slot_id != excluding
            }
        return reserved | {
            slot.entry_ip
            for slot in self.store.list_slots()
            if slot.id != excluding and slot.entry_ip
        }

    def reserved_entry_ips(self) -> set[str]:
        with self._selection_lock:
            return set(self._reserved_nodes.values())

    def start_slot(self, slot_id: str) -> ExitSlotSnapshot:
        slot = self.store.get_slot(slot_id)
        if not slot.enabled:
            return slot
        runtime = self.runtime(slot_id)
        assert runtime.lock is not None and runtime.stop is not None
        with runtime.lock:
            if runtime.worker is not None and runtime.worker.is_alive():
                return slot
            if runtime.retry_timer:
                runtime.retry_timer.cancel()
                runtime.retry_timer = None
            if runtime.listener:
                runtime.listener.stop()
                runtime.listener = None
            runtime.stop.clear()
            slot = self.store.set_runtime(slot_id, state="connecting", last_error="")
            if self.start_workers:
                generation = slot.generation
                runtime.worker = threading.Thread(
                    target=self._connect_worker,
                    args=(slot_id, generation),
                    name=f"connect-{slot_id}",
                    daemon=True,
                )
                runtime.worker.start()
        return slot

    def _terminate_process(self, runtime: SlotRuntime) -> None:
        process = runtime.process
        if not process:
            return
        try:
            process.terminate()
            process.wait(timeout=3)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass
        runtime.process = None

    def stop_slot(self, slot_id: str, *, stop_listener: bool = True) -> None:
        slot = self.store.get_slot(slot_id)
        runtime = self.runtime(slot_id)
        assert runtime.lock is not None and runtime.stop is not None
        worker = None
        with runtime.lock:
            runtime.stop.set()
            if runtime.retry_timer:
                runtime.retry_timer.cancel()
                runtime.retry_timer = None
            self._terminate_process(runtime)
            self._release_node(slot_id)
            self.routing.cleanup(slot)
            if stop_listener and runtime.listener:
                runtime.listener.stop()
                runtime.listener = None
            if slot.enabled:
                self.store.set_runtime(slot_id, state="idle", entry_ip="", egress_ip="", current_node={}, check_result={})
            worker = runtime.worker
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=2)
            if not worker.is_alive():
                with runtime.lock:
                    if runtime.worker is worker:
                        runtime.worker = None

    def redial_slot(self, slot_id: str) -> ExitSlotSnapshot:
        slot = self.store.get_slot(slot_id)
        if slot.entry_ip:
            self.node_pool.penalize(slot.entry_ip, 3000)
        self.stop_slot(slot_id, stop_listener=False)
        updated = self.store.update_slot(slot_id, enabled=True)
        self.store.record_event(slot_id, "redial", "manual redial requested")
        return self.start_slot(updated.id)

    def connect_slot(self, slot_id: str, node_ip: str) -> ExitSlotSnapshot:
        slot = self.store.get_slot(slot_id)
        node = self.node_pool.get(node_ip, slot.country)
        if node is None:
            raise ValueError(f"node {node_ip} is not available for {slot.country}")
        self.stop_slot(slot_id, stop_listener=False)
        updated = self.store.update_slot(slot_id, enabled=True)
        runtime = self.runtime(slot_id)
        assert runtime.lock is not None
        with runtime.lock:
            runtime.preferred_node_ip = node_ip
        self.store.record_event(slot_id, "connect", f"manual candidate selected: {node_ip}")
        return self.start_slot(updated.id)

    def enable_slot(self, slot_id: str) -> ExitSlotSnapshot:
        current = self.store.get_slot(slot_id)
        if current.enabled and current.state in {"connecting", "ready"}:
            return current
        slot = self.store.enable_slot(slot_id)
        return self.start_slot(slot.id)

    def disable_slot(self, slot_id: str) -> ExitSlotSnapshot:
        self.stop_slot(slot_id)
        slot = self.store.update_slot(slot_id, enabled=False)
        self.store.record_event(slot_id, "disabled", "slot disabled manually")
        return slot

    def fail_slot(self, slot_id: str, error: str) -> ExitSlotSnapshot:
        slot = self.store.record_failure(slot_id, error)
        runtime = self.runtime(slot_id)
        if runtime.listener:
            runtime.listener.stop()
            runtime.listener = None
        if runtime.process:
            self._terminate_process(runtime)
        self._release_node(slot_id)
        self.routing.cleanup(slot)
        if not slot.enabled:
            self.store.set_runtime(slot_id, state="disabled")
        return self.store.get_slot(slot_id)

    def _schedule_retry(self, slot_id: str, failed_generation: int, delay: int) -> None:
        runtime = self.runtime(slot_id)
        assert runtime.lock is not None
        with runtime.lock:
            if runtime.retry_timer:
                runtime.retry_timer.cancel()
            runtime.retry_timer = threading.Timer(
                delay,
                self._retry_failed_slot,
                args=(slot_id, failed_generation),
            )
            runtime.retry_timer.daemon = True
            runtime.retry_timer.start()

    def _retry_failed_slot(self, slot_id: str, failed_generation: int) -> None:
        runtime = self.runtime(slot_id)
        assert runtime.lock is not None
        with runtime.lock:
            runtime.retry_timer = None
            current = self.store.get_slot(slot_id)
            if (
                self._shutdown.is_set()
                or not current.enabled
                or current.generation != failed_generation
                or current.state != "failed"
            ):
                return
            self.start_slot(slot_id)

    def _handle_connection_failure(
        self,
        slot_id: str,
        generation: int,
        error: str,
        endpoint_ip: str = "",
    ) -> ExitSlotSnapshot:
        current = self.store.get_slot(slot_id)
        if not current.enabled or current.generation != generation:
            return current
        if endpoint_ip:
            self.node_pool.penalize(endpoint_ip, 10000)
        failed = self.fail_slot(slot_id, error)
        if failed.enabled and self.start_workers:
            delay = min(5 * (2 ** max(0, failed.failure_streak - 1)), 60)
            self._schedule_retry(slot_id, failed.generation, delay)
        return failed

    def record_failed_check(self, slot_id: str, generation: int, check_result: dict[str, Any]) -> bool:
        current = self.store.get_slot(slot_id)
        if not current.enabled or current.generation != generation:
            return False
        self.store.append_check_result(slot_id, generation, check_result)
        return True

    def commit_ready(
        self,
        slot_id: str,
        generation: int,
        *,
        entry_ip: str,
        egress_ip: str,
        node: dict[str, Any],
        check_result: dict[str, Any],
    ) -> bool:
        current = self.store.get_slot(slot_id)
        if not current.enabled or current.generation != generation or current.country not in {"ANY", node.get("country")}:
            return False
        runtime = self.runtime(slot_id)
        assert runtime.lock is not None
        listener = self.listener_factory(
            current.id,
            "0.0.0.0",
            current.proxy_port,
            current.tunnel_name,
            current.mark,
        )
        try:
            listener.start(timeout=3)
            self.store.append_check_result(slot_id, generation, check_result)
            updated = self.store.set_runtime_if_generation(
                slot_id,
                generation,
                state="ready",
                entry_ip=entry_ip,
                egress_ip=egress_ip,
                current_node=node,
                check_result=check_result,
                last_error="",
                failure_streak=0,
            )
            if updated is None:
                listener.stop()
                return False
            with runtime.lock:
                if runtime.listener:
                    runtime.listener.stop()
                runtime.listener = listener
        except Exception:
            listener.stop()
            with runtime.lock:
                if runtime.listener is listener:
                    runtime.listener = None
            raise
        self.store.record_event(slot_id, "connected", f"{entry_ip} -> {egress_ip}")
        return True

    @staticmethod
    def _default_route(run=subprocess.run) -> tuple[str, str]:
        result = run(["ip", "route", "show", "default"], capture_output=True, text=True, check=False)
        match = re.search(r"default via (\S+) dev (\S+)", result.stdout)
        if not match:
            raise RuntimeError("default route not found")
        return match.group(1), match.group(2)

    def _openvpn_proxy_args(self) -> list[str]:
        raw = os.environ.get("KUI_OPENVPN_SOCKS_PROXY", "").strip()
        if not raw:
            return []
        parsed = urllib.parse.urlsplit(raw)
        if parsed.scheme not in {"socks5", "socks5h"} or not parsed.hostname:
            raise ValueError("KUI_OPENVPN_SOCKS_PROXY must be a socks5 URL")
        args = ["--socks-proxy", parsed.hostname, str(parsed.port or 1080)]
        if parsed.username is not None or parsed.password is not None:
            # OpenVPN --socks-proxy 支持 authfile（两行 user/pass），对齐 aimili-vpngate 上游代理认证
            auth_file = self.workspace / "socks_auth.txt"
            auth_file.parent.mkdir(parents=True, exist_ok=True)
            auth_file.write_text(
                f"{urllib.parse.unquote(parsed.username or '')}\n{urllib.parse.unquote(parsed.password or '')}\n",
                encoding="utf-8",
            )
            auth_file.chmod(0o600)
            args.append(str(auth_file))
        return args

    def _node_eligible(self, node: dict[str, Any]) -> bool:
        return not self._openvpn_proxy_args() or bool(
            re.search(r"(?m)^proto\s+tcp(?:-client)?\b", node["config"])
        )

    def _select_node(self, country: str, excluded: set[str]) -> dict[str, Any] | None:
        skipped = set(excluded)
        while True:
            node = self.node_pool.select(country, skipped)
            if not node:
                return None
            if self._node_eligible(node):
                return node
            skipped.add(node["ip"])

    def _reserve_node(self, slot_id: str, country: str, preferred_ip: str = "") -> dict[str, Any] | None:
        with self._selection_lock:
            self._reserved_nodes.pop(slot_id, None)
            excluded = self.active_entry_ips(excluding=slot_id)
            node = self.node_pool.get(preferred_ip, country) if preferred_ip else None
            if node is not None and (node["ip"] in excluded or not self._node_eligible(node)):
                node = None
            if node is None:
                node = self._select_node(country, excluded)
            if node:
                self._reserved_nodes[slot_id] = str(node["ip"])
            return node

    def _release_node(self, slot_id: str) -> None:
        with self._selection_lock:
            self._reserved_nodes.pop(slot_id, None)

    @staticmethod
    def _write_runtime_file(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)

    @staticmethod
    def _prepare_runtime_log(path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(mode=0o600, exist_ok=True)
        path.chmod(0o600)

    def _openvpn_command(self, slot: ExitSlotSnapshot, config_path: Path) -> list[str]:
        version = self._run(["openvpn", "--version"], capture_output=True, text=True, check=False).stdout
        if "2.4" in version:
            cipher_args = ["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"]
        else:
            cipher_args = [
                "--data-ciphers",
                "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
                "--data-ciphers-fallback",
                "AES-128-CBC",
            ]
        return [
            "openvpn",
            "--config",
            str(config_path),
            "--dev",
            slot.tunnel_name,
            "--dev-type",
            "tun",
            "--nobind",
            "--route-nopull",
            "--pull-filter",
            "ignore",
            "route-ipv6",
            "--pull-filter",
            "ignore",
            "ifconfig-ipv6",
            "--auth-user-pass",
            str(self.auth_file),
            *self._openvpn_proxy_args(),
            "--connect-timeout",
            "5",
            "--connect-retry-max",
            "1",
            "--verb",
            "3",
            *cipher_args,
        ]

    def _connect_worker(self, slot_id: str, generation: int) -> None:
        slot = self.store.get_slot(slot_id)
        runtime = self.runtime(slot_id)
        endpoint_ip = ""
        try:
            preferred_ip = runtime.preferred_node_ip
            runtime.preferred_node_ip = ""
            node = self._reserve_node(slot_id, slot.country, preferred_ip)
            if not node:
                raise RuntimeError(f"no VPNGate node for {slot.country}; distribution={self.node_pool.counts()}")
            endpoint_ip = str(node["ip"])
            config_path = self.config_dir / f"{slot_id}.ovpn"
            log_path = self.workspace / f"{slot_id}.log"
            self._write_runtime_file(config_path, node["config"])
            self._prepare_runtime_log(log_path)
            gateway, external_interface = self._default_route(self._run)
            with log_path.open("w") as log_file:
                runtime.process = self._popen(
                    self._openvpn_command(slot, config_path),
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                )
            initialized = False
            for _ in range(20):
                assert runtime.stop is not None
                if runtime.stop.wait(1):
                    return
                if runtime.process.poll() is not None:
                    break
                if "Initialization Sequence Completed" in log_path.read_text(errors="replace"):
                    initialized = True
                    break
            if not initialized:
                raise RuntimeError("OpenVPN initialization failed")
            if self.store.get_slot(slot_id).generation != generation:
                return
            self.routing.install(slot, endpoint_ip, gateway, external_interface)
            egress_ip = detect_egress(slot.tunnel_name, self._run)
            if not egress_ip:
                raise RuntimeError("real egress IP unavailable")
            residential, residential_result = check_residential(egress_ip)
            if not residential:
                self.node_pool.penalize(endpoint_ip, 50000)
                raise RuntimeError("exit classified as datacenter")
            probe_result = probe_targets(slot.tunnel_name, STREAM_URLS, self._run)
            check_result = {"residential": residential_result, "targets": probe_result}
            if not probe_result["accepted"]:
                self.record_failed_check(slot_id, generation, check_result)
                self.node_pool.penalize(endpoint_ip, 3000)
                raise RuntimeError("target probes failed")
            if not self.commit_ready(
                slot_id,
                generation,
                entry_ip=endpoint_ip,
                egress_ip=egress_ip,
                node={key: value for key, value in node.items() if key != "config"},
                check_result=check_result,
            ):
                raise RuntimeError("slot configuration changed during dial")
            self._health_loop(slot_id, generation)
        except Exception as error:
            self._handle_connection_failure(slot_id, generation, str(error), endpoint_ip)
        finally:
            current = self.store.get_slot(slot_id)
            if current.state != "ready":
                self._terminate_process(runtime)
                self._release_node(slot_id)
                self.routing.cleanup(slot)
            assert runtime.lock is not None
            with runtime.lock:
                if runtime.worker is threading.current_thread():
                    runtime.worker = None

    def _health_loop(self, slot_id: str, generation: int) -> None:
        slot = self.store.get_slot(slot_id)
        runtime = self.runtime(slot_id)
        failures = 0
        while not self._shutdown.wait(15):
            current = self.store.get_slot(slot_id)
            if not current.enabled or current.generation != generation or runtime.process is None:
                return
            if runtime.process.poll() is not None:
                self._handle_connection_failure(slot_id, generation, "OpenVPN process exited", current.entry_ip)
                return
            if not self.routing.is_installed(current):
                self._handle_connection_failure(slot_id, generation, "policy route disappeared", current.entry_ip)
                return
            egress = detect_egress(slot.tunnel_name, self._run)
            if egress and egress == current.egress_ip:
                failures = 0
                continue
            failures += 1
            if failures >= 3:
                self._handle_connection_failure(
                    slot_id,
                    generation,
                    "exit health probe failed three times",
                    current.entry_ip,
                )
                return

    def snapshot(self) -> list[dict[str, Any]]:
        return [slot.as_dict() for slot in self.store.list_slots()]

    def list_nodes(self, country: str = "ANY") -> list[dict[str, Any]]:
        return self.node_pool.list_nodes(country)

    def shutdown(self) -> None:
        self._shutdown.set()
        for slot in self.store.list_slots():
            self.stop_slot(slot.id)
