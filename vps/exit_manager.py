from __future__ import annotations

import json
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
from .openvpn_sources import fetch_all_openvpn_nodes
from .proxy_server import ProxyListener
from .routing import RouteManager
from .slot_config import is_connectivity_only_slot
from .store import LocalStore
from .vpngate import STREAM_URLS, NodePool, check_residential, detect_egress, probe_204, probe_targets


@dataclass
class SlotRuntime:
    process: subprocess.Popen | None = None
    listener: ProxyListener | None = None
    worker: threading.Thread | None = None
    retry_timer: threading.Timer | None = None
    stop: threading.Event | None = None
    lock: threading.RLock | None = None
    preferred_node_ip: str = ""


COUNTRY_FALLBACK_AFTER_FAILURES = 2
COUNTRY_SLOT_FAILURE_LIMIT = 5


class ExitManager:
    def __init__(
        self,
        store: LocalStore,
        *,
        routing: RouteManager | None = None,
        listener_factory=ProxyListener,
        workspace: Path | str = "/opt/kui-local",
        start_workers: bool = True,
        slot_count: int | None = None,
        dial_workers: int | None = None,
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
        all_slots = self.store.list_slots()
        if slot_count is None:
            slot_count = len(all_slots)
        try:
            slot_count = int(slot_count)
        except (TypeError, ValueError) as error:
            raise ValueError("slot_count must be a positive integer") from error
        if not 1 <= slot_count <= len(all_slots):
            raise ValueError(f"slot_count must be between 1 and {len(all_slots)}")
        self._managed_slot_ids = tuple(slot.id for slot in all_slots[:slot_count])
        self._runtimes = {
            slot_id: SlotRuntime(stop=threading.Event(), lock=threading.RLock())
            for slot_id in self._managed_slot_ids
        }
        if dial_workers is None:
            dial_workers = slot_count
        try:
            dial_workers = int(dial_workers)
        except (TypeError, ValueError) as error:
            raise ValueError("dial_workers must be a positive integer") from error
        if not 1 <= dial_workers <= slot_count:
            raise ValueError(f"dial_workers must be between 1 and {slot_count}")
        self._dial_slots = threading.BoundedSemaphore(dial_workers)
        self._selection_lock = threading.RLock()
        self._reserved_nodes: dict[str, str] = {}
        self._refresh_thread: threading.Thread | None = None

    @property
    def managed_slot_ids(self) -> tuple[str, ...]:
        return self._managed_slot_ids

    def is_managed_slot(self, slot_id: str) -> bool:
        return slot_id in self._runtimes

    def _require_managed_slot(self, slot_id: str) -> None:
        if not self.is_managed_slot(slot_id):
            raise KeyError(f"slot {slot_id} is outside the active runtime profile")

    def _managed_slots(self) -> list[ExitSlotSnapshot]:
        return [slot for slot in self.store.list_slots() if self.is_managed_slot(slot.id)]

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
        self._try_recover_auto_disabled_slots()
        if self.start_workers:
            self._refresh_thread = threading.Thread(target=self._refresh_loop, name="vpngate-refresh", daemon=True)
            self._refresh_thread.start()
        for slot in self._managed_slots():
            if slot.enabled:
                self.start_slot(slot.id)

    def refresh_nodes(self) -> int:
        report: dict[str, Any] = {}
        try:
            fresh_nodes, report = fetch_all_openvpn_nodes(timeout=60)
        except Exception as error:
            fresh_nodes = []
            self.store.record_event(None, "openvpn_refresh_failed", str(error))
        if fresh_nodes:
            try:
                self.store.replace_vpn_nodes(
                    fresh_nodes,
                    retention_days=int(os.environ.get("KUI_VPN_HISTORY_DAYS", "30")),
                )
            except Exception as error:
                self.store.record_event(None, "openvpn_cache_write_failed", str(error))
        cached_nodes = self.store.load_vpn_nodes()
        nodes = cached_nodes or fresh_nodes
        if nodes:
            self.node_pool.replace(nodes)
            if report:
                self.store.set_setting("openvpn_source_report", json.dumps(report, ensure_ascii=False, separators=(",", ":")))
            providers = report.get("providers", {}) if report else {}
            summary = ", ".join(
                f"{name}={detail.get('count', 0)}"
                for name, detail in providers.items()
                if isinstance(detail, dict) and not detail.get("metadata_only")
            )
            self.store.record_event(None, "openvpn_refreshed", f"loaded {len(nodes)} rolling nodes; {summary}")
            return len(nodes)
        self.store.record_event(None, "openvpn_refresh_empty", "all OpenVPN sources returned no usable nodes")
        return 0

    def _refresh_loop(self) -> None:
        """Periodically refresh node pool and try to recover disabled slots."""
        refresh_interval = 600
        recovery_interval = 60
        next_refresh = time.time() + refresh_interval
        while not self._shutdown.wait(recovery_interval):
            self._try_recover_auto_disabled_slots()
            if time.time() >= next_refresh:
                count = self.refresh_nodes()
                if count > 0:
                    self._try_recover_auto_disabled_slots()
                next_refresh = time.time() + refresh_interval

    def _try_recover_auto_disabled_slots(self) -> None:
        """Recover only managed slots that have an eligible unreserved node."""
        recoverable: list[str] = []
        with self._selection_lock:
            excluded = set(self._reserved_nodes.values())
            excluded.update(slot.entry_ip for slot in self._managed_slots() if slot.entry_ip)
            for slot in self._managed_slots():
                if slot.enabled or slot.disabled_reason != "automatic_failure_limit":
                    continue
                node = self._select_node(slot.country, excluded)
                if node is None and slot.country != "ANY":
                    node = self._select_node("ANY", excluded, excluded_countries={slot.country})
                if node is None:
                    continue
                recoverable.append(slot.id)
                excluded.add(str(node["ip"]))
        for slot_id in recoverable:
            updated = self.store.enable_slot(slot_id)
            self.store.record_event(slot_id, "auto_recovery", "eligible node became available")
            self.start_slot(updated.id)

    def active_entry_ips(self, excluding: str | None = None) -> set[str]:
        with self._selection_lock:
            reserved = {
                ip for slot_id, ip in self._reserved_nodes.items() if slot_id != excluding
            }
        return reserved | {
            slot.entry_ip
            for slot in self._managed_slots()
            if slot.id != excluding and slot.entry_ip
        }

    def reserved_entry_ips(self) -> set[str]:
        with self._selection_lock:
            return set(self._reserved_nodes.values())

    def start_slot(self, slot_id: str) -> ExitSlotSnapshot:
        self._require_managed_slot(slot_id)
        slot = self.store.get_slot(slot_id)
        if not slot.enabled:
            return slot
        runtime = self.runtime(slot_id)
        assert runtime.lock is not None and runtime.stop is not None
        with runtime.lock:
            if runtime.worker is not None:
                if runtime.worker.is_alive():
                    return slot
                runtime.worker = None
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

    def _terminate_process(self, runtime: SlotRuntime, process: Any | None = None) -> None:
        target = runtime.process if process is None else process
        if not target:
            return
        try:
            target.terminate()
            target.wait(timeout=3)
        except Exception:
            try:
                target.kill()
            except Exception:
                pass
        if runtime.process is target:
            runtime.process = None

    def stop_slot(self, slot_id: str, *, stop_listener: bool = True) -> None:
        self._require_managed_slot(slot_id)
        runtime = self.runtime(slot_id)
        assert runtime.lock is not None and runtime.stop is not None
        worker = None
        with runtime.lock:
            slot = self.store.get_slot(slot_id)
            runtime.stop.set()
            if slot.enabled:
                slot = self.store.update_slot(slot_id, enabled=True)
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
        self._require_managed_slot(slot_id)
        slot = self.store.get_slot(slot_id)
        if slot.entry_ip:
            self.node_pool.penalize(slot.entry_ip, 3000)
        self.stop_slot(slot_id, stop_listener=False)
        updated = self.store.get_slot(slot_id)
        if not updated.enabled:
            updated = self.store.update_slot(slot_id, enabled=True)
        self.store.record_event(slot_id, "redial", "manual redial requested")
        return self.start_slot(updated.id)

    def connect_slot(self, slot_id: str, node_ip: str) -> ExitSlotSnapshot:
        self._require_managed_slot(slot_id)
        slot = self.store.get_slot(slot_id)
        node = self.node_pool.get(node_ip, slot.country)
        if node is None:
            raise ValueError(f"node {node_ip} is not available for {slot.country}")
        self.stop_slot(slot_id, stop_listener=False)
        updated = self.store.get_slot(slot_id)
        if not updated.enabled:
            updated = self.store.update_slot(slot_id, enabled=True)
        runtime = self.runtime(slot_id)
        assert runtime.lock is not None
        with runtime.lock:
            runtime.preferred_node_ip = node_ip
        self.store.record_event(slot_id, "connect", f"manual candidate selected: {node_ip}")
        return self.start_slot(updated.id)

    def enable_slot(self, slot_id: str) -> ExitSlotSnapshot:
        self._require_managed_slot(slot_id)
        current = self.store.get_slot(slot_id)
        if current.enabled and current.state in {"connecting", "ready"}:
            return current
        slot = self.store.enable_slot(slot_id)
        return self.start_slot(slot.id)

    def disable_slot(self, slot_id: str) -> ExitSlotSnapshot:
        self._require_managed_slot(slot_id)
        self.stop_slot(slot_id)
        slot = self.store.update_slot(slot_id, enabled=False)
        self.store.record_event(slot_id, "disabled", "slot disabled manually")
        return slot

    def fail_slot(self, slot_id: str, error: str, *, max_failures: int = 3) -> ExitSlotSnapshot:
        self._require_managed_slot(slot_id)
        runtime = self.runtime(slot_id)
        assert runtime.lock is not None and runtime.stop is not None
        with runtime.lock:
            runtime.stop.set()
            slot = self.store.record_failure(slot_id, error, max_failures=max_failures)
            listener = runtime.listener
            runtime.listener = None
            process = runtime.process
        if listener:
            listener.stop()
        if process:
            self._terminate_process(runtime, process)
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
            if runtime.worker is not None and runtime.worker.is_alive():
                self._schedule_retry(slot_id, failed_generation, 1)
                return
            self.start_slot(slot_id)

    def _handle_connection_failure(
        self,
        slot_id: str,
        generation: int,
        error: str,
        endpoint_ip: str = "",
    ) -> ExitSlotSnapshot:
        runtime = self.runtime(slot_id)
        assert runtime.lock is not None
        with runtime.lock:
            current = self.store.get_slot(slot_id)
            if not current.enabled or current.generation != generation:
                return current
            max_failures = COUNTRY_SLOT_FAILURE_LIMIT if current.country != "ANY" else 3
            failed = self.fail_slot(slot_id, error, max_failures=max_failures)
        if endpoint_ip:
            self.node_pool.penalize(endpoint_ip, 10000)
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
        node_country = str(node.get("country") or "")
        fallback_matches = (
            bool(node.get("country_fallback"))
            and str(node.get("target_country") or "") == current.country
        )
        if (
            not current.enabled
            or current.generation != generation
            or (current.country not in {"ANY", node_country} and not fallback_matches)
        ):
            return False
        runtime = self.runtime(slot_id)
        assert runtime.lock is not None and runtime.stop is not None
        if self._shutdown.is_set() or runtime.stop.is_set():
            return False
        listener = self.listener_factory(
            current.id,
            "0.0.0.0",
            current.proxy_port,
            current.tunnel_name,
            current.mark,
        )
        try:
            listener.start(timeout=3)
            if self._shutdown.is_set() or runtime.stop.is_set():
                listener.stop()
                return False
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

    def _select_node(
        self,
        country: str,
        excluded: set[str],
        *,
        excluded_countries: set[str] | None = None,
    ) -> dict[str, Any] | None:
        skipped = set(excluded)
        excluded_countries = excluded_countries or set()
        while True:
            node = self.node_pool.select(country, skipped)
            if not node:
                return None
            if node.get("country") not in excluded_countries and self._node_eligible(node):
                return node
            skipped.add(node["ip"])

    def _reserve_node(
        self,
        slot_id: str,
        country: str,
        preferred_ip: str = "",
        *,
        allow_country_fallback: bool = False,
    ) -> dict[str, Any] | None:
        with self._selection_lock:
            self._reserved_nodes.pop(slot_id, None)
            excluded = self.active_entry_ips(excluding=slot_id)
            node = self.node_pool.get(preferred_ip, country) if preferred_ip else None
            if node is not None and (node["ip"] in excluded or not self._node_eligible(node)):
                node = None
            fallback = False
            if node is None and preferred_ip:
                node = self._select_node(country, excluded)
            elif node is None and country != "ANY" and allow_country_fallback:
                node = self._select_node("ANY", excluded, excluded_countries={country})
                fallback = node is not None
                if node is None:
                    node = self._select_node(country, excluded)
            elif node is None:
                node = self._select_node(country, excluded)
                if node is None and country != "ANY":
                    node = self._select_node("ANY", excluded, excluded_countries={country})
                    fallback = node is not None
            if node:
                node.pop("country_fallback", None)
                node.pop("target_country", None)
                if fallback:
                    node["country_fallback"] = True
                    node["target_country"] = country
                self._reserved_nodes[slot_id] = str(node["ip"])
            return node

    def _release_node(self, slot_id: str) -> None:
        with self._selection_lock:
            self._reserved_nodes.pop(slot_id, None)

    def _node_auth_file(self, slot: ExitSlotSnapshot, node: dict[str, Any]) -> Path:
        username = str(node.get("username", ""))
        password = str(node.get("password", ""))
        if not username and not password:
            return self.auth_file
        path = self.workspace / f"auth-{slot.id}.txt"
        self._write_runtime_file(path, f"{username}\n{password}\n")
        return path

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

    def _openvpn_command(
        self,
        slot: ExitSlotSnapshot,
        config_path: Path,
        auth_file: Path | None = None,
    ) -> list[str]:
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
            str(auth_file or self.auth_file),
            *self._openvpn_proxy_args(),
            "--connect-timeout",
            "10",
            "--connect-retry-max",
            "1",
            "--tun-mtu", "1400", "--mssfix", "1300", "--verb",
            "3",
            *cipher_args,
        ]

    def _worker_is_stale(
        self,
        slot_id: str,
        generation: int,
        stop_event: threading.Event,
    ) -> bool:
        if self._shutdown.is_set() or stop_event.is_set():
            return True
        current = self.store.get_slot(slot_id)
        return not current.enabled or current.generation != generation

    def _acquire_dial_slot(
        self,
        slot_id: str,
        generation: int,
        stop_event: threading.Event,
    ) -> bool:
        while not self._worker_is_stale(slot_id, generation, stop_event):
            if self._dial_slots.acquire(timeout=1):
                return True
        return False

    @staticmethod
    def _country_fallback_allowed(slot: ExitSlotSnapshot) -> bool:
        return slot.country != "ANY" and slot.failure_streak >= COUNTRY_FALLBACK_AFTER_FAILURES

    def _connect_worker(self, slot_id: str, generation: int) -> None:
        self._require_managed_slot(slot_id)
        slot = self.store.get_slot(slot_id)
        runtime = self.runtime(slot_id)
        assert runtime.lock is not None and runtime.stop is not None
        stop_event = runtime.stop
        endpoint_ip = ""
        process: Any | None = None
        try:
            if not self._acquire_dial_slot(slot_id, generation, stop_event):
                return
            try:
                with runtime.lock:
                    preferred_ip = runtime.preferred_node_ip
                    runtime.preferred_node_ip = ""
                node = self._reserve_node(
                    slot_id,
                    slot.country,
                    preferred_ip,
                    allow_country_fallback=self._country_fallback_allowed(slot),
                )
                if not node:
                    raise RuntimeError(f"no OpenVPN node for {slot.country}; distribution={self.node_pool.counts()}")
                if node.get("country_fallback"):
                    self.store.record_event(
                        slot_id,
                        "country_fallback",
                        f"preferred {slot.country} unavailable; using {node.get('country', 'ANY')}",
                    )
                endpoint_ip = str(node["ip"])
                config_path = self.config_dir / f"{slot_id}.ovpn"
                log_path = self.workspace / f"{slot_id}.log"
                self._write_runtime_file(config_path, node["config"])
                self._prepare_runtime_log(log_path)
                if self._worker_is_stale(slot_id, generation, stop_event):
                    return
                gateway, external_interface = self._default_route(self._run)
                if self._worker_is_stale(slot_id, generation, stop_event):
                    return
                with log_path.open("w") as log_file:
                    process = self._popen(
                        self._openvpn_command(slot, config_path, self._node_auth_file(slot, node)),
                        stdout=log_file,
                        stderr=subprocess.STDOUT,
                    )
                with runtime.lock:
                    process_started_after_stop = (
                        stop_event.is_set()
                        or self._shutdown.is_set()
                        or self.store.get_slot(slot_id).generation != generation
                    )
                    if not process_started_after_stop:
                        runtime.process = process
                if process_started_after_stop:
                    self._terminate_process(runtime, process)
                    return
                initialized = False
                for _ in range(25):
                    if stop_event.wait(1):
                        return
                    if self._worker_is_stale(slot_id, generation, stop_event):
                        return
                    if process.poll() is not None:
                        break
                    if "Initialization Sequence Completed" in log_path.read_text(errors="replace"):
                        initialized = True
                        break
                if not initialized:
                    raise RuntimeError("OpenVPN initialization failed")
                if self._worker_is_stale(slot_id, generation, stop_event):
                    return
                self.routing.install(slot, endpoint_ip, gateway, external_interface)
                if self._worker_is_stale(slot_id, generation, stop_event):
                    return
                # PATCH: source-based rule so tunnel traffic from this slot uses the tunnel table
                try:
                    import time as _time
                    import re as _re
                    _pref = str(slot.route_table + 5000)
                    for _ in range(10):
                        _d = self._run(["ip", "rule", "del", "pref", _pref], capture_output=True, text=True, check=False)
                        if _d.returncode != 0:
                            break
                    for _attempt in range(5):
                        _r = self._run(["ip", "-4", "addr", "show", slot.tunnel_name], capture_output=True, text=True, check=False)
                        _m = _re.search(r"inet (\d+\.\d+\.\d+\.\d+)", _r.stdout)
                        if _m:
                            self._run(["ip", "rule", "add", "from", _m.group(1), "lookup", str(slot.route_table), "pref", _pref], capture_output=True, text=True, check=False)
                            break
                        _time.sleep(1)
                except Exception:
                    pass
                egress_ip = detect_egress(slot.tunnel_name, self._run)
                if self._worker_is_stale(slot_id, generation, stop_event):
                    return
                if not egress_ip:
                    raise RuntimeError("real egress IP unavailable")
                if is_connectivity_only_slot(slot_id):
                    residential_result = {
                        "status": "skipped",
                        "validation_mode": "connectivity_only",
                        "is_residential": False,
                        "egress_type": "unverified",
                        "egress_type_label": "未验证IP",
                    }
                else:
                    _residential, residential_result = check_residential(egress_ip)
                    if self._worker_is_stale(slot_id, generation, stop_event):
                        return
                    status = str(residential_result.get("status", "")).lower()
                    egress_type = str(residential_result.get("egress_type", "unknown")).lower()
                    raw = residential_result.get("raw") if isinstance(residential_result.get("raw"), dict) else {}
                    geo = raw.get("geo") if isinstance(raw.get("geo"), dict) else {}
                    actual_country = str(geo.get("country_code") or "").upper()
                    if (
                        slot.country != "ANY"
                        and not node.get("country_fallback")
                        and re.fullmatch(r"[A-Z]{2}", actual_country)
                        and actual_country != slot.country
                    ):
                        self.node_pool.penalize(endpoint_ip, 20000)
                        raise RuntimeError(
                            f"egress country mismatch: target={slot.country}, actual={actual_country}"
                        )
                    allow_non_residential = os.environ.get("KUI_ALLOW_NON_RESIDENTIAL", "1").strip().lower() in {"1", "true", "yes", "on"}
                    if status != "checked" or egress_type == "unknown":
                        self.node_pool.penalize(endpoint_ip, 5000)
                        raise RuntimeError("TestISP check failed or unknown IP type")
                    if egress_type == "datacenter" and not allow_non_residential:
                        self.node_pool.penalize(endpoint_ip, 50000)
                        raise RuntimeError("exit classified as datacenter")
                probe_result = probe_targets(slot.tunnel_name, STREAM_URLS, self._run)
                if self._worker_is_stale(slot_id, generation, stop_event):
                    return
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
            finally:
                self._dial_slots.release()
            self._health_loop(slot_id, generation)
        except Exception as error:
            if not self._worker_is_stale(slot_id, generation, stop_event):
                self._handle_connection_failure(slot_id, generation, str(error), endpoint_ip)
        finally:
            current = self.store.get_slot(slot_id)
            owns_generation = current.generation == generation
            if owns_generation and current.state != "ready":
                if process is not None:
                    self._terminate_process(runtime, process)
                self._release_node(slot_id)
                self.routing.cleanup(slot)
            elif not owns_generation and process is not None:
                with runtime.lock:
                    owns_process = runtime.process is process
                if owns_process:
                    self._terminate_process(runtime, process)
            assert runtime.lock is not None
            with runtime.lock:
                if runtime.worker is threading.current_thread():
                    runtime.worker = None

    def _health_loop(
        self,
        slot_id: str,
        generation: int,
        stop_event: threading.Event | None = None,
    ) -> None:
        runtime = self.runtime(slot_id)
        if stop_event is None:
            assert runtime.stop is not None
            stop_event = runtime.stop
        failures = 0
        while True:
            if self._shutdown.is_set() or stop_event.wait(60):
                return
            current = self.store.get_slot(slot_id)
            if not current.enabled or current.generation != generation or runtime.process is None:
                return
            if runtime.process.poll() is not None:
                self._handle_connection_failure(slot_id, generation, "OpenVPN process exited", current.entry_ip)
                return
            if not self.routing.is_installed(current):
                self._handle_connection_failure(slot_id, generation, "policy route disappeared", current.entry_ip)
                return
            if probe_204(current.tunnel_name, self._run):
                failures = 0
                continue
            failures += 1
            if failures >= 2:
                error = "HTTP 204 probe failed twice consecutively"
                self.store.record_event(
                    slot_id,
                    "health_check_failed",
                    f"{error}, triggering retry",
                )
                # This loop runs inside the connection worker, so it must defer
                # redial through failure handling instead of restarting itself.
                self._handle_connection_failure(slot_id, generation, error, current.entry_ip)
                return

    def snapshot(self) -> list[dict[str, Any]]:
        return [slot.as_dict() for slot in self._managed_slots()]

    def list_nodes(self, country: str = "ANY") -> list[dict[str, Any]]:
        return self.node_pool.list_nodes(country)

    def shutdown(self) -> None:
        self._shutdown.set()
        for slot_id in self._managed_slot_ids:
            self.stop_slot(slot_id)
