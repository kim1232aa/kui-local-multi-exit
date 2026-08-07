from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
from typing import Any, Callable

from .store import LocalStore


REALM_SETTING_KEY = "realm_config"


class RealmUnavailable(RuntimeError):
    pass


def _endpoint(value: Any, *, listen: bool) -> str:
    text = str(value or "").strip()
    if text.startswith("["):
        match = re.fullmatch(r"\[([0-9A-Fa-f:]+)\]:(\d+)", text)
    else:
        match = re.fullmatch(r"([^\s:]+):(\d+)", text)
    if not match:
        raise ValueError("endpoint must be host:port")
    host, raw_port = match.groups()
    port = int(raw_port)
    if not 1 <= port <= 65535:
        raise ValueError("endpoint port must be between 1 and 65535")
    if listen and host not in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
        raise ValueError("listen endpoint must bind a local address")
    return text


class RealmManager:
    def __init__(
        self,
        store: LocalStore,
        *,
        binary: str | None = None,
        popen: Callable[..., Any] = subprocess.Popen,
        which: Callable[[str], str | None] = shutil.which,
    ):
        self.store = store
        self.binary = binary or which("realm")
        self._popen = popen
        self._process = None
        self._lock = threading.RLock()
        self._state = "stopped"
        self._error = ""

    def _config(self) -> dict[str, Any]:
        raw = self.store.get_setting(REALM_SETTING_KEY, "")
        if not raw:
            return {"listen": "", "remote": "", "use_udp": False}
        try:
            value = json.loads(raw)
        except (TypeError, ValueError):
            return {"listen": "", "remote": "", "use_udp": False}
        if not isinstance(value, dict):
            return {"listen": "", "remote": "", "use_udp": False}
        return {
            "listen": str(value.get("listen", "")),
            "remote": str(value.get("remote", "")),
            "use_udp": bool(value.get("use_udp", False)),
        }

    def configure(self, payload: dict[str, Any]) -> dict[str, Any]:
        config = {
            "listen": _endpoint(payload.get("listen"), listen=True),
            "remote": _endpoint(payload.get("remote"), listen=False),
            "use_udp": bool(payload.get("use_udp", False)),
        }
        self.store.set_setting(
            REALM_SETTING_KEY,
            json.dumps(config, ensure_ascii=False, separators=(",", ":")),
        )
        return config

    def status(self) -> dict[str, Any]:
        with self._lock:
            running = self._process is not None and self._process.poll() is None
            state = "running" if running else self._state
            available = bool(self.binary)
            if not available:
                state = "unavailable"
            return {
                **self._config(),
                "available": available,
                "running": running,
                "state": state,
                "error": self._error,
                "binary": self.binary or "",
            }

    def start(self) -> dict[str, Any]:
        with self._lock:
            if self._process is not None and self._process.poll() is None:
                return self.status()
            config = self._config()
            if not config["listen"] or not config["remote"]:
                raise ValueError("Realm listen and remote endpoints are required")
            if not self.binary:
                self._state = "unavailable"
                self._error = "realm binary is not installed"
                raise RealmUnavailable(self._error)
            command = [self.binary]
            if config["use_udp"]:
                command.append("-u")
            command.extend(("-l", config["listen"], "-r", config["remote"]))
            try:
                self._process = self._popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except OSError as error:
                self._process = None
                self._state = "failed"
                self._error = str(error)
                raise RuntimeError(f"failed to start Realm: {error}") from error
            if self._process.poll() is not None:
                self._process = None
                self._state = "failed"
                self._error = "realm process exited during startup"
                raise RuntimeError(self._error)
            self._state = "running"
            self._error = ""
            return self.status()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            process = self._process
            self._process = None
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            self._state = "stopped"
            self._error = ""
            return self.status()

    def restart(self) -> dict[str, Any]:
        self.stop()
        return self.start()
