from __future__ import annotations

import subprocess
from collections.abc import Callable

from .models import ExitSlotSnapshot


class RouteManager:
    def __init__(self, run: Callable[..., object] = subprocess.run):
        self._run = run

    def _execute(self, command: list[str]) -> None:
        self._run(command, capture_output=True, text=True, check=False)

    def cleanup(self, slot: ExitSlotSnapshot) -> None:
        preference = slot.route_table
        self._execute(["ip", "rule", "del", "fwmark", str(slot.mark), "lookup", str(slot.route_table), "pref", str(preference)])
        self._execute(["ip", "route", "flush", "table", str(slot.route_table)])

    def install(
        self,
        slot: ExitSlotSnapshot,
        endpoint_ip: str,
        gateway: str,
        external_interface: str,
    ) -> None:
        self.cleanup(slot)
        table = str(slot.route_table)
        self._execute(["ip", "route", "add", f"{endpoint_ip}/32", "via", gateway, "dev", external_interface, "table", table])
        self._execute(["ip", "route", "add", "default", "dev", slot.tunnel_name, "table", table])
        self._execute(
            [
                "ip",
                "rule",
                "add",
                "fwmark",
                str(slot.mark),
                "lookup",
                table,
                "pref",
                str(slot.route_table),
            ]
        )
