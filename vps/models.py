from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ExitSlotSnapshot:
    id: str
    country: str
    enabled: bool
    proxy_port: int
    tunnel_name: str
    route_table: int
    mark: int
    state: str = "idle"
    entry_ip: str = ""
    egress_ip: str = ""
    current_node: dict[str, Any] = field(default_factory=dict)
    check_result: dict[str, Any] = field(default_factory=dict)
    last_error: str = ""
    failure_streak: int = 0
    disabled_reason: str = ""
    generation: int = 0
    updated_at: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "country": self.country,
            "enabled": self.enabled,
            "proxy_port": self.proxy_port,
            "tunnel_name": self.tunnel_name,
            "route_table": self.route_table,
            "mark": self.mark,
            "state": self.state,
            "entry_ip": self.entry_ip,
            "egress_ip": self.egress_ip,
            "current_node": self.current_node,
            "check_result": self.check_result,
            "last_error": self.last_error,
            "failure_streak": self.failure_streak,
            "disabled_reason": self.disabled_reason,
            "generation": self.generation,
            "updated_at": self.updated_at,
        }
