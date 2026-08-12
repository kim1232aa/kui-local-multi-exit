from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .models import ExitSlotSnapshot


DEFAULT_COUNTRIES = (
    "JP", "JP", "JP", "JP",
    "KR", "KR", "KR", "KR",
    "US", "US", "CA", "CA",
    "GB", "GB", "DE", "DE",
    "FR", "FR", "RU", "RU",
    "TH", "TH", "ANY", "ANY",
)
VALID_STATES = {"idle", "starting", "connecting", "ready", "degraded", "failed", "disabled"}


class LocalStore:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._lock = threading.RLock()

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self, slot_count: int = len(DEFAULT_COUNTRIES)) -> None:
        try:
            slot_count = int(slot_count)
        except (TypeError, ValueError) as error:
            raise ValueError(f"slot_count must be between 1 and {len(DEFAULT_COUNTRIES)}") from error
        if not 1 <= slot_count <= len(DEFAULT_COUNTRIES):
            raise ValueError(f"slot_count must be between 1 and {len(DEFAULT_COUNTRIES)}")
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._connect() as db:
            db.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS exit_slots (
                    id TEXT PRIMARY KEY,
                    country TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    proxy_port INTEGER NOT NULL UNIQUE,
                    tunnel_name TEXT NOT NULL UNIQUE,
                    route_table INTEGER NOT NULL UNIQUE,
                    mark INTEGER NOT NULL UNIQUE,
                    state TEXT NOT NULL DEFAULT 'idle',
                    entry_ip TEXT NOT NULL DEFAULT '',
                    egress_ip TEXT NOT NULL DEFAULT '',
                    current_node TEXT NOT NULL DEFAULT '{}',
                    check_result TEXT NOT NULL DEFAULT '{}',
                    last_error TEXT NOT NULL DEFAULT '',
                    failure_streak INTEGER NOT NULL DEFAULT 0,
                    disabled_reason TEXT NOT NULL DEFAULT '',
                    generation INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    slot_id TEXT,
                    kind TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS vps_list (
                    ip TEXT PRIMARY KEY,
                    name TEXT NOT NULL DEFAULT '',
                    os TEXT NOT NULL DEFAULT 'debian',
                    egress_mode TEXT NOT NULL DEFAULT '',
                    proxy_mode TEXT NOT NULL DEFAULT '',
                    proxy_categories TEXT NOT NULL DEFAULT '',
                    egress_revision INTEGER NOT NULL DEFAULT 0,
                    egress_status TEXT NOT NULL DEFAULT '',
                    egress_applied_mode TEXT NOT NULL DEFAULT '',
                    egress_applied_revision INTEGER NOT NULL DEFAULT 0,
                    egress_error TEXT NOT NULL DEFAULT '',
                    egress_ip TEXT NOT NULL DEFAULT '',
                    socks5_addr TEXT NOT NULL DEFAULT '',
                    socks5_port INTEGER NOT NULL DEFAULT 0,
                    socks5_user TEXT NOT NULL DEFAULT '',
                    socks5_pass TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS node_list (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    protocol TEXT NOT NULL DEFAULT '',
                    address TEXT NOT NULL DEFAULT '',
                    port INTEGER NOT NULL DEFAULT 0,
                    username TEXT NOT NULL DEFAULT '',
                    uuid TEXT NOT NULL DEFAULT '',
                    password TEXT NOT NULL DEFAULT '',
                    sni TEXT NOT NULL DEFAULT '',
                    private_key TEXT NOT NULL DEFAULT '',
                    public_key TEXT NOT NULL DEFAULT '',
                    short_id TEXT NOT NULL DEFAULT '',
                    flow TEXT NOT NULL DEFAULT '',
                    network TEXT NOT NULL DEFAULT 'tcp',
                    host TEXT NOT NULL DEFAULT '',
                    path TEXT NOT NULL DEFAULT '',
                    extra TEXT NOT NULL DEFAULT '',
                    relay_type TEXT NOT NULL DEFAULT '',
                    target_ip TEXT NOT NULL DEFAULT '',
                    target_port INTEGER NOT NULL DEFAULT 0,
                    target_id INTEGER NOT NULL DEFAULT 0,
                    enable INTEGER NOT NULL DEFAULT 1,
                    traffic_used INTEGER NOT NULL DEFAULT 0,
                    traffic_limit INTEGER NOT NULL DEFAULT 0,
                    expire_time INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS user_list (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL,
                    enable INTEGER NOT NULL DEFAULT 1,
                    traffic_used INTEGER NOT NULL DEFAULT 0,
                    traffic_limit INTEGER NOT NULL DEFAULT 0,
                    expire_time INTEGER NOT NULL DEFAULT 0,
                    sub_token TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS thirdparty_subs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    enable INTEGER NOT NULL DEFAULT 1,
                    created_at INTEGER NOT NULL,
                    last_fetched_at INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS thirdparty_nodes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subscription_id INTEGER NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    protocol TEXT NOT NULL,
                    address TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    uuid TEXT NOT NULL DEFAULT '',
                    password TEXT NOT NULL DEFAULT '',
                    sni TEXT NOT NULL DEFAULT '',
                    public_key TEXT NOT NULL DEFAULT '',
                    short_id TEXT NOT NULL DEFAULT '',
                    flow TEXT NOT NULL DEFAULT '',
                    network TEXT NOT NULL DEFAULT 'tcp',
                    host TEXT NOT NULL DEFAULT '',
                    path TEXT NOT NULL DEFAULT '',
                    extra TEXT NOT NULL DEFAULT '',
                    enable INTEGER NOT NULL DEFAULT 1,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY(subscription_id) REFERENCES thirdparty_subs(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS vpn_nodes (
                    ip TEXT PRIMARY KEY,
                    country TEXT NOT NULL,
                    ping INTEGER NOT NULL,
                    score INTEGER NOT NULL,
                    config TEXT NOT NULL,
                    harvested_at REAL NOT NULL,
                    penalty INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL,
                    source TEXT NOT NULL DEFAULT 'vpngate',
                    username TEXT NOT NULL DEFAULT '',
                    password TEXT NOT NULL DEFAULT '',
                    provider_id TEXT NOT NULL DEFAULT '',
                    first_seen_at INTEGER NOT NULL DEFAULT 0,
                    last_seen_at INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS check_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    slot_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    result TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                """
            )
            thirdparty_columns = {
                row["name"] for row in db.execute("PRAGMA table_info(thirdparty_subs)").fetchall()
            }
            if "last_fetched_at" not in thirdparty_columns:
                db.execute("ALTER TABLE thirdparty_subs ADD COLUMN last_fetched_at INTEGER NOT NULL DEFAULT 0")
            migrations = {
                "vps_list": {
                    "proxy_mode": "TEXT NOT NULL DEFAULT ''",
                    "proxy_categories": "TEXT NOT NULL DEFAULT ''",
                    "egress_revision": "INTEGER NOT NULL DEFAULT 0",
                    "egress_status": "TEXT NOT NULL DEFAULT ''",
                    "egress_applied_mode": "TEXT NOT NULL DEFAULT ''",
                    "egress_applied_revision": "INTEGER NOT NULL DEFAULT 0",
                    "egress_error": "TEXT NOT NULL DEFAULT ''",
                    "egress_ip": "TEXT NOT NULL DEFAULT ''",
                },
                "node_list": {
                    "address": "TEXT NOT NULL DEFAULT ''",
                    "port": "INTEGER NOT NULL DEFAULT 0",
                    "username": "TEXT NOT NULL DEFAULT ''",
                    "uuid": "TEXT NOT NULL DEFAULT ''",
                    "password": "TEXT NOT NULL DEFAULT ''",
                    "sni": "TEXT NOT NULL DEFAULT ''",
                    "private_key": "TEXT NOT NULL DEFAULT ''",
                    "public_key": "TEXT NOT NULL DEFAULT ''",
                    "short_id": "TEXT NOT NULL DEFAULT ''",
                    "flow": "TEXT NOT NULL DEFAULT ''",
                    "network": "TEXT NOT NULL DEFAULT 'tcp'",
                    "host": "TEXT NOT NULL DEFAULT ''",
                    "path": "TEXT NOT NULL DEFAULT ''",
                    "extra": "TEXT NOT NULL DEFAULT ''",
                    "relay_type": "TEXT NOT NULL DEFAULT ''",
                    "target_ip": "TEXT NOT NULL DEFAULT ''",
                    "target_port": "INTEGER NOT NULL DEFAULT 0",
                    "target_id": "INTEGER NOT NULL DEFAULT 0",
                },
                "vpn_nodes": {
                    "source": "TEXT NOT NULL DEFAULT 'vpngate'",
                    "username": "TEXT NOT NULL DEFAULT ''",
                    "password": "TEXT NOT NULL DEFAULT ''",
                    "provider_id": "TEXT NOT NULL DEFAULT ''",
                    "first_seen_at": "INTEGER NOT NULL DEFAULT 0",
                    "last_seen_at": "INTEGER NOT NULL DEFAULT 0",
                },
            }
            for table, definitions in migrations.items():
                existing = {row["name"] for row in db.execute(f"PRAGMA table_info({table})").fetchall()}
                for name, definition in definitions.items():
                    if name not in existing:
                        db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
            now = int(time.time())
            for index, country in enumerate(DEFAULT_COUNTRIES[:slot_count]):
                db.execute(
                    """
                    INSERT OR IGNORE INTO exit_slots
                    (id, country, enabled, proxy_port, tunnel_name, route_table, mark, updated_at)
                    VALUES (?, ?, 1, ?, ?, ?, ?, ?)
                    """,
                    (f"exit-{index + 1:02d}", country, 7920 + index, f"tun{index}", 200 + index, 200 + index, now),
                )

    @staticmethod
    def _row_to_slot(row: sqlite3.Row) -> ExitSlotSnapshot:
        return ExitSlotSnapshot(
            id=row["id"],
            country=row["country"],
            enabled=bool(row["enabled"]),
            proxy_port=row["proxy_port"],
            tunnel_name=row["tunnel_name"],
            route_table=row["route_table"],
            mark=row["mark"],
            state=row["state"],
            entry_ip=row["entry_ip"],
            egress_ip=row["egress_ip"],
            current_node=json.loads(row["current_node"] or "{}"),
            check_result=json.loads(row["check_result"] or "{}"),
            last_error=row["last_error"],
            failure_streak=row["failure_streak"],
            disabled_reason=row["disabled_reason"],
            generation=row["generation"],
            updated_at=row["updated_at"],
        )

    def list_slots(self) -> list[ExitSlotSnapshot]:
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT * FROM exit_slots ORDER BY id").fetchall()
        return [self._row_to_slot(row) for row in rows]

    def get_slot(self, slot_id: str) -> ExitSlotSnapshot:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM exit_slots WHERE id = ?", (slot_id,)).fetchone()
        if row is None:
            raise KeyError(slot_id)
        return self._row_to_slot(row)

    def validate_slot_update(
        self,
        slot_id: str,
        *,
        country: str | None,
        proxy_port: int | None,
        enabled: bool | None,
    ) -> ExitSlotSnapshot:
        current = self.get_slot(slot_id)
        next_country = current.country if country is None else str(country).upper()
        next_port = current.proxy_port if proxy_port is None else int(proxy_port)
        if not re.fullmatch(r"[A-Z]{2}|ANY", next_country):
            raise ValueError("country must be a two-letter code or ANY")
        if not 7920 <= next_port <= 7943:
            raise ValueError("proxy port must be between 7920 through 7943")
        with self._lock, self._connect() as db:
            row = db.execute(
                "SELECT id FROM exit_slots WHERE proxy_port = ? AND id <> ?",
                (next_port, slot_id),
            ).fetchone()
        if row is not None:
            raise ValueError(f"proxy port {next_port} is already used")
        return current

    def update_slot(
        self,
        slot_id: str,
        *,
        country: str | None = None,
        proxy_port: int | None = None,
        enabled: bool | None = None,
    ) -> ExitSlotSnapshot:
        current = self.validate_slot_update(
            slot_id,
            country=country,
            proxy_port=proxy_port,
            enabled=enabled,
        )
        next_country = current.country if country is None else str(country).upper()
        next_port = current.proxy_port if proxy_port is None else int(proxy_port)
        next_enabled = current.enabled if enabled is None else bool(enabled)
        next_state = current.state if next_enabled else "disabled"
        next_reason = current.disabled_reason if next_enabled else "manual"
        if next_enabled and not current.enabled:
            next_state = "idle"
            next_reason = ""
        now = int(time.time())
        try:
            with self._lock, self._connect() as db:
                db.execute(
                    """
                    UPDATE exit_slots
                    SET country = ?, proxy_port = ?, enabled = ?, state = ?, disabled_reason = ?,
                        generation = generation + 1, updated_at = ?
                    WHERE id = ?
                    """,
                    (next_country, next_port, int(next_enabled), next_state, next_reason, now, slot_id),
                )
        except sqlite3.IntegrityError as error:
            if "proxy_port" in str(error) or "UNIQUE" in str(error):
                raise ValueError(f"proxy port {next_port} is already used") from error
            raise
        return self.get_slot(slot_id)

    def record_failure(self, slot_id: str, error: str) -> ExitSlotSnapshot:
        current = self.get_slot(slot_id)
        failures = current.failure_streak + 1
        enabled = failures < 3
        state = "failed" if enabled else "disabled"
        reason = "" if enabled else "automatic_failure_limit"
        with self._lock, self._connect() as db:
            db.execute(
                """
                UPDATE exit_slots
                SET failure_streak = ?, last_error = ?, enabled = ?, state = ?, disabled_reason = ?,
                    entry_ip = '', egress_ip = '', current_node = '{}', check_result = '{}',
                    generation = generation + 1, updated_at = ?
                WHERE id = ?
                """,
                (failures, error[:1000], int(enabled), state, reason, int(time.time()), slot_id),
            )
        self.record_event(slot_id, "failure", error)
        return self.get_slot(slot_id)

    def enable_slot(self, slot_id: str) -> ExitSlotSnapshot:
        with self._lock, self._connect() as db:
            db.execute(
                """
                UPDATE exit_slots
                SET enabled = 1, state = 'idle', failure_streak = 0, disabled_reason = '',
                    last_error = '', generation = generation + 1, updated_at = ?
                WHERE id = ?
                """,
                (int(time.time()), slot_id),
            )
        self.record_event(slot_id, "enabled", "slot enabled manually")
        return self.get_slot(slot_id)

    @staticmethod
    def _runtime_assignments(values: dict[str, Any]) -> tuple[list[str], list[Any]]:
        allowed = {"state", "entry_ip", "egress_ip", "current_node", "check_result", "last_error", "failure_streak"}
        unknown = set(values) - allowed
        if unknown:
            raise ValueError(f"unsupported runtime fields: {', '.join(sorted(unknown))}")
        if "state" in values and values["state"] not in VALID_STATES:
            raise ValueError("invalid state")
        assignments: list[str] = []
        parameters: list[Any] = []
        for key, value in values.items():
            assignments.append(f"{key} = ?")
            parameters.append(json.dumps(value) if key in {"current_node", "check_result"} else value)
        assignments.append("updated_at = ?")
        parameters.append(int(time.time()))
        return assignments, parameters

    def set_runtime(self, slot_id: str, **values: Any) -> ExitSlotSnapshot:
        assignments, parameters = self._runtime_assignments(values)
        parameters.append(slot_id)
        with self._lock, self._connect() as db:
            db.execute(f"UPDATE exit_slots SET {', '.join(assignments)} WHERE id = ?", parameters)
        return self.get_slot(slot_id)

    def set_runtime_if_generation(
        self,
        slot_id: str,
        generation: int,
        **values: Any,
    ) -> ExitSlotSnapshot | None:
        assignments, parameters = self._runtime_assignments(values)
        parameters.extend((slot_id, int(generation)))
        with self._lock, self._connect() as db:
            cursor = db.execute(
                f"UPDATE exit_slots SET {', '.join(assignments)} WHERE id = ? AND generation = ?",
                parameters,
            )
            if cursor.rowcount != 1:
                return None
            row = db.execute("SELECT * FROM exit_slots WHERE id = ?", (slot_id,)).fetchone()
        return self._row_to_slot(row)

    def replace_vpn_nodes(self, nodes: list[dict[str, Any]], *, retention_days: int = 30) -> None:
        """Merge the latest provider snapshot into a rolling OpenVPN history pool."""
        now = int(time.time())
        cutoff = now - max(1, int(retention_days)) * 86400
        with self._lock, self._connect() as db:
            for node in nodes:
                db.execute(
                    """
                    INSERT INTO vpn_nodes
                    (ip, country, ping, score, config, harvested_at, penalty, updated_at,
                     source, username, password, provider_id, first_seen_at, last_seen_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        country = excluded.country,
                        ping = excluded.ping,
                        score = excluded.score,
                        config = excluded.config,
                        harvested_at = excluded.harvested_at,
                        updated_at = excluded.updated_at,
                        source = excluded.source,
                        username = excluded.username,
                        password = excluded.password,
                        provider_id = excluded.provider_id,
                        last_seen_at = excluded.last_seen_at
                    """,
                    (
                        node["ip"],
                        node["country"],
                        int(node["ping"]),
                        int(node["score"]),
                        node["config"],
                        float(node["harvested_at"]),
                        int(node.get("penalty", 0)),
                        now,
                        str(node.get("source", "vpngate")),
                        str(node.get("username", "")),
                        str(node.get("password", "")),
                        str(node.get("provider_id", "")),
                        now,
                        now,
                    ),
                )
            db.execute("DELETE FROM vpn_nodes WHERE last_seen_at > 0 AND last_seen_at < ?", (cutoff,))

    def load_vpn_nodes(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute(
                "SELECT ip, country, ping, score, config, harvested_at, source, username, password, provider_id "
                "FROM vpn_nodes ORDER BY last_seen_at DESC, ip"
            ).fetchall()
        return [dict(row) for row in rows]

    def append_check_result(self, slot_id: str, generation: int, result: dict[str, Any]) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT INTO check_results (slot_id, generation, result, created_at) VALUES (?, ?, ?, ?)",
                (
                    slot_id,
                    int(generation),
                    json.dumps(result, ensure_ascii=False, separators=(",", ":")),
                    int(time.time()),
                ),
            )

    def list_check_results(
        self,
        *,
        slot_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(int(limit), 500))
        with self._lock, self._connect() as db:
            if slot_id is None:
                rows = db.execute(
                    "SELECT id, slot_id, generation, result, created_at "
                    "FROM check_results ORDER BY id DESC LIMIT ?",
                    (bounded_limit,),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT id, slot_id, generation, result, created_at "
                    "FROM check_results WHERE slot_id = ? ORDER BY id DESC LIMIT ?",
                    (slot_id, bounded_limit),
                ).fetchall()
        return [
            {**dict(row), "result": json.loads(row["result"] or "{}")}
            for row in rows
        ]

    def record_event(self, slot_id: str | None, kind: str, message: str) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT INTO events (slot_id, kind, message, created_at) VALUES (?, ?, ?, ?)",
                (slot_id, kind[:100], message[:2000], int(time.time())),
            )

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(int(limit), 500))
        with self._lock, self._connect() as db:
            rows = db.execute(
                "SELECT id, slot_id, kind, message, created_at FROM events ORDER BY id DESC LIMIT ?",
                (bounded_limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    # ---------- settings ----------

    def get_setting(self, key: str, default: str = "") -> str:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                (key, value, int(time.time())),
            )

    def delete_setting(self, key: str) -> None:
        with self._lock, self._connect() as db:
            db.execute("DELETE FROM settings WHERE key = ?", (key,))

    def get_all_settings(self) -> dict[str, str]:
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT key, value FROM settings").fetchall()
        return {row["key"]: row["value"] for row in rows}

    # ---------- vps ----------

    @staticmethod
    def _vps_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return dict(row) if row else None

    def list_vps(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT * FROM vps_list ORDER BY created_at").fetchall()
        return [self._vps_dict(row) for row in rows]

    def add_vps(
        self,
        ip: str,
        name: str = "",
        os_type: str = "debian",
        **fields: Any,
    ) -> dict[str, Any]:
        allowed = {
            "egress_mode", "proxy_mode", "proxy_categories", "egress_revision",
            "egress_status", "egress_applied_mode", "egress_applied_revision",
            "egress_error", "egress_ip", "socks5_addr", "socks5_port",
            "socks5_user", "socks5_pass",
        }
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"unsupported vps fields: {', '.join(sorted(unknown))}")
        values = {"ip": ip, "name": name, "os": os_type, **fields, "created_at": int(time.time())}
        columns = list(values)
        placeholders = ", ".join("?" for _ in columns)
        with self._lock, self._connect() as db:
            db.execute(
                f"INSERT INTO vps_list ({', '.join(columns)}) VALUES ({placeholders})",
                [values[column] for column in columns],
            )
        return self.get_vps(ip)

    def get_vps(self, ip: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM vps_list WHERE ip = ?", (ip,)).fetchone()
        return self._vps_dict(row)

    def update_vps(self, ip: str, **fields: Any) -> dict[str, Any]:
        allowed = {
            "name", "os", "egress_mode", "proxy_mode", "proxy_categories",
            "egress_revision", "egress_status", "egress_applied_mode",
            "egress_applied_revision", "egress_error", "egress_ip",
            "socks5_addr", "socks5_port", "socks5_user", "socks5_pass",
        }
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"unsupported vps fields: {', '.join(sorted(unknown))}")
        if not fields:
            raise ValueError("no fields to update")
        assignments = [f"{key} = ?" for key in fields]
        params = [*fields.values(), ip]
        with self._lock, self._connect() as db:
            db.execute(f"UPDATE vps_list SET {', '.join(assignments)} WHERE ip = ?", params)
        vps = self.get_vps(ip)
        if not vps:
            raise KeyError(ip)
        return vps

    def delete_vps(self, ip: str) -> None:
        with self._lock, self._connect() as db:
            db.execute("DELETE FROM vps_list WHERE ip = ?", (ip,))
            db.execute("DELETE FROM node_list WHERE ip = ?", (ip,))

    # ---------- nodes ----------

    @staticmethod
    def _node_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if not row:
            return None
        node = dict(row)
        node["vps_ip"] = node["ip"]
        return node

    def list_nodes(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT * FROM node_list ORDER BY created_at, id").fetchall()
        return [self._node_dict(row) for row in rows]

    def add_node(
        self,
        ip: str,
        name: str = "",
        protocol: str = "",
        traffic_limit: int = 0,
        expire_time: int = 0,
        *,
        node_id: int | None = None,
        **fields: Any,
    ) -> dict[str, Any]:
        allowed = {
            "address", "port", "username", "uuid", "password", "sni",
            "private_key", "public_key", "short_id", "flow", "network",
            "host", "path", "extra", "relay_type", "target_ip", "target_port",
            "target_id", "enable", "traffic_used",
        }
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"unsupported node fields: {', '.join(sorted(unknown))}")
        values = {
            "ip": ip,
            "name": name,
            "protocol": protocol,
            "traffic_limit": traffic_limit,
            "expire_time": expire_time,
            **fields,
            "created_at": int(time.time()),
        }
        if node_id is not None:
            values = {"id": int(node_id), **values}
        columns = list(values)
        placeholders = ", ".join("?" for _ in columns)
        with self._lock, self._connect() as db:
            cursor = db.execute(
                f"INSERT INTO node_list ({', '.join(columns)}) VALUES ({placeholders})",
                [values[column] for column in columns],
            )
            stored_id = int(node_id) if node_id is not None else int(cursor.lastrowid)
        return self.get_node(stored_id)

    def get_node(self, node_id: int) -> dict[str, Any] | None:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM node_list WHERE id = ?", (node_id,)).fetchone()
        return self._node_dict(row)

    def update_node(self, node_id: int, **fields: Any) -> dict[str, Any]:
        allowed = {
            "ip", "name", "protocol", "address", "port", "username", "uuid",
            "password", "sni", "private_key", "public_key", "short_id", "flow",
            "network", "host", "path", "extra", "relay_type", "target_ip",
            "target_port", "target_id", "enable", "traffic_used", "traffic_limit",
            "expire_time",
        }
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"unsupported node fields: {', '.join(sorted(unknown))}")
        if not fields:
            raise ValueError("no fields to update")
        assignments = [f"{key} = ?" for key in fields]
        params = [*fields.values(), node_id]
        with self._lock, self._connect() as db:
            db.execute(f"UPDATE node_list SET {', '.join(assignments)} WHERE id = ?", params)
        node = self.get_node(node_id)
        if not node:
            raise KeyError(node_id)
        return node

    def delete_node(self, node_id: int) -> None:
        with self._lock, self._connect() as db:
            db.execute("DELETE FROM node_list WHERE id = ?", (node_id,))

    # ---------- users ----------

    def list_users(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT * FROM user_list ORDER BY created_at").fetchall()
        return [dict(row) for row in rows]

    def add_user(self, username: str, password_hash: str, traffic_limit: int = 0, expire_time: int = 0) -> dict[str, Any]:
        import secrets as _secrets
        sub_token = _secrets.token_urlsafe(16)
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT INTO user_list (username, password, traffic_limit, expire_time, sub_token, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (username, password_hash, traffic_limit, expire_time, sub_token, int(time.time())),
            )
        return self.get_user(username)

    def get_user(self, username: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT * FROM user_list WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

    def update_user(self, username: str, **fields: Any) -> dict[str, Any]:
        allowed = {"password", "enable", "traffic_used", "traffic_limit", "expire_time", "sub_token"}
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"unsupported user fields: {', '.join(sorted(unknown))}")
        if not fields:
            raise ValueError("no fields to update")
        assignments = [f"{key} = ?" for key in fields]
        params = list(fields.values())
        params.append(username)
        with self._lock, self._connect() as db:
            db.execute(f"UPDATE user_list SET {', '.join(assignments)} WHERE username = ?", params)
        user = self.get_user(username)
        if not user:
            raise KeyError(username)
        return user

    def delete_user(self, username: str) -> None:
        with self._lock, self._connect() as db:
            db.execute("DELETE FROM user_list WHERE username = ?", (username,))

    # ---------- thirdparty ----------

    def list_thirdparty(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute(
                "SELECT s.id, s.name, s.url, s.enable AS is_enable, s.created_at AS added_at, "
                "s.last_fetched_at, COUNT(n.id) AS node_count "
                "FROM thirdparty_subs s LEFT JOIN thirdparty_nodes n ON n.subscription_id = s.id "
                "GROUP BY s.id ORDER BY s.created_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def add_thirdparty(self, name: str, url: str, nodes: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        now = int(time.time() * 1000)
        with self._lock, self._connect() as db:
            cursor = db.execute(
                "INSERT INTO thirdparty_subs (name, url, created_at, last_fetched_at) VALUES (?, ?, ?, ?)",
                (name, url, now, now),
            )
            tp_id = int(cursor.lastrowid)
            for node in nodes or []:
                db.execute(
                    "INSERT INTO thirdparty_nodes "
                    "(subscription_id, name, protocol, address, port, uuid, password, sni, public_key, short_id, flow, network, host, path, extra, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        tp_id, node.get("name", ""), node["protocol"], node["address"], int(node["port"]),
                        node.get("uuid", ""), node.get("password", ""), node.get("sni", ""),
                        node.get("public_key", ""), node.get("short_id", ""), node.get("flow", ""),
                        node.get("network", "tcp"), node.get("host", ""), node.get("path", ""),
                        node.get("extra", ""), now,
                    ),
                )
        return self.get_thirdparty(tp_id)

    def get_thirdparty(self, tp_id: int) -> dict[str, Any] | None:
        with self._lock, self._connect() as db:
            row = db.execute(
                "SELECT s.id, s.name, s.url, s.enable AS is_enable, s.created_at AS added_at, "
                "s.last_fetched_at, COUNT(n.id) AS node_count "
                "FROM thirdparty_subs s LEFT JOIN thirdparty_nodes n ON n.subscription_id = s.id "
                "WHERE s.id = ? GROUP BY s.id",
                (tp_id,),
            ).fetchone()
        return dict(row) if row else None

    def list_enabled_thirdparty_nodes(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute(
                "SELECT n.* FROM thirdparty_nodes n "
                "JOIN thirdparty_subs s ON s.id = n.subscription_id "
                "WHERE n.enable = 1 AND s.enable = 1 ORDER BY n.id"
            ).fetchall()
        return [dict(row) for row in rows]

    def update_thirdparty(self, tp_id: int, **fields: Any) -> dict[str, Any]:
        allowed = {"name", "url", "enable"}
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"unsupported thirdparty fields: {', '.join(sorted(unknown))}")
        if not fields:
            raise ValueError("no fields to update")
        assignments = [f"{key} = ?" for key in fields]
        params = list(fields.values())
        params.append(tp_id)
        with self._lock, self._connect() as db:
            db.execute(f"UPDATE thirdparty_subs SET {', '.join(assignments)} WHERE id = ?", params)
            if "enable" in fields:
                db.execute("UPDATE thirdparty_nodes SET enable = ? WHERE subscription_id = ?", (int(bool(fields["enable"])), tp_id))
        tp = self.get_thirdparty(tp_id)
        if not tp:
            raise KeyError(tp_id)
        return tp

    def delete_thirdparty(self, tp_id: int) -> None:
        with self._lock, self._connect() as db:
            db.execute("DELETE FROM thirdparty_nodes WHERE subscription_id = ?", (tp_id,))
            db.execute("DELETE FROM thirdparty_subs WHERE id = ?", (tp_id,))
