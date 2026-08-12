from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


GIB = 1024**3
MAX_SLOT_COUNT = 24
MAX_PROXY_CONNECTIONS = 4096
_UNLIMITED_CGROUP_LIMIT = 1 << 60


@dataclass(frozen=True)
class RuntimeProfile:
    slot_count: int
    dial_workers: int
    max_connections: int
    memory_bytes: int | None
    memory_source: str


def _read_memory_limit(path: Path) -> int | None:
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not raw or raw == "max":
        return None
    try:
        limit = int(raw)
    except ValueError:
        return None
    if limit <= 0 or limit >= _UNLIMITED_CGROUP_LIMIT:
        return None
    return limit


def _read_memtotal(path: Path) -> int | None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "MemTotal:":
            try:
                kib = int(fields[1])
            except ValueError:
                return None
            return kib * 1024 if kib > 0 else None
    return None


def detect_memory_limit(
    *,
    cgroup_root: str | Path = "/sys/fs/cgroup",
    meminfo_path: str | Path = "/proc/meminfo",
) -> tuple[int | None, str]:
    """Return the effective memory capacity visible to this process."""
    root = Path(cgroup_root)
    for source, path in (
        ("cgroup-v2", root / "memory.max"),
        ("cgroup-v1", root / "memory" / "memory.limit_in_bytes"),
        ("cgroup-v1", root / "memory.limit_in_bytes"),
    ):
        limit = _read_memory_limit(path)
        if limit is not None:
            return limit, source
    memory_bytes = _read_memtotal(Path(meminfo_path))
    if memory_bytes is not None:
        return memory_bytes, "meminfo"
    return None, "unknown"


def _auto_profile(memory_bytes: int | None) -> tuple[int, int, int]:
    if memory_bytes is None:
        return 4, 2, 64
    if memory_bytes <= int(1.5 * GIB):
        return 2, 1, 32
    if memory_bytes <= int(2.5 * GIB):
        return 4, 2, 64
    if memory_bytes <= 4 * GIB:
        return 8, 2, 128
    return 24, 4, 256


def _parse_override(
    environ: Mapping[str, str],
    name: str,
    *,
    minimum: int,
    maximum: int,
) -> int | None:
    raw = environ.get(name, "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def resolve_runtime_profile(
    *,
    environ: Mapping[str, str] | None = None,
    cgroup_root: str | Path = "/sys/fs/cgroup",
    meminfo_path: str | Path = "/proc/meminfo",
) -> RuntimeProfile:
    """Choose bounded defaults, with explicit environment overrides."""
    env = os.environ if environ is None else environ
    memory_bytes, memory_source = detect_memory_limit(
        cgroup_root=cgroup_root,
        meminfo_path=meminfo_path,
    )
    auto_slots, auto_workers, auto_connections = _auto_profile(memory_bytes)

    raw_slots = env.get("KUI_SLOT_COUNT", "").strip()
    if raw_slots.lower() == "auto":
        raw_slots = ""
    if raw_slots:
        try:
            slot_count = int(raw_slots)
        except ValueError as exc:
            raise ValueError(f"KUI_SLOT_COUNT must be an integer between 1 and {MAX_SLOT_COUNT}, or auto") from exc
        if not 1 <= slot_count <= MAX_SLOT_COUNT:
            raise ValueError(f"KUI_SLOT_COUNT must be between 1 and {MAX_SLOT_COUNT}")
    else:
        slot_count = auto_slots

    dial_workers = _parse_override(
        env,
        "KUI_DIAL_WORKERS",
        minimum=1,
        maximum=slot_count,
    )
    max_connections = _parse_override(
        env,
        "PROXY_MAX_CONNECTIONS",
        minimum=1,
        maximum=MAX_PROXY_CONNECTIONS,
    )
    return RuntimeProfile(
        slot_count=slot_count,
        dial_workers=auto_workers if dial_workers is None else dial_workers,
        max_connections=auto_connections if max_connections is None else max_connections,
        memory_bytes=memory_bytes,
        memory_source=memory_source,
    )
