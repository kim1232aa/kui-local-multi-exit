from __future__ import annotations

import re


LEGACY_SLOT_COUNT = 24
MAX_SLOT_COUNT = 34
FLEX_SLOT_START = LEGACY_SLOT_COUNT + 1
BASE_PROXY_PORT = 7920
MAX_PROXY_PORT = BASE_PROXY_PORT + MAX_SLOT_COUNT - 1
BASE_ROUTE_TABLE = 200


def slot_number(slot_id: str) -> int | None:
    match = re.fullmatch(r"exit-(\d+)", str(slot_id))
    return int(match.group(1)) if match else None


def is_valid_exit_slot_id(slot_id: str) -> bool:
    number = slot_number(slot_id)
    return number is not None and 1 <= number <= MAX_SLOT_COUNT


def is_connectivity_only_slot(slot_id: str) -> bool:
    number = slot_number(slot_id)
    return number is not None and FLEX_SLOT_START <= number <= MAX_SLOT_COUNT
