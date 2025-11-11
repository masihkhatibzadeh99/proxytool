from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

@dataclass(slots=True)
class Config:
    raw: dict[str, Any]

    def get_block(self, name: str) -> dict[str, Any]:
        value = self.raw.get(name)
        return value if isinstance(value, dict) else {}

    def get_list(self, name: str) -> list[Any]:
        value = self.raw.get(name)
        return value if isinstance(value, list) else []

    def missing_blocks(self, *names: str) -> Iterable[str]:
        for name in names:
            if name not in self.raw:
                yield name

    def hostgroups(self) -> set[int]:
        groups: set[int] = set()
        for entry in self.get_list("mysql_servers"):
            hg = _coerce_int(entry.get("hostgroup")) if isinstance(entry, dict) else None
            if hg is not None:
                groups.add(hg)
        return groups

    def users(self) -> list[dict[str, Any]]:
        return [entry for entry in self.get_list("mysql_users") if isinstance(entry, dict)]

    def query_rules(self) -> list[dict[str, Any]]:
        return [entry for entry in self.get_list("mysql_query_rules") if isinstance(entry, dict)]


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None
