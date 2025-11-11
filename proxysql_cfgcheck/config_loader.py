from __future__ import annotations

from pathlib import Path
from typing import Any

from .config_parser import ConfigSyntaxError, parse_config


class ConfigLoader:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> dict[str, Any]:
        text = self.path.read_text(encoding="utf-8")
        return parse_config(text)


__all__ = ["ConfigLoader", "ConfigSyntaxError"]
