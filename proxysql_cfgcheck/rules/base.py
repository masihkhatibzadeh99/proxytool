from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from ..config_model import Config


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(slots=True)
class Finding:
    rule: str
    message: str
    severity: Severity = Severity.ERROR
    location: str | None = None


class Rule:
    slug: str = "rule"
    description: str = ""
    severity: Severity = Severity.ERROR

    def check(self, config: Config) -> Iterable[Finding]:
        raise NotImplementedError


class RuleEngine:
    def __init__(self, rules: Iterable[Rule]):
        self.rules = list(rules)

    def run(self, config: Config) -> Iterable[Finding]:
        for rule in self.rules:
            yield from rule.check(config)
