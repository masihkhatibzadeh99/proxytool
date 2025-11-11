from __future__ import annotations

import argparse
import json
import sys
from typing import Iterable

from .config_loader import ConfigLoader, ConfigSyntaxError
from .config_model import Config
from .rules.base import Finding, Rule, RuleEngine, Severity
from .rules.builtin import builtin_rules


def main(argv: Iterable[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "check":
        return _handle_check(args)
    if args.command == "list-rules":
        return _handle_list_rules(args)
    parser.error("No command specified")
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="proxytool", description="Validate ProxySQL configuration files")
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser("check", help="Validate a ProxySQL config file")
    check.add_argument("path", help="Path to proxysql.cnf")
    check.add_argument("--format", choices=("text", "json"), default="text", help="Output format")
    check.add_argument("--fail-fast", action="store_true", help="Stop on first error")

    sub.add_parser("list-rules", help="List built-in validation rules")
    return parser


def _handle_check(args: argparse.Namespace) -> int:
    try:
        raw = ConfigLoader(args.path).load()
    except FileNotFoundError:
        print(f"File not found: {args.path}", file=sys.stderr)
        return 2
    except ConfigSyntaxError as exc:
        print(f"Syntax error: {exc}", file=sys.stderr)
        return 2

    config = Config(raw)
    engine = RuleEngine(_load_rules())
    findings = []
    for finding in engine.run(config):
        findings.append(finding)
        if args.fail_fast and finding.severity == Severity.ERROR:
            break

    has_errors = any(f.severity == Severity.ERROR for f in findings)

    if args.format == "json":
        _print_json(findings)
    else:
        _print_text(findings, args.path, has_errors)

    return 0 if not has_errors else 2


def _handle_list_rules(_: argparse.Namespace) -> int:
    for rule in _load_rules():
        print(f"{rule.slug}: {rule.description}")
    return 0


def _load_rules() -> list[Rule]:
    return builtin_rules()


def _print_json(findings: list[Finding]) -> None:
    payload = [
        {
            "rule": f.rule,
            "message": f.message,
            "severity": f.severity.value,
            "location": f.location,
        }
        for f in findings
    ]
    json.dump(payload, sys.stdout, indent=2)
    print()


def _print_text(findings: list[Finding], path: str, has_errors: bool) -> None:
    if not findings:
        print(f"OK: {path} is valid")
        return
    for finding in findings:
        location = f" ({finding.location})" if finding.location else ""
        print(f"[{finding.severity.value.upper()}] {finding.rule}: {finding.message}{location}")
    error_count = sum(1 for f in findings if f.severity == Severity.ERROR)
    warning_count = len(findings) - error_count
    if has_errors:
        print(f"FAILED: {error_count} error(s), {warning_count} warning(s)")
    else:
        print(f"OK: {path} is valid (warnings: {warning_count})")


if __name__ == "__main__":
    sys.exit(main())
