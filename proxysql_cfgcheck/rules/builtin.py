from __future__ import annotations

from pathlib import PurePosixPath
from typing import Iterable

from ..config_model import Config
from .base import Finding, Rule, Severity


class RequiredBlocksRule(Rule):
    slug = "required_blocks"
    description = "Ensure essential ProxySQL blocks are present"

    def __init__(self, required: Iterable[str] | None = None) -> None:
        self.required = tuple(required or ("admin_variables", "mysql_variables", "mysql_servers"))

    def check(self, config: Config) -> Iterable[Finding]:
        for name in config.missing_blocks(*self.required):
            yield Finding(rule=self.slug, message=f"Missing required block '{name}'", severity=self.severity)


class AdminCredentialsRule(Rule):
    slug = "admin_credentials"
    description = "Validate admin credentials and listener configuration"

    def check(self, config: Config) -> Iterable[Finding]:
        admin_block = config.get_block("admin_variables")
        creds = admin_block.get("admin_credentials")
        if not isinstance(creds, str) or ":" not in creds:
            yield Finding(rule=self.slug, message="admin_variables.admin_credentials must be set as 'user:password'")
        mysql_ifaces = admin_block.get("mysql_ifaces")
        if isinstance(mysql_ifaces, str) and mysql_ifaces.strip():
            return
        yield Finding(rule=self.slug, message="admin_variables.mysql_ifaces should define at least one listener", severity=Severity.WARNING)


class MysqlServersRule(Rule):
    slug = "mysql_servers"
    description = "Check backend server definitions"

    def check(self, config: Config) -> Iterable[Finding]:
        servers = config.get_list("mysql_servers")
        if not servers:
            yield Finding(rule=self.slug, message="mysql_servers must define at least one hostgroup")
            return
        seen: set[tuple[str, int, int]] = set()
        for index, entry in enumerate(servers):
            prefix = f"mysql_servers[{index}]"
            if not isinstance(entry, dict):
                yield Finding(rule=self.slug, message=f"{prefix} must be an object")
                continue
            addr = entry.get("address")
            port = _coerce_int(entry.get("port"))
            hostgroup = _coerce_int(entry.get("hostgroup"))
            if not isinstance(addr, str) or not addr:
                yield Finding(rule=self.slug, message=f"{prefix}.address must be a non-empty string")
            if port is None or not (0 < port < 65536):
                yield Finding(rule=self.slug, message=f"{prefix}.port must be a valid TCP port")
            if hostgroup is None or hostgroup < 0:
                yield Finding(rule=self.slug, message=f"{prefix}.hostgroup must be a non-negative integer")
            max_conn = entry.get("max_connections")
            if max_conn is None:
                yield Finding(rule=self.slug, message=f"{prefix}.max_connections is recommended", severity=Severity.WARNING)
            key = (addr or "", port or -1, hostgroup or -1)
            if None not in (addr, port, hostgroup):
                if key in seen:
                    yield Finding(rule=self.slug, message=f"Duplicate mysql_server entry for {addr}:{port} in hostgroup {hostgroup}")
                seen.add(key)


class MysqlUsersRule(Rule):
    slug = "mysql_users"
    description = "Validate user definitions"

    def check(self, config: Config) -> Iterable[Finding]:
        users = config.get_list("mysql_users")
        hostgroups = config.hostgroups()
        for index, entry in enumerate(users):
            if not isinstance(entry, dict):
                yield Finding(rule=self.slug, message=f"mysql_users[{index}] must be an object")
                continue
            username = entry.get("username")
            password = entry.get("password")
            dflt_hg = _coerce_int(entry.get("default_hostgroup"))
            if not isinstance(username, str) or not username:
                yield Finding(rule=self.slug, message=f"mysql_users[{index}].username must be set")
            if not isinstance(password, str) or not password:
                yield Finding(rule=self.slug, message=f"mysql_users[{index}].password must be set")
            if dflt_hg is None:
                yield Finding(rule=self.slug, message=f"mysql_users[{index}].default_hostgroup must be an integer")
            elif hostgroups and dflt_hg not in hostgroups:
                yield Finding(rule=self.slug, message=f"mysql_users[{index}] references missing hostgroup {dflt_hg}")


class MysqlQueryRulesRule(Rule):
    slug = "mysql_query_rules"
    description = "Validate routing/query rules consistency"

    def check(self, config: Config) -> Iterable[Finding]:
        rules = config.get_list("mysql_query_rules")
        hostgroups = config.hostgroups()
        seen_ids: set[int] = set()
        for index, entry in enumerate(rules):
            if not isinstance(entry, dict):
                yield Finding(rule=self.slug, message=f"mysql_query_rules[{index}] must be an object")
                continue
            rule_id = _coerce_int(entry.get("rule_id"))
            if rule_id is None:
                yield Finding(rule=self.slug, message=f"mysql_query_rules[{index}].rule_id must be an integer")
            elif rule_id in seen_ids:
                yield Finding(rule=self.slug, message=f"Duplicate rule_id {rule_id} in mysql_query_rules")
            else:
                seen_ids.add(rule_id)
            dest = _coerce_int(entry.get("destination_hostgroup"))
            if dest is not None and hostgroups and dest not in hostgroups:
                yield Finding(rule=self.slug, message=f"mysql_query_rules[{index}] references missing hostgroup {dest}")
            if not entry.get("match_pattern"):
                yield Finding(rule=self.slug, message=f"mysql_query_rules[{index}].match_pattern should be defined", severity=Severity.WARNING)


class DatadirRule(Rule):
    slug = "datadir"
    description = "Validate datadir definition"
    severity = Severity.WARNING

    def check(self, config: Config) -> Iterable[Finding]:
        datadir = config.raw.get("datadir")
        if not isinstance(datadir, str) or not datadir.strip():
            yield Finding(rule=self.slug, message="datadir should be set to a writable path", severity=self.severity)
            return
        path = PurePosixPath(datadir)
        if not path.is_absolute():
            yield Finding(rule=self.slug, message="datadir should be an absolute path", severity=self.severity)


def builtin_rules() -> list[Rule]:
    return [
        RequiredBlocksRule(),
        AdminCredentialsRule(),
        MysqlServersRule(),
        MysqlUsersRule(),
        MysqlQueryRulesRule(),
        DatadirRule(),
    ]


def _coerce_int(value: object) -> int | None:
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
