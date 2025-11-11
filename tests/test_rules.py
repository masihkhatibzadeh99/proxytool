from proxysql_cfgcheck.config_model import Config
from proxysql_cfgcheck.rules.base import RuleEngine, Severity
from proxysql_cfgcheck.rules.builtin import builtin_rules


def load_fixture() -> Config:
    from proxysql_cfgcheck.config_loader import ConfigLoader

    raw = ConfigLoader("tests/data/minimal.cnf").load()
    return Config(raw)


def test_builtin_rules_pass_on_fixture() -> None:
    config = load_fixture()
    engine = RuleEngine(builtin_rules())

    findings = list(engine.run(config))

    assert findings == []


def test_missing_admin_credentials_triggers_error() -> None:
    raw = {
        "mysql_servers": [{"address": "127.0.0.1", "port": 3306, "hostgroup": 0, "max_connections": 100}],
        "admin_variables": {},
        "mysql_variables": {},
    }
    config = Config(raw)
    engine = RuleEngine(builtin_rules())

    findings = list(engine.run(config))

    slugs = {f.rule for f in findings}
    assert "admin_credentials" in slugs
    assert any(f.severity == Severity.ERROR for f in findings)
