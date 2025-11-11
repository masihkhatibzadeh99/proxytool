from pathlib import Path

from proxysql_cfgcheck.config_loader import ConfigLoader
from proxysql_cfgcheck.config_parser import parse_config


def test_parse_minimal_config(tmp_path: Path) -> None:
    fixture = Path("tests/data/minimal.cnf")
    data = fixture.read_text(encoding="utf-8")
    parsed = parse_config(data)

    assert parsed["datadir"] == "/var/lib/proxysql"
    assert parsed["admin_variables"]["admin_credentials"] == "admin:admin"
    assert parsed["mysql_servers"][0]["hostgroup"] == 0


def test_config_loader_reads_file(tmp_path: Path) -> None:
    path = tmp_path / "config.cnf"
    path.write_text("datadir=\"/tmp/proxy\"", encoding="utf-8")

    loader = ConfigLoader(path)
    parsed = loader.load()

    assert parsed["datadir"] == "/tmp/proxy"
