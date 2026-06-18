from wraith.core.context import Workspace
from wraith.core.models import Severity


def test_dedupe(tmp_path):
    ws = Workspace.create("ex", base_dir=str(tmp_path))
    ws.add_host("1.1.1.1")
    ws.add_host("1.1.1.1")
    ws.add_service("1.1.1.1", 80)
    ws.add_service("1.1.1.1", 80)
    assert len(ws.hosts) == 1
    assert len(ws.services) == 1


def test_save_load_roundtrip(tmp_path):
    ws = Workspace.create("example.com", base_dir=str(tmp_path))
    ws.add_host("2.2.2.2", kind="ip", source="resolve")
    ws.add_service("2.2.2.2", 443, name="https")
    ws.add_endpoint("https://2.2.2.2/", status=200, server="nginx")
    ws.add_finding("IDOR", Severity.HIGH, phase="access-control", target="https://2.2.2.2/x")

    path = ws.save()
    loaded = Workspace.load(path)

    assert loaded.target == "example.com"
    assert loaded.hosts[0].value == "2.2.2.2"
    assert loaded.services[0].port == 443
    assert loaded.findings[0].severity == Severity.HIGH
    assert loaded.findings[0].severity.label == "High"


def test_finding_meta_survives_save_load(tmp_path):
    ws = Workspace.create("h", base_dir=str(tmp_path))
    ws.add_finding("SQL Injection (error-based) in 'id'", Severity.HIGH, phase="injection",
                   target="http://h/p.php", meta={"technique": "error-based", "dbms": "mysql"})
    ws.add_finding("Missing header", Severity.LOW, phase="security-headers")    # no meta
    loaded = Workspace.load(ws.save())
    assert loaded.findings[0].meta == {"technique": "error-based", "dbms": "mysql"}
    assert loaded.findings[1].meta == {}                                        # backward-compatible default
