from wraith.core import report
from wraith.core.context import Workspace
from wraith.core.engine import PhaseResult
from wraith.core.models import Severity


def _workspace(tmp_path):
    ws = Workspace.create("example.com", base_dir=str(tmp_path))
    ws.add_service("1.2.3.4", 443, name="https")
    ws.add_endpoint("https://1.2.3.4/", status=200, server="nginx")
    ws.add_finding("Broken Access Control", Severity.HIGH, phase="access-control",
                   target="https://1.2.3.4/admin")
    return ws


def test_markdown_report(tmp_path):
    ws = _workspace(tmp_path)
    results = [PhaseResult("access-control", "done", 0.1, 1)]
    text = report.write_markdown(ws, results).read_text()
    assert "example.com" in text
    assert "Broken Access Control" in text


def test_html_report(tmp_path):
    ws = _workspace(tmp_path)
    results = [PhaseResult("access-control", "done", 0.1, 1)]
    html_text = report.write_html(ws, results).read_text()
    assert "example.com" in html_text
    assert "Broken Access Control" in html_text
    assert "<table" in html_text
    assert "High" in html_text


def test_markdown_escapes_pipes_in_cells(tmp_path):
    # a payload-bearing target ("...?host=1| sleep 3") must not break the table.
    ws = Workspace.create("example.com", base_dir=str(tmp_path))
    ws.add_finding("Command Injection in 'host'", Severity.CRITICAL, phase="injection",
                   target="http://h/ping?host=1| sleep 3")
    text = report.write_markdown(ws, []).read_text()
    row = next(ln for ln in text.splitlines() if "Command Injection" in ln and ln.startswith("|"))
    assert "\\|" in row                              # the payload's pipe was escaped
    assert row.count("|") - row.count("\\|") == 5    # still a clean four-column row


def test_json_report_carries_handoff_fields(tmp_path):
    import json
    ws = Workspace.create("h", base_dir=str(tmp_path))
    ws.add_finding("SQL Injection (error-based) in 'id'", Severity.HIGH, phase="injection",
                   target="http://h/p.php",
                   meta={"technique": "error-based", "dbms": "mysql", "param": "id", "method": "GET"})
    data = json.loads(report.write_json(ws).read_text())
    entry = next(e for e in data if "SQL Injection" in e["title"])
    assert entry["technique"] == "error-based" and entry["dbms"] == "mysql"
    assert entry["param"] == "id" and entry["method"] == "GET"    # injectable point, structured
