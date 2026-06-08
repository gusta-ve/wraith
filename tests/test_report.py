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
