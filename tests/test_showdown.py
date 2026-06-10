from types import SimpleNamespace

from wraith.core.console import Console
from wraith.core.models import Severity
from wraith.core.showdown import Showdown


def _f(severity, title, target="http://h/x", evidence="", phase="injection"):
    return SimpleNamespace(severity=severity, title=title, target=target,
                           evidence=evidence, phase=phase)


def test_live_finding_is_emphasised(capsys):
    c = Console(color=False, banner=False)
    Showdown(c).live_finding(c, "High", "Reflected XSS in 'q'")
    out = capsys.readouterr().out
    assert "HIGH" in out and "Reflected XSS in 'q'" in out
    assert "┃" in out                       # the showdown bar, not the plain [HIGH] tag


def test_receipts_show_the_evidence(capsys):
    c = Console(color=False, banner=False)
    Showdown(c)._receipts([_f(Severity.HIGH, "SQL Injection in 'id'", evidence="1' -> SQL error")])
    out = capsys.readouterr().out
    assert "SQL Injection in 'id'" in out
    assert "1' -> SQL error" in out         # the proof line


def test_verdict_reads_the_targets_hand(capsys):
    c = Console(color=False, banner=False)
    Showdown(c)._verdict([_f(Severity.HIGH, "x"), _f(Severity.LOW, "y")])
    out = capsys.readouterr().out
    assert "A♣" in out and "A♥" in out
    assert "1 High" in out and "1 Low" in out
    assert "never had the cards" in out


def test_verdict_on_a_clean_target(capsys):
    c = Console(color=False, banner=False)
    Showdown(c)._verdict([_f(Severity.INFO, "banner")])
    out = capsys.readouterr().out
    assert "busted hand" in out
    assert "empty table" in out


def test_kill_chain_follows_attack_order(capsys):
    c = Console(color=False, banner=False)
    findings = [
        _f(Severity.HIGH, "Broken Access Control at /admin", phase="access-control"),
        _f(Severity.HIGH, "Reflected XSS in 'q'", phase="injection"),
    ]
    Showdown(c)._kill_chain(findings)
    out = capsys.readouterr().out
    assert "input handling" in out and "authorization" in out
    assert out.index("input handling") < out.index("authorization")  # injection before access-control
