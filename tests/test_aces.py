from types import SimpleNamespace

from wraith.core.console import Console
from wraith.core.models import Severity


def test_findings_report_lists_vulns_worst_first_and_skips_info(capsys):
    findings = [
        SimpleNamespace(severity=Severity.INFO, title="Server banner disclosed", target="http://h/"),
        SimpleNamespace(severity=Severity.LOW, title="Missing header: X-Frame-Options", target="http://h/"),
        SimpleNamespace(severity=Severity.HIGH, title="SQL Injection in 'q'", target="http://h/search"),
    ]
    Console(color=False, banner=False).findings_report(findings)
    out = capsys.readouterr().out
    assert "SQL Injection in 'q'" in out
    assert "Missing header: X-Frame-Options" in out
    assert "Server banner disclosed" not in out          # Info is not a vulnerability
    assert out.index("SQL Injection") < out.index("Missing header")   # worst first


def test_findings_report_says_nothing_found_when_clean(capsys):
    Console(color=False, banner=False).findings_report(
        [SimpleNamespace(severity=Severity.INFO, title="banner", target="")]
    )
    assert "no vulnerabilities surfaced" in capsys.readouterr().out


def test_aces_renders_art_and_phrase(capsys):
    Console(color=False, banner=False).aces()
    out = capsys.readouterr().out
    assert "@" in out or "%" in out      # the wraith silhouette
    assert "aces" in out                 # the reveal phrase
    assert "A♠" in out and "A♣" in out   # the two black aces (half the dead man's hand)
    assert "Hickok" in out               # teases its companion that brings the eights


def test_banner_is_clean_wordmark(capsys):
    Console(color=False, banner=True).banner()
    out = capsys.readouterr().out
    assert "█" in out                    # block wordmark
    assert "♣" not in out and "♥" not in out   # no cards in the banner
    assert "WRAITH" not in out           # it's block art, not literal text
    assert "showdown mode" not in out    # the indicator only shows when the mode is on


def test_banner_flags_showdown_mode_when_active(capsys):
    from wraith.core.showdown import Showdown
    c = Console(color=False, banner=True)
    c.showdown = Showdown(c)
    c.banner()
    assert "showdown mode" in capsys.readouterr().out
