from wraith.core.console import THEMES, Console, _fit


def test_plain_when_color_disabled():
    c = Console(theme="crimson", color=False)
    assert c._c("\033[31m", "x") == "x"


def test_codes_when_color_enabled():
    c = Console(color=True)
    out = c._c("\033[31m", "x")
    assert out.startswith("\033[31m") and out.endswith("\033[0m")


def test_themes_available():
    assert {"crimson", "matrix", "ice", "amber", "mono"} <= set(THEMES)


def test_unknown_theme_falls_back():
    c = Console(theme="does-not-exist", color=False)
    assert c.theme == THEMES["crimson"]


def test_finding_and_summary_do_not_crash(capsys):
    c = Console(color=True, banner=False)
    c.finding("High", "Reflected XSS")
    c.severity_summary({"High": 2, "Info": 1})
    out = capsys.readouterr().out
    assert "HIGH" in out
    assert "High 2" in out


def test_fit_clips_to_width():
    assert _fit("hello", 10) == "hello"           # fits -> unchanged
    assert _fit("hello world", 7) == "hello …"    # clipped with an ellipsis
    assert _fit("x", 1) == "x"
    assert _fit("hello", 0) == ""


def test_spinner_never_wider_than_terminal(monkeypatch, capsys):
    # the bug: a long phase list wrapped and the redraw stacked copies. The
    # spinner line must stay within the terminal width (here a narrow 40 cols).
    import re as _re
    import sys as _sys

    monkeypatch.setenv("COLUMNS", "40")
    monkeypatch.setattr(_sys.stdout, "isatty", lambda: True)
    c = Console(color=False, banner=False)
    label = "working · " + " · ".join(
        ["content-discovery", "tech-detect", "vhost", "template-checks", "security-headers", "injection"])
    c.spinner("⣾", label)
    out = capsys.readouterr().out
    visible = _re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", out).replace("\r", "")
    assert len(visible) <= 39          # never wraps (width - 1)
    assert visible.endswith("…")       # it was clipped, not wrapped
