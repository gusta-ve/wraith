from wraith.core.console import THEMES, Console


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
