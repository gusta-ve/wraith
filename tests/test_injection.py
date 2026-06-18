from wraith.phases.injection import (
    REDIRECT_PARAMS,
    InjectionPhase,
    _echo_strip,
    _skip_param,
    boolean_blind_hit,
    core_sim,
    dbms_from_error,
    looks_like_sql_error,
    lfi_signature,
    relative_break,
    ssti_evaluated,
    ssti_payloads,
    timing_confirms,
    timing_hit,
    timing_too_noisy,
    xss_reflected,
)
from wraith.core.context import Workspace
from wraith.core.http import Response
from wraith.core.models import Severity
from wraith.core.web import Point


def test_sql_error_detection_covers_mssql_and_dotnet():
    assert looks_like_sql_error("Incorrect syntax near ''.") is True
    assert looks_like_sql_error("System.Data.SqlClient.SqlException: ...") is True
    assert looks_like_sql_error("Conversion failed when converting the varchar value") is True


def test_relative_break_is_calibrated_to_page_noise():
    # calm page (noise 1.0): the quote diverged hard (0.10) and a continuation
    # restored it (0.99) -> a real, swallowed-error break
    assert relative_break(1.0, 0.10, [0.10, 0.99]) is True
    # a *small* break on a calm page still counts (the fixed-0.9 oracle missed
    # exactly this — a tiny data tell in a big chrome page)
    assert relative_break(1.0, 0.91, [0.99]) is True
    # noisy page (noise 0.80): 0.91 is within the page's own slack -> not a break
    assert relative_break(0.80, 0.91, [0.99]) is False
    # broke but nothing restored near the baseline -> not the quote's doing
    assert relative_break(1.0, 0.10, [0.10, 0.12]) is False
    # no stable baseline -> can't judge
    assert relative_break(0.0, 0.10, [0.99]) is False


def test_echo_strip_removes_reflected_payloads():
    body = "<p>results for 1' AND '1'='1 here</p>"
    assert "1' AND '1'='1" not in _echo_strip(body, "1' AND '1'='1")
    # two pages that differ only by the reflected payload collapse to equal
    a = _echo_strip("hi 1' AND '1'='1 bye", "1' AND '1'='1")
    b = _echo_strip("hi 1' AND '1'='2 bye", "1' AND '1'='2")
    assert a == b


def test_point_priority_orders_data_params_before_flag_forms():
    q = Point("GET", "http://h/app", {"id": "1"}, "id", "query")
    form = Point("POST", "http://h/level", {"flag": "1"}, "flag", "body")
    wide = Point("POST", "http://h/c", {"a": "1", "b": "2", "c": "3"}, "a", "body")
    ordered = sorted([form, wide, q], key=InjectionPhase._point_priority)
    assert ordered[0] is q          # cheap GET query param first
    assert ordered[-1] is form      # flag-submission field last


def test_timing_too_noisy_guards_jittery_targets():
    assert timing_too_noisy([0.30, 0.31, 0.29, 0.30]) is False   # stable -> trust timing
    assert timing_too_noisy([0.9, 12.1, 0.95, 22.2]) is True      # wild swings (vulnweb-like)
    assert timing_too_noisy([5.0, 5.1, 5.2]) is True              # slow but steady -> still unreliable
    assert timing_too_noisy([]) is True


def test_skip_framework_and_csrf_params():
    for noise in ("__VIEWSTATE", "__EVENTVALIDATION", "__VIEWSTATEGENERATOR",
                  "csrfmiddlewaretoken", "authenticity_token", "__RequestVerificationToken"):
        assert _skip_param(noise) is True
    for real in ("id", "q", "username", "search", "file"):
        assert _skip_param(real) is False


def test_xss_reflected_requires_html_and_a_raw_breakout():
    payload = 'wxabcdef"><svg/onload=alert(1)>'
    html = {"content-type": "text/html; charset=utf-8"}
    json = {"content-type": "application/json"}
    # verbatim breakout in an HTML page -> real reflected XSS
    assert xss_reflected(Response(200, "u", f"hi {payload} bye", html), payload) is True
    # same reflection, but a JSON response the browser won't render as markup
    assert xss_reflected(Response(200, "u", f'{{"q":"{payload}"}}', json), payload) is False
    # the markup was encoded (no raw breakout) -> not reflected
    assert xss_reflected(Response(200, "u", "hi wxabcdef&quot;&gt; bye", html), payload) is False
    assert xss_reflected(None, payload) is False


def test_sql_error_detection():
    assert looks_like_sql_error("You have an error in your SQL syntax; near ''") is True
    assert looks_like_sql_error("Warning: mysqli_query()") is True
    assert looks_like_sql_error("ORA-00933: SQL command not properly ended") is True
    assert looks_like_sql_error("just a normal page") is False


def test_report_records_param_and_method():
    # every injection finding carries the injectable point, so the hickok handoff
    # is structured (no title string-parsing on the consumer side)
    ws = Workspace(target="h")
    pt = Point("POST", "http://h/login", {"u": "1"}, "u", "body")

    class _Console:
        def finding(self, *a):
            pass

    InjectionPhase()._report(ws, _Console(), "Reflected XSS", Severity.HIGH, pt, "x", "desc")
    assert ws.findings[0].meta["param"] == "u"
    assert ws.findings[0].meta["method"] == "POST"


def test_dbms_from_error_tags_the_backend():
    # the handoff to hickok needs the DBMS so it picks the right error-based payloads
    assert dbms_from_error("You have an error in your SQL syntax; check the manual") == "mysql"
    assert dbms_from_error("ORA-00933: SQL command not properly ended") == "oracle"
    assert dbms_from_error("Npgsql.PostgresException") == "postgresql"
    assert dbms_from_error("Incorrect syntax near ''.") == "mssql"
    assert dbms_from_error("sqlite3.OperationalError: near \"'\": syntax error") == "sqlite"
    assert dbms_from_error("just a normal page") == ""


def test_redirect_params():
    assert {"url", "next", "redirect"} <= REDIRECT_PARAMS


def test_lfi_signature():
    assert lfi_signature("root:x:0:0:root:/root:/bin/bash") == "/etc/passwd"
    assert lfi_signature("[fonts]\r\n[extensions]") == "windows/win.ini"
    assert lfi_signature("<html>nothing here</html>") is None


def test_ssti_evaluated_sees_product_past_a_reflected_payload():
    # the engine evaluated it: the product is present
    assert ssti_evaluated("Welcome 1763", 1763, "{{43*41}}") is True
    # merely reflected: only the payload came back, no product -> not a hit
    assert ssti_evaluated("Welcome {{43*41}}", 1763, "{{43*41}}") is False
    # the form re-renders the submitted payload *and* the engine evaluated it —
    # the product must still register even though the expression is echoed back
    # (the old `expr not in text` guard wrongly rejected this; the Cipher level)
    echoed = '<input value="{{43*41}}"><div>Hello, 1763!</div>'
    assert ssti_evaluated(echoed, 1763, "{{43*41}}") is True
    # HTML-escaped echo of the payload shouldn't leave a stray product either
    assert ssti_evaluated('value="{{43*41}}"', 1763, "{{43*41}}") is False
    # neither -> not a hit
    assert ssti_evaluated("Welcome guest", 1763, "{{43*41}}") is False


def test_ssti_payloads_cover_common_engines():
    payloads = dict((engine, p) for engine, p in ssti_payloads(7, 8))
    assert payloads["Jinja2/Twig"] == "{{7*8}}"
    assert payloads["ERB"] == "<%= 7*8 %>"
    assert payloads["Smarty/FreeMarker"] == "${7*8}"


def test_boolean_blind_hit():
    # TRUE/FALSE cores diverge (verdict flip, or rows vs no rows) -> injectable,
    # regardless of how small the tell is relative to the whole page
    assert boolean_blind_hit(1.0, 0.24) is True     # whispers: one-word verdict flip
    assert boolean_blind_hit(1.0, 0.0) is True      # first-blood: rows vs none
    # identical cores -> a non-injectable parameter -> no signal
    assert boolean_blind_hit(1.0, 1.0) is False
    assert boolean_blind_hit(1.0, 0.95) is False    # within the gate, not a flip
    # a noisy core (dynamic content where it reacts) demands a bigger divergence:
    # gate tracks the noise, so a probe no more divergent than the page itself
    # doesn't fire
    assert boolean_blind_hit(0.50, 0.60) is False


def test_core_sim_isolates_the_reacting_region():
    chrome_a = "<html>" + "x" * 2000 + "VERDICT-OK" + "y" * 2000 + "</html>"
    chrome_b = "<html>" + "x" * 2000 + "DENIED!!!!" + "y" * 2000 + "</html>"
    # whole-page similarity barely moves; core similarity exposes the flip
    assert core_sim(chrome_a, chrome_b) < 0.5
    # identical pages -> core empty -> perfectly similar
    assert core_sim(chrome_a, chrome_a) == 1.0


def test_timing_hit():
    assert timing_hit(0.2, 3.3, 3) is True       # ~3s slower than the 0.2s baseline
    assert timing_hit(0.2, 0.5, 3) is False       # barely slower -> not the sleep


def test_timing_confirms_requires_proportional_delay():
    # baseline 0.2s; sleep(3)->3.3s; sleep(6)->6.4s -> the delay tracks the sleep
    assert timing_confirms(0.2, 3.3, 3, 6.4, 6) is True
    # the longer sleep did NOT delay more -> random lag, not injection
    assert timing_confirms(0.2, 3.3, 3, 3.4, 6) is False
