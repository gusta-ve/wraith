from wraith.phases.injection import (
    REDIRECT_PARAMS,
    _skip_param,
    boolean_blind_hit,
    looks_like_sql_error,
    lfi_signature,
    ssti_evaluated,
    ssti_payloads,
    timing_confirms,
    timing_hit,
    timing_too_noisy,
)


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


def test_sql_error_detection():
    assert looks_like_sql_error("You have an error in your SQL syntax; near ''") is True
    assert looks_like_sql_error("Warning: mysqli_query()") is True
    assert looks_like_sql_error("ORA-00933: SQL command not properly ended") is True
    assert looks_like_sql_error("just a normal page") is False


def test_redirect_params():
    assert {"url", "next", "redirect"} <= REDIRECT_PARAMS


def test_lfi_signature():
    assert lfi_signature("root:x:0:0:root:/root:/bin/bash") == "/etc/passwd"
    assert lfi_signature("[fonts]\r\n[extensions]") == "windows/win.ini"
    assert lfi_signature("<html>nothing here</html>") is None


def test_ssti_evaluated_needs_product_without_expression():
    # the engine evaluated it: product present, expression gone
    assert ssti_evaluated("Welcome 1763", 1763, "43*41") is True
    # merely reflected: the expression came back verbatim -> not a hit
    assert ssti_evaluated("Welcome 43*41", 1763, "43*41") is False
    # neither -> not a hit
    assert ssti_evaluated("Welcome guest", 1763, "43*41") is False


def test_ssti_payloads_cover_common_engines():
    payloads = dict((engine, p) for engine, p in ssti_payloads(7, 8))
    assert payloads["Jinja2/Twig"] == "{{7*8}}"
    assert payloads["ERB"] == "<%= 7*8 %>"
    assert payloads["Smarty/FreeMarker"] == "${7*8}"


def test_boolean_blind_hit():
    # TRUE looks normal, FALSE diverges -> injectable
    assert boolean_blind_hit(0.99, 0.40) is True
    # both look the same as normal -> not a signal
    assert boolean_blind_hit(0.99, 0.99) is False
    # TRUE itself doesn't match normal -> noisy, not a clean signal
    assert boolean_blind_hit(0.80, 0.10) is False


def test_timing_hit():
    assert timing_hit(0.2, 3.3, 3) is True       # ~3s slower than the 0.2s baseline
    assert timing_hit(0.2, 0.5, 3) is False       # barely slower -> not the sleep


def test_timing_confirms_requires_proportional_delay():
    # baseline 0.2s; sleep(3)->3.3s; sleep(6)->6.4s -> the delay tracks the sleep
    assert timing_confirms(0.2, 3.3, 3, 6.4, 6) is True
    # the longer sleep did NOT delay more -> random lag, not injection
    assert timing_confirms(0.2, 3.3, 3, 3.4, 6) is False
