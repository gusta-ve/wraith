from wraith.core.http import Response
from wraith.phases import template_checks as tc


def _r(status=200, body="", headers=None):
    return Response(status, "http://h/", body, headers or {})


def test_status_matcher():
    assert tc.match_one({"type": "status", "status": [200, 301]}, _r(200)) is True
    assert tc.match_one({"type": "status", "status": [200]}, _r(404)) is False


def test_word_matcher_conditions():
    resp = _r(body="hello world foo")
    assert tc.match_one({"type": "word", "words": ["hello", "foo"], "condition": "and"}, resp) is True
    assert tc.match_one({"type": "word", "words": ["hello", "nope"], "condition": "and"}, resp) is False
    assert tc.match_one({"type": "word", "words": ["nope", "foo"], "condition": "or"}, resp) is True


def test_regex_matcher():
    resp = _r(body="DB_PASSWORD=secret")
    assert tc.match_one({"type": "regex", "regex": ["DB_(HOST|PASSWORD)"]}, resp) is True


def test_header_matcher():
    resp = _r(headers={"server": "Apache/2.4.41"})
    assert tc.match_one({"type": "header", "key": "server", "value": "apache"}, resp) is True
    assert tc.match_one({"type": "header", "key": "server", "value": "nginx"}, resp) is False


def test_evaluate_and_or():
    resp = _r(200, "Index of /")
    matchers = [{"type": "status", "status": [200]},
                {"type": "word", "words": ["Index of /"]}]
    assert tc.evaluate(matchers, "and", resp) is True
    assert tc.evaluate(matchers, "and", _r(404, "Index of /")) is False


def test_builtin_templates_are_valid():
    templates = tc.load_templates(tc.BUILTIN_DIR)
    assert len(templates) >= 5
    for t in templates:
        assert t.get("id") and t.get("info", {}).get("severity")
        assert t.get("requests")


def test_bad_matcher_skips_one_template_without_killing_the_phase(tmp_path, monkeypatch):
    import asyncio

    from wraith.core.context import Workspace

    async def fake_fetch(url, **kw):
        return Response(200, url, "anything", {})

    monkeypatch.setattr(tc, "fetch", fake_fetch)

    class _C:                       # a console that only needs warn/finding here
        def warn(self, *a):
            pass

        def finding(self, *a):
            pass

    ws = Workspace.create("h", base_dir=str(tmp_path))
    broken = {"id": "broken", "info": {"name": "broken", "severity": "high"},
              "requests": [{"path": "/", "matchers": [{"type": "regex", "regex": ["("]}]}]}
    # the unbalanced regex raises re.error mid-evaluate; the phase must swallow it
    asyncio.run(tc.TemplateChecksPhase()._run_template(ws, _C(), "http://h", broken))
    assert ws.findings == []        # no crash, and no bogus finding
