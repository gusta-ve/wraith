from wraith.core.http import Response
from wraith.phases.vhost import VhostPhase as V


def _r(status, body):
    return Response(status, "http://h", body, {})


def test_different_status_is_distinct():
    assert V._distinct(_r(301, ""), _r(200, "x" * 100)) is True


def test_different_body_is_distinct():
    assert V._distinct(_r(200, "B" * 500), _r(200, "A" * 500)) is True


def test_identical_is_not_distinct():
    base = _r(200, "same content here " * 20)
    assert V._distinct(_r(200, "same content here " * 20), base) is False


def test_misdirected_request_is_ignored():
    assert V._distinct(_r(421, "y" * 999), _r(200, "x" * 100)) is False


def test_same_as_junk_host_is_catch_all():
    # A candidate that looks just like a host that can't exist is a catch-all,
    # not a real vhost.
    junk = _r(200, "")
    assert V._same(_r(200, ""), junk) is True
    assert V._same(_r(301, ""), junk) is False  # different status -> real signal
