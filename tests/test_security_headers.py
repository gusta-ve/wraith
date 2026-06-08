from wraith.core.models import Severity
from wraith.phases.security_headers import cookie_issues, cors_issue, missing_headers


def test_missing_headers_flags_absent():
    labels = {label for label, _, _ in missing_headers({}, "https")}
    assert "Content-Security-Policy" in labels
    assert "Strict-Transport-Security" in labels


def test_hsts_skipped_on_http():
    labels = {label for label, _, _ in missing_headers({}, "http")}
    assert "Strict-Transport-Security" not in labels


def test_xfo_satisfied_by_csp_frame_ancestors():
    headers = {"content-security-policy": "frame-ancestors 'none'"}
    labels = {label for label, _, _ in missing_headers(headers, "http")}
    assert "X-Frame-Options" not in labels


def test_cookie_issues():
    assert set(cookie_issues("session=1", "https")) == {"HttpOnly", "Secure", "SameSite"}
    assert cookie_issues("session=1; HttpOnly; Secure; SameSite=Lax", "https") == []
    assert "Secure" not in cookie_issues("session=1; HttpOnly; SameSite=Lax", "http")


def test_cors_issue():
    assert cors_issue("*", "", "https://e")[1] == Severity.LOW
    assert cors_issue("https://e", "true", "https://e")[1] == Severity.HIGH
    assert cors_issue("https://e", "", "https://e")[1] == Severity.MEDIUM
    assert cors_issue("https://trusted", "", "https://e") is None
