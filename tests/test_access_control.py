from wraith.core.http import Response
from wraith.phases.access_control import AccessControlPhase as AC


def test_id_in_path_mutation():
    url = "http://h/account/orders/5"
    assert AC._first_id(url) == 5
    assert AC._with_id(url, 6) == "http://h/account/orders/6"


def test_id_in_query_mutation():
    url = "http://h/item?id=10&x=2"
    assert AC._first_id(url) == 10
    assert AC._with_id(url, 11) == "http://h/item?id=11&x=2"


def test_port_in_host_is_not_treated_as_id():
    url = "http://127.0.0.1:8080/orders/3"
    assert AC._first_id(url) == 3
    assert AC._with_id(url, 4) == "http://127.0.0.1:8080/orders/4"


def test_id_is_last_path_int_not_a_version_or_year():
    # the object id is the trailing segment — never an API version or a date,
    # so the probe mutates the real id and not the /v1/ or /2024/ prefix.
    assert AC._first_id("http://h/api/v1/users/5") == 5
    assert AC._with_id("http://h/api/v1/users/5", 6) == "http://h/api/v1/users/6"
    assert AC._first_id("http://h/v2/orders/1003") == 1003
    assert AC._first_id("http://h/2024/report/42") == 42


def test_id_like_query_param_wins_over_other_numbers():
    # a number-bearing path segment (v1) and a paging param (page=2) are both
    # present, but the id-like parameter is the one to mutate.
    url = "http://h/api/v1/widget?page=2&user_id=77"
    assert AC._first_id(url) == 77
    assert AC._with_id(url, 78) == "http://h/api/v1/widget?page=2&user_id=78"


def test_ok_rejects_login_and_redirects():
    assert AC._ok(Response(200, "http://h/dashboard", "<p>ok</p>", {})) is True
    assert AC._ok(Response(200, "http://h/login", "<form>", {})) is False
    assert AC._ok(Response(200, "http://h/x", '<input type="password">', {})) is False
    assert AC._ok(Response(302, "http://h/x", "", {})) is False
    assert AC._ok(Response(403, "http://h/x", "", {})) is False


def test_similar_scores():
    assert AC._similar("hello world", "hello world") == 1.0
    assert AC._similar("abc", "xyz") < 0.5


def test_redirect_is_not_a_bypass():
    # Bounced to their own area / login => denied, not a bypass.
    assert AC._redirected(Response(200, "http://h/portal", "", {}), "http://h/cofre") is True
    assert AC._redirected(Response(200, "http://h/cofre", "", {}), "http://h/cofre") is False
    # Trailing-slash and query differences don't count as a redirect.
    assert AC._redirected(Response(200, "http://h/cofre?landing=1", "", {}), "http://h/cofre") is False


def test_static_assets_are_skipped():
    assert AC._is_static("http://h/app.css") is True
    assert AC._is_static("http://h/_framework/blazor.web.js") is True
    assert AC._is_static("http://h/favicon.svg") is True
    assert AC._is_static("http://h/financeiro") is False
