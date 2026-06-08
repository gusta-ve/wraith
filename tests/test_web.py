from wraith.core import web


def test_is_ip():
    assert web.is_ip("127.0.0.1") is True
    assert web.is_ip("example.com") is False


def test_params_from_url():
    assert web.params_from_url("http://h/p?a=1&b=2") == {"a": "1", "b": "2"}
    assert web.params_from_url("http://h/p") == {}


def test_extract_links_same_host_only():
    html = '<a href="/a">x</a><a href="http://other/b">y</a><a href="/logout">z</a>'
    links = web.extract_links("http://h/", html, "h")
    assert "http://h/a" in links
    assert all("other" not in link for link in links)
    assert all("logout" not in link for link in links)


def test_extract_forms():
    html = ('<form action="/login" method="POST">'
            '<input name="user"><input type="password" name="password"></form>')
    forms = web.extract_forms("http://h/", html)
    assert forms[0]["action"] == "http://h/login"
    assert forms[0]["method"] == "POST"
    assert forms[0]["inputs"] == ["user", "password"]


def test_build_points_from_query_and_form():
    html = '<form action="/s" method="GET"><input name="q"></form>'
    points = web.build_points("http://h/page?id=5", html)
    kinds = {(p.method, p.param, p.location) for p in points}
    assert ("GET", "id", "query") in kinds
    assert ("GET", "q", "query") in kinds  # GET form -> query location
