from wraith.phases.tech_detect import detect


def test_server_and_powered_by_versions():
    d = detect({"server": "nginx/1.18.0", "x-powered-by": "PHP/7.4.3"}, "")
    assert d.get("Nginx") == "1.18.0"
    assert d.get("PHP") == "7.4.3"


def test_cookie_and_body_markers():
    d = detect(
        {"set-cookie": "wordpress_logged_in=1; path=/"},
        '<link href="/wp-content/themes/x/style.css">',
    )
    assert "WordPress" in d


def test_generator_and_angular_version():
    d = detect({}, '<meta name="generator" content="Drupal 9"> <html ng-version="15.1.0">')
    assert d.get("Drupal") == "9"
    assert d.get("Angular") == "15.1.0"


def test_empty_when_no_signals():
    assert detect({}, "<html></html>") == {}
