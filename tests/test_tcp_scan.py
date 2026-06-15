from wraith.phases.tcp_scan import COMMON_PORTS, WEB_PORTS, parse_ports


def test_parse_ports_handles_lists_and_ranges():
    assert parse_ports("80,443") == [80, 443]
    assert parse_ports("8000-8002") == [8000, 8001, 8002]
    # mixed, de-duplicated and sorted
    assert parse_ports("443,80,80,81") == [80, 81, 443]


def test_parse_ports_keywords():
    assert parse_ports("top") == sorted(COMMON_PORTS)
    assert parse_ports("web") == sorted(WEB_PORTS)
    # every "all" spelling expands to the full range
    for spec in ("all", "full", "-", "1-65535"):
        full = parse_ports(spec)
        assert full[0] == 1 and full[-1] == 65535 and len(full) == 65535


def test_parse_ports_combines_keyword_with_extra_port():
    # `top,8666` adds a single odd port to the default — the deadwood case
    out = parse_ports("top,8666")
    assert 8666 in out
    assert set(COMMON_PORTS) <= set(out)


def test_parse_ports_drops_out_of_range_and_blanks():
    assert parse_ports("0,80,70000, ,443") == [80, 443]
    assert parse_ports("") == []


def test_web_set_covers_the_odd_http_ports():
    # the broad web sweep must reach ports the lean default skips
    assert 8666 in WEB_PORTS
    assert 8888 in WEB_PORTS
    assert set(COMMON_PORTS) <= set(WEB_PORTS)
