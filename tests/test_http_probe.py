from wraith.phases.http_probe import HttpProbePhase


def test_known_web_ports_use_their_scheme():
    assert HttpProbePhase._schemes_for(80) == ["http"]
    assert HttpProbePhase._schemes_for(443) == ["https"]
    assert HttpProbePhase._schemes_for(8080) == ["http"]


def test_non_standard_open_port_is_probed_http_then_https():
    # a service on a non-standard port (a dev server, a range, an admin panel)
    # must still be probed, not skipped just because it isn't 80/443
    assert HttpProbePhase._schemes_for(8666) == ["http", "https"]
    assert HttpProbePhase._schemes_for(1337) == ["http", "https"]
