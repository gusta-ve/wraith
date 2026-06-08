from wraith.shell import payloads


def test_generate_embeds_lhost_and_lport():
    gen = payloads.generate("10.0.0.5", 4444)
    assert {"bash", "sh-fifo", "nc-e", "python3", "php", "perl", "powershell"} <= set(gen)
    for name, line in gen.items():
        assert "10.0.0.5" in line, name
        assert "4444" in line, name


def test_guess_lhost_returns_ipv4_string():
    host = payloads.guess_lhost()
    assert isinstance(host, str)
    assert host.count(".") == 3
