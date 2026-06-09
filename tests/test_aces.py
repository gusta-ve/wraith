from wraith.core.console import Console


def test_aces_renders_art_and_phrase(capsys):
    Console(color=False, banner=False).aces()
    out = capsys.readouterr().out
    assert "@" in out or "%" in out      # the wraith silhouette
    assert "aces" in out                 # the reveal phrase
    assert "A♣" in out and "A♥" in out   # the pocket aces


def test_showdown_reveals_finding_count(capsys):
    Console(color=False, banner=False).showdown(17)
    out = capsys.readouterr().out
    assert "@" in out or "%" in out          # the wraith silhouette
    assert "17 findings" in out              # the hand it was holding
    assert "holding aces" in out             # the showdown phrase
    Console(color=False, banner=False).showdown(1)
    assert "1 finding\n" in capsys.readouterr().out  # singular, no plural 's'


def test_banner_is_clean_wordmark(capsys):
    Console(color=False, banner=True).banner()
    out = capsys.readouterr().out
    assert "█" in out                    # block wordmark
    assert "♣" not in out and "♥" not in out   # no cards in the banner
    assert "WRAITH" not in out           # it's block art, not literal text
