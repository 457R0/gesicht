from __future__ import annotations

from gesicht.tools import wordlists


def test_override_wins(tmp_path):
    wl = tmp_path / "my.txt"
    wl.write_text("a\nb\n")
    assert wordlists.find_wordlist("content", override=str(wl)) == wl


def test_override_missing_returns_none(tmp_path):
    assert wordlists.find_wordlist("content", override=str(tmp_path / "nope")) is None


def test_seclists_preferred_when_present(tmp_path, monkeypatch):
    root = tmp_path / "seclists"
    (root / "Discovery/Web-Content").mkdir(parents=True)
    target = root / "Discovery/Web-Content/raft-medium-directories.txt"
    target.write_text("admin\n")
    monkeypatch.setattr(wordlists, "_SECLISTS_ROOTS", (root,))
    assert wordlists.find_wordlist("content") == target


def test_params_always_has_a_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(wordlists, "_SECLISTS_ROOTS", ())
    monkeypatch.setenv("HOME", str(tmp_path))
    wl = wordlists.find_wordlist("params")
    assert wl is not None and wl.is_file()
    assert "redirect" in wl.read_text()


def test_content_none_when_nothing_available(monkeypatch):
    monkeypatch.setattr(wordlists, "_SECLISTS_ROOTS", ())
    monkeypatch.setattr(wordlists, "_STOCK", {"content": ("/nonexistent/xyz",)})
    assert wordlists.find_wordlist("content") is None
