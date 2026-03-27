from types import SimpleNamespace
from unittest.mock import patch

import hermes_cli.main as main_mod


def test_cmd_version_shows_git_context_and_forces_update_refresh(capsys, monkeypatch):
    monkeypatch.setitem(__import__("sys").modules, "openai", SimpleNamespace(__version__="2.24.0"))

    with (
        patch.object(
            main_mod,
            "_get_git_version_context",
            return_value={
                "branch": "main",
                "short_sha": "41d9d080",
                "tracking": "synced with origin/main",
            },
        ),
        patch("hermes_cli.banner.check_for_updates", return_value=0) as mock_check,
    ):
        main_mod.cmd_version(None)

    out = capsys.readouterr().out
    assert "Hermes Agent v0.4.0 (2026.3.23)" in out
    assert "Git: main @ 41d9d080 [synced with origin/main]" in out
    assert "OpenAI SDK: 2.24.0" in out
    assert "Up to date" in out
    mock_check.assert_called_once_with(force_refresh=True)
