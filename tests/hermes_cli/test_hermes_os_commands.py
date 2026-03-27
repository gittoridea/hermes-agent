from hermes_cli import hermes_os_commands as hoc


def test_run_status_command_formats_components(monkeypatch):
    monkeypatch.setattr(
        hoc,
        "_run_json_script",
        lambda *args, **kwargs: {
            "status": "healthy",
            "health_percentage": 100,
            "ready": "YES",
            "components": {
                "gateway": "ok",
                "repo": "warn",
            },
            "summary": "2/2 components passing",
        },
    )

    result = hoc.run_status_command()

    assert "Hermes OS Status (100% healthy)" in result
    assert "Gateway" in result
    assert "Repo" in result
    assert "Ready              YES" in result


def test_run_apply_command_defaults_to_preview(monkeypatch):
    monkeypatch.setattr(
        hoc,
        "_run_json_script",
        lambda *args, **kwargs: {
            "status": "preview",
            "affected_files": "\\n- config.yaml",
        },
    )

    result = hoc.run_apply_command("")

    assert "Hermes OS apply preview" in result
    assert "/hermes-os-apply --confirm" in result


def test_run_apply_command_confirm_can_restart_gateway(monkeypatch):
    called = {"restart": False}

    monkeypatch.setattr(
        hoc,
        "_run_json_script",
        lambda *args, **kwargs: {
            "status": "success",
            "affected_files": "\\n- config.yaml",
            "backup_location": "/tmp/backup",
            "gateway_restart_needed": True,
        },
    )

    def _restart():
        called["restart"] = True

    result = hoc.run_apply_command("--confirm --restart-gateway", restart_callback=_restart)

    assert called["restart"] is True
    assert "Gateway restart: completed" in result
