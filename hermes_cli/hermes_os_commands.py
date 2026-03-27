"""First-class Hermes OS slash-command helpers shared by CLI and gateway."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Callable


HERMES_OS_REPO = Path.home() / "hermes-os"
SLASH_COMMANDS_DIR = HERMES_OS_REPO / "scripts" / "slash-commands"


def _run_json_script(script_name: str, *args: str, timeout: int = 60) -> dict:
    script_path = SLASH_COMMANDS_DIR / script_name
    if not script_path.exists():
        return {"status": "error", "message": f"Script not found: {script_path}"}

    try:
        result = subprocess.run(
            [str(script_path), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(HERMES_OS_REPO),
        )
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Command timed out"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    raw_output = stdout or stderr

    json_candidate = stdout
    if stdout and "{" in stdout and "}" in stdout:
        json_candidate = stdout[stdout.find("{"):stdout.rfind("}") + 1]

    try:
        payload = json.loads(json_candidate) if json_candidate else {}
    except json.JSONDecodeError:
        payload = {
            "status": "error" if result.returncode else "info",
            "message": "Script returned non-JSON output",
            "raw_output": raw_output,
        }

    if result.returncode and payload.get("status") not in {"error", "preview"}:
        payload = {
            "status": "error",
            "message": payload.get("message") or raw_output or "Command failed",
            "raw_output": raw_output,
        }
    elif raw_output and "raw_output" not in payload:
        payload["raw_output"] = raw_output

    return payload


def _parse_args(arg_string: str) -> list[str]:
    return [part.strip() for part in arg_string.split() if part.strip()]


def restart_gateway_service() -> None:
    subprocess.run(
        ["systemctl", "--user", "restart", "hermes-gateway.service"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )


def run_status_command() -> str:
    payload = _run_json_script("status.sh")
    if payload.get("status") not in {"healthy", "degraded"}:
        return f"Hermes OS status failed: {payload.get('message', 'Unknown error')}"

    health = payload.get("health_percentage", 0)
    ready = payload.get("ready", "NO")
    components = payload.get("components", {}) or {}
    lines = [f"Hermes OS Status ({health}% healthy)"]
    for key, value in components.items():
        marker = "OK" if value == "ok" else "WARN" if value == "warn" else "FAIL"
        lines.append(f"{key.replace('_', ' ').title():<18} {marker}")
    lines.append(f"Ready              {'YES' if ready == 'YES' else 'NO'}")
    summary = payload.get("summary")
    if summary:
        lines.append(summary)
    return "\n".join(lines)


def run_export_command(arg_string: str = "") -> str:
    args = _parse_args(arg_string)
    payload = _run_json_script("export.sh", *(["--force"] if "--force" in args else []))
    status = payload.get("status")
    if status == "success":
        files = payload.get("files_changed", 0)
        if files == 0:
            return "Hermes OS export complete: no changes to commit."
        return f"Hermes OS export complete: {files} file(s) changed and committed."
    if status == "info":
        return payload.get("message", "No export action needed.")
    return f"Hermes OS export failed: {payload.get('message', 'Unknown error')}"


def run_refresh_patch_command() -> str:
    payload = _run_json_script("refresh-patch.sh")
    status = payload.get("status")
    if status == "success":
        size = payload.get("patch_size_bytes", 0)
        delta = payload.get("size_change_bytes", 0)
        commit = payload.get("commit_status", "")
        tail = f"; commit={commit}" if commit else ""
        return f"Runtime patch refreshed: {size} bytes ({delta:+} bytes){tail}."
    if status == "info":
        return payload.get("message", "No runtime patch refresh needed.")
    return f"Runtime patch refresh failed: {payload.get('message', 'Unknown error')}"


def run_apply_command(
    arg_string: str = "",
    restart_callback: Callable[[], None] | None = None,
) -> str:
    args = _parse_args(arg_string)
    wants_confirm = any(arg in {"--confirm", "--force", "confirm"} for arg in args)
    wants_restart = any(arg in {"--restart-gateway", "--restart"} for arg in args)

    if not wants_confirm:
        payload = _run_json_script("apply.sh", "--dry-run")
        status = payload.get("status")
        if status == "info":
            return payload.get("message", "No changes to apply.")
        if status != "preview":
            return f"Hermes OS apply preview failed: {payload.get('message', 'Unknown error')}"

        affected = (payload.get("affected_files") or "").replace("\\n", "\n").strip()
        lines = [
            "Hermes OS apply preview",
            "This will overwrite live Hermes configuration.",
        ]
        if affected:
            lines.extend(["", "Affected files:", affected])
        lines.extend(["", "Run /hermes-os-apply --confirm to execute."])
        return "\n".join(lines)

    payload = _run_json_script("apply.sh")
    if payload.get("status") != "success":
        return f"Hermes OS apply failed: {payload.get('message', 'Unknown error')}"

    restarted = False
    if (
        payload.get("gateway_restart_needed")
        and wants_restart
        and restart_callback is not None
    ):
        restart_callback()
        restarted = True

    affected = (payload.get("affected_files") or "").replace("\\n", "\n").strip()
    lines = ["Hermes OS apply complete."]
    if affected:
        lines.extend(["", "Changed files:", affected])
    backup = payload.get("backup_location")
    if backup:
        lines.extend(["", f"Backup: {backup}"])
    if payload.get("gateway_restart_needed"):
        lines.append("Gateway restart: completed" if restarted else "Gateway restart: required")
        if not restarted:
            lines.append("Re-run with /hermes-os-apply --confirm --restart-gateway to restart automatically.")
    return "\n".join(lines)
