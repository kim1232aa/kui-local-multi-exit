from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Mapping


DEFAULT_CREDENTIALS_FILE = "internal_proxy.json"


def _credential_path(
    workspace: str | Path,
    environ: Mapping[str, str],
    credentials_file: str | Path | None,
) -> Path:
    return Path(credentials_file or environ.get("KUI_INTERNAL_PROXY_FILE", "") or Path(workspace) / DEFAULT_CREDENTIALS_FILE)


def _configured_credentials(environ: Mapping[str, str]) -> tuple[str, str] | None:
    configured_user = environ.get("KUI_INTERNAL_PROXY_USER", "").strip()
    configured_password = environ.get("KUI_INTERNAL_PROXY_PASSWORD", "")
    if bool(configured_user) != bool(configured_password):
        raise ValueError("KUI_INTERNAL_PROXY_USER and KUI_INTERNAL_PROXY_PASSWORD must be set together")
    return (configured_user, configured_password) if configured_user else None


def load_internal_proxy_credentials(
    workspace: str | Path,
    *,
    environ: Mapping[str, str] | None = None,
    credentials_file: str | Path | None = None,
) -> tuple[str, str]:
    """Read explicit or persisted gateway-only SOCKS credentials."""
    env = os.environ if environ is None else environ
    configured = _configured_credentials(env)
    if configured:
        return configured
    path = _credential_path(workspace, env, credentials_file)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("internal proxy credentials are unavailable") from error
    username = str(payload.get("username", ""))
    password = str(payload.get("password", ""))
    if not username or not password:
        raise RuntimeError("internal proxy credentials are invalid")
    return username, password


def load_or_create_internal_proxy_credentials(
    workspace: str | Path,
    *,
    environ: Mapping[str, str] | None = None,
    credentials_file: str | Path | None = None,
) -> tuple[str, str]:
    """Return stable gateway-only SOCKS credentials without using admin credentials."""
    env = os.environ if environ is None else environ
    configured = _configured_credentials(env)
    if configured:
        return configured
    path = _credential_path(workspace, env, credentials_file)
    try:
        return load_internal_proxy_credentials(workspace, environ=env, credentials_file=path)
    except RuntimeError:
        pass

    path.parent.mkdir(parents=True, exist_ok=True)
    credentials = {
        "version": 1,
        "username": "kui-gateway",
        "password": secrets.token_urlsafe(32),
    }
    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(credentials, separators=(",", ":")), encoding="utf-8")
    tmp_path.chmod(0o600)
    tmp_path.replace(path)
    path.chmod(0o600)
    return credentials["username"], credentials["password"]
