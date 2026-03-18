"""
RELAY — Environment File Manager

Writes runtime configuration values back to the .env file whenever
the admin saves API credentials or service settings through the GUI.

This means the admin only configures things once (in the GUI) and the
values are persisted both in the database AND in the .env file so they
survive service restarts and environment refreshes.

Usage:
    from app.utils.env_manager import write_env_vars
    write_env_vars({"TEAMS_TENANT_ID": "...", "TEAMS_CLIENT_ID": "..."})
"""
import os
import re
import logging
from pathlib import Path

log = logging.getLogger(__name__)

# Env file location — mirrors what install.sh writes
_ENV_CANDIDATES = [
    "/opt/relay/.env",
    "/etc/relay.env",
]


def _locate_env() -> Path | None:
    """Return the first writable .env path that exists."""
    # Prefer the path set in the process environment
    explicit = os.environ.get("RELAY_ENV_FILE")
    if explicit and Path(explicit).exists():
        return Path(explicit)
    for p in _ENV_CANDIDATES:
        path = Path(p)
        if path.exists():
            return path
    # Development fallback: project root .env
    dev = Path(__file__).parent.parent.parent / ".env"
    if dev.exists():
        return dev
    return None


def read_env_file() -> dict[str, str]:
    """Parse the .env file and return key → value dict."""
    path = _locate_env()
    if not path:
        return {}
    result: dict[str, str] = {}
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                result[k.strip()] = v.strip()
    return result


def write_env_vars(updates: dict[str, str]) -> bool:
    """
    Update specific keys in the .env file without touching other lines.
    Keys that don't exist yet are appended.
    Secrets that are empty strings are skipped (avoids blanking stored passwords).

    Returns True on success, False if the env file cannot be found/written.
    """
    path = _locate_env()
    if not path:
        log.warning("env_manager: .env file not found — skipping write")
        return False

    try:
        with open(path, "r") as f:
            lines = f.readlines()
    except OSError as e:
        log.error("env_manager: cannot read %s: %s", path, e)
        return False

    written_keys: set[str] = set()
    new_lines: list[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue
        if "=" in stripped:
            k, _, _ = stripped.partition("=")
            k = k.strip()
            if k in updates:
                if updates[k] == "":
                    # Keep existing value for blank updates (password placeholders)
                    new_lines.append(line)
                else:
                    new_lines.append(f"{k}={updates[k]}\n")
                written_keys.add(k)
                continue
        new_lines.append(line)

    # Append any keys that were not already in the file
    new_keys = [k for k in updates if k not in written_keys and updates[k] != ""]
    if new_keys:
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines.append("\n")
        new_lines.append("# GUI-configured settings\n")
        for k in new_keys:
            new_lines.append(f"{k}={updates[k]}\n")

    try:
        with open(path, "w") as f:
            f.writelines(new_lines)
        # Preserve permissions
        os.chmod(path, 0o600)
        log.info("env_manager: updated %d key(s) in %s", len(updates), path)
        return True
    except OSError as e:
        log.error("env_manager: cannot write %s: %s", path, e)
        return False


def sync_all_configs_to_env() -> int:
    """
    Read all stored platform configs from the database and write them all
    to the .env file. Useful after a migration or restore.
    Returns the number of keys written.
    """
    updates: dict[str, str] = {}

    try:
        from app.models import (MSGraphConfig, WebexConfig, CUCMConfig,
                                SMTPConfig, PlatformSettings)

        ps = PlatformSettings.get()
        updates.update({
            "HAS_TEAMS":        str(ps.has_teams).lower(),
            "HAS_WEBEX":        str(ps.has_webex).lower(),
            "HAS_CUCM":         str(ps.has_cucm).lower(),
            "HAS_CERT_MONITOR": str(ps.has_cert_monitor).lower(),
            "HAS_DID":          str(ps.has_did).lower(),
            "HAS_LDAP":         str(ps.has_ldap).lower(),
            "HAS_AUDIT":        str(ps.has_audit).lower(),
            "CLIENT_NAME":      ps.client_name or "",
        })

        cfg = MSGraphConfig.query.first()
        if cfg:
            updates.update({
                "TEAMS_TENANT_ID":      cfg.tenant_id or "",
                "TEAMS_CLIENT_ID":      cfg.client_id or "",
                "TEAMS_CLIENT_SECRET":  cfg.client_secret or "",
                "TEAMS_SVC_UPN":        cfg.service_account_upn or "",
            })

        w = WebexConfig.get()
        updates.update({
            "WEBEX_CLIENT_ID":     w.client_id or "",
            "WEBEX_CLIENT_SECRET": w.client_secret or "",
            "WEBEX_REFRESH_TOKEN": w.refresh_token or "",
            "WEBEX_ORG_ID":        w.org_id or "",
        })

        c = CUCMConfig.get()
        updates.update({
            "CUCM_HOST":     c.cucm_host or "",
            "CUCM_USERNAME": c.cucm_username or "",
            "CUCM_PASSWORD": c.cucm_password or "",
            "CUCM_VERSION":  c.cucm_version or "12.5",
        })

        s = SMTPConfig.get()
        updates.update({
            "SMTP_HOST":     s.host or "",
            "SMTP_PORT":     str(s.port or 587),
            "SMTP_USER":     s.username or "",
            "SMTP_PASS":     s.password or "",
            "SMTP_FROM":     s.from_addr or "",
            "SMTP_ALERT_TO": s.alert_to or "",
            "SMTP_TLS":      str(s.use_tls).lower(),
            "SMTP_SSL":      str(s.use_ssl).lower(),
            "SMTP_ENABLED":  str(s.enabled).lower(),
        })

    except Exception as e:
        log.error("sync_all_configs_to_env: DB read failed: %s", e)
        return 0

    if write_env_vars(updates):
        return len(updates)
    return 0
