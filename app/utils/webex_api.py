"""
Webex Calling REST API utility layer for RELAY.
Handles OAuth2 token refresh and common People / Numbers API calls.
"""
import requests
from datetime import datetime, timedelta
from app import db

WEBEX_BASE = "https://webexapis.com/v1"
TOKEN_URL  = "https://webexapis.com/v1/access_token"


def _load_cfg():
    from app.models import WebexConfig
    return WebexConfig.get()


# ── Token management ──────────────────────────────────────────
def get_webex_token() -> str:
    """Return a valid Webex access token, refreshing via refresh_token if needed."""
    cfg = _load_cfg()
    if not cfg or not cfg.is_configured():
        raise RuntimeError("Webex API credentials are not configured.")

    now = datetime.utcnow()
    if cfg.access_token and cfg.token_expiry and cfg.token_expiry > now:
        return cfg.access_token

    # Refresh
    data = {
        "grant_type":    "refresh_token",
        "client_id":     cfg.client_id,
        "client_secret": cfg.client_secret,
        "refresh_token": cfg.refresh_token,
    }
    r = requests.post(TOKEN_URL, data=data, timeout=15)
    r.raise_for_status()
    j = r.json()
    cfg.access_token  = j["access_token"]
    cfg.token_expiry  = now + timedelta(seconds=int(j.get("expires_in", 3600)) - 60)
    if "refresh_token" in j:
        cfg.refresh_token = j["refresh_token"]
    db.session.commit()
    return cfg.access_token


def _headers():
    return {"Authorization": f"Bearer {get_webex_token()}",
            "Content-Type":  "application/json"}


# ── People API ────────────────────────────────────────────────
def search_webex_users(query: str, max_results: int = 20) -> list:
    """Search Webex users by display name."""
    cfg = _load_cfg()
    params = {"displayName": query, "max": max_results}
    if cfg and cfg.org_id:
        params["orgId"] = cfg.org_id
    r = requests.get(f"{WEBEX_BASE}/people", headers=_headers(),
                     params=params, timeout=15)
    r.raise_for_status()
    return r.json().get("items", [])


def get_webex_user_by_email(email: str) -> dict | None:
    """Fetch a single Webex user by email address."""
    cfg = _load_cfg()
    params = {"email": email}
    if cfg and cfg.org_id:
        params["orgId"] = cfg.org_id
    r = requests.get(f"{WEBEX_BASE}/people", headers=_headers(),
                     params=params, timeout=15)
    r.raise_for_status()
    items = r.json().get("items", [])
    return items[0] if items else None


def get_webex_user_by_id(person_id: str) -> dict:
    """Fetch full Webex user record by Webex person ID."""
    r = requests.get(f"{WEBEX_BASE}/people/{person_id}",
                     headers=_headers(), timeout=15)
    r.raise_for_status()
    return r.json()


# ── Calling / Numbers API ─────────────────────────────────────
def get_webex_numbers(org_id: str = None, max_results: int = 100) -> list:
    """Return phone numbers from the Webex Calling Numbers API."""
    cfg = _load_cfg()
    oid = org_id or (cfg.org_id if cfg else None)
    params = {"max": max_results}
    if oid:
        params["orgId"] = oid
    r = requests.get(f"{WEBEX_BASE}/telephony/config/numbers",
                     headers=_headers(), params=params, timeout=15)
    r.raise_for_status()
    return r.json().get("phoneNumbers", [])


def get_webex_locations() -> list:
    """Return Webex Calling locations for the org."""
    cfg = _load_cfg()
    params = {}
    if cfg and cfg.org_id:
        params["orgId"] = cfg.org_id
    r = requests.get(f"{WEBEX_BASE}/locations", headers=_headers(),
                     params=params, timeout=15)
    r.raise_for_status()
    return r.json().get("items", [])


def set_webex_call_forward(person_id: str, forward_to: str, enabled: bool = True) -> dict:
    """
    Enable or disable call forwarding always for a Webex user.
    Requires the 'spark-admin:people_write' scope on the integration.
    """
    payload = {
        "callForwarding": {
            "always": {
                "enabled":       enabled,
                "destination":   forward_to,
                "ringReminderEnabled": False,
                "destinationVoicemailEnabled": False,
            }
        }
    }
    r = requests.put(f"{WEBEX_BASE}/people/{person_id}/features/callForwarding",
                     headers=_headers(), json=payload, timeout=15)
    r.raise_for_status()
    return r.json()


def get_webex_call_forward(person_id: str) -> dict:
    """Get current call forwarding settings for a Webex user."""
    r = requests.get(f"{WEBEX_BASE}/people/{person_id}/features/callForwarding",
                     headers=_headers(), timeout=15)
    r.raise_for_status()
    return r.json()
