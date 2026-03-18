"""
Microsoft Graph API + Teams Routing API utility layer for RELAY.

API CHANGELOG (March 2026 review)
──────────────────────────────────────────────────────────────────────
BREAKING — Phone number inventory endpoint changed:
  OLD  →  /beta/admin/telephony/phoneNumbers
  NEW  →  /beta/admin/teams/telephoneNumberManagement/numberAssignments
  assignmentStatus values changed:
    "assigned"  →  "userAssigned"  (assigned to a user)
    new values:   "conferenceAssigned", "voiceApplicationAssigned"
    unchanged:    "unassigned"
  New fields: activationState, capabilities[], assignmentCategory,
              portInStatus, isoCountryCode, numberSource

BREAKING — Per-user phone number + config API (new):
  GET /beta/admin/teams/userConfigurations
  Returns telephoneNumbers[{telephoneNumber, assignmentCategory}] per user.

DEPRECATED — Skype.VoiceGroup call forwarding endpoint:
  api.interfaces.records.teams.microsoft.com/Skype.VoiceGroup
  No stable Graph API replacement confirmed as of March 2026.
  ROPC (password grant) for Teams token increasingly blocked by
  Conditional Access / MFA — configure an App Password or CA exclusion
  for the RELAY service account.

REQUIRED APP PERMISSIONS
  Graph (client_credentials):
    User.Read.All
    TeamsTelephoneNumber.ReadWrite.All   (new number inventory API)
    TeamsUserConfiguration.ReadWrite.All (new userConfigurations API)
  Skype PSTN (ROPC, for forwarding):
    scope 48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default
    service account: Teams Phone licence, no MFA or App Password
──────────────────────────────────────────────────────────────────────
"""
import time
import logging
import requests
from datetime import datetime, timedelta
from app import db

log = logging.getLogger(__name__)

GRAPH_BASE        = "https://graph.microsoft.com"
TEAMS_ADMIN_BASE  = f"{GRAPH_BASE}/beta/admin/teams"
SKYPE_PSTN_SCOPE  = "48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default"
ROUTING_BASE      = "https://api.interfaces.records.teams.microsoft.com/Skype.VoiceGroup"

# assignmentStatus values that count as "assigned to something"
_ASSIGNED = frozenset({
    "userAssigned", "conferenceAssigned", "voiceApplicationAssigned",
    "assigned",   # legacy value from old API
})


def _load_cfg():
    from app.models import MSGraphConfig
    return MSGraphConfig.query.first()


# ── Retry / rate-limit wrapper ────────────────────────────────
def _req(method: str, url: str, *, retries: int = 3, **kwargs) -> requests.Response:
    """requests.{method} with automatic retry on 429/503, honouring Retry-After."""
    kwargs.setdefault("timeout", 20)
    for attempt in range(retries):
        r = getattr(requests, method)(url, **kwargs)
        if r.status_code in (429, 503):
            wait = int(r.headers.get("Retry-After", 2 ** attempt))
            log.warning("Graph %s %s → %d, wait %ds", method.upper(), url, r.status_code, wait)
            time.sleep(wait)
            continue
        return r
    return r


# ── Tokens ────────────────────────────────────────────────────
def get_graph_token() -> str:
    """
    App-only token via client_credentials for Microsoft Graph.
    Required permissions: User.Read.All, TeamsTelephoneNumber.ReadWrite.All,
    TeamsUserConfiguration.ReadWrite.All.
    """
    cfg = _load_cfg()
    if not cfg or not cfg.is_configured():
        raise RuntimeError("MS Graph credentials not configured.")
    now = datetime.utcnow()
    if cfg.graph_access_token and cfg.graph_token_expiry and cfg.graph_token_expiry > now:
        return cfg.graph_access_token

    url = f"https://login.microsoftonline.com/{cfg.tenant_id}/oauth2/v2.0/token"
    r   = requests.post(url, data={
        "grant_type":    "client_credentials",
        "client_id":     cfg.client_id,
        "client_secret": cfg.client_secret,
        "scope":         f"{GRAPH_BASE}/.default",
    }, timeout=15)
    if not r.ok:
        raise RuntimeError(f"Graph token error {r.status_code}: "
                           f"{r.json().get('error_description','')[:200]}")
    j = r.json()
    cfg.graph_access_token = j["access_token"]
    cfg.graph_token_expiry = now + timedelta(seconds=int(j.get("expires_in", 3600)) - 60)
    db.session.commit()
    return cfg.graph_access_token


def get_teams_token() -> str:
    """
    Delegated token for Skype.VoiceGroup PSTN API via ROPC (password grant).

    DEPRECATION: ROPC is increasingly rejected by Azure AD when Conditional
    Access or Security Defaults are active. If you receive 400 / AADSTS5007x
    errors, either:
      - Create an App Password for the service account (recommended)
      - Exclude the service account from MFA policies
    """
    cfg = _load_cfg()
    if not cfg or not cfg.service_account_upn or not cfg.service_account_password:
        raise RuntimeError("Teams service account UPN/password not configured.")
    now = datetime.utcnow()
    if cfg.teams_access_token and cfg.teams_token_expiry and cfg.teams_token_expiry > now:
        return cfg.teams_access_token

    url = f"https://login.microsoftonline.com/{cfg.tenant_id}/oauth2/v2.0/token"
    r   = requests.post(url, data={
        "grant_type":    "password",
        "client_id":     cfg.client_id,
        "client_secret": cfg.client_secret,
        "username":      cfg.service_account_upn,
        "password":      cfg.service_account_password,
        "scope":         SKYPE_PSTN_SCOPE,
    }, timeout=15)
    if not r.ok:
        err = r.json().get("error_description", r.text)[:300]
        if any(c in err for c in ("AADSTS50076", "AADSTS50079", "AADSTS50158")):
            raise RuntimeError(
                f"Teams ROPC blocked by MFA/Conditional Access. "
                f"Use an App Password or exclude the service account from CA. Detail: {err}"
            )
        if any(c in err for c in ("AADSTS700016", "AADSTS500011")):
            raise RuntimeError(
                f"Skype.VoiceGroup resource not consented in this tenant. "
                f"An admin must grant consent for scope 48ac35b8-... Detail: {err}"
            )
        raise RuntimeError(f"Teams ROPC token failed: {err}")

    j = r.json()
    cfg.teams_access_token = j["access_token"]
    cfg.teams_token_expiry = now + timedelta(seconds=int(j.get("expires_in", 3600)) - 60)
    db.session.commit()
    return cfg.teams_access_token


def _gh(token=None) -> dict:
    """Graph headers shorthand."""
    return {"Authorization": f"Bearer {token or get_graph_token()}",
            "Content-Type": "application/json"}


# ── User lookup ───────────────────────────────────────────────
def get_user_by_upn(upn: str) -> dict | None:
    r = _req("get",
        f"{GRAPH_BASE}/v1.0/users/{upn}"
        "?$select=id,displayName,userPrincipalName,businessPhones,mail",
        headers=_gh())
    if r.status_code == 404:
        return None
    r.raise_for_status()
    u = r.json()
    u.setdefault("upn", u.get("userPrincipalName", ""))
    return u


def search_users(query: str, top: int = 25) -> list:
    """
    Search by displayName or UPN. Adds normalised 'upn' key to every result
    so the multi-platform schedule modal JS works uniformly.
    Falls back to $filter if the tenant blocks $search.
    """
    hdrs = _gh()
    hdrs["ConsistencyLevel"] = "eventual"
    r = _req("get",
        f"{GRAPH_BASE}/v1.0/users"
        f"?$search=\"displayName:{query}\" OR \"userPrincipalName:{query}\""
        f"&$select=id,displayName,userPrincipalName,businessPhones,mail"
        f"&$top={top}&$count=true",
        headers=hdrs)

    if r.status_code in (400, 403):
        # $search blocked — fall back to $filter startswith
        r = _req("get",
            f"{GRAPH_BASE}/v1.0/users"
            f"?$filter=startswith(displayName,'{query}') "
            f"or startswith(userPrincipalName,'{query}')"
            f"&$select=id,displayName,userPrincipalName,businessPhones,mail&$top={top}",
            headers=_gh())

    r.raise_for_status()
    users = r.json().get("value", [])
    for u in users:
        u.setdefault("upn", u.get("userPrincipalName", ""))
    return users


def get_user_teams_phone(user_id: str) -> str:
    """
    Return the primary Teams-provisioned phone number for a user via the
    new /beta/admin/teams/userConfigurations endpoint.
    Falls back gracefully to empty string if not available.
    """
    try:
        r = _req("get", f"{TEAMS_ADMIN_BASE}/userConfigurations/{user_id}", headers=_gh())
        if r.ok:
            nums = r.json().get("telephoneNumbers", [])
            # primary first, then first available
            for n in sorted(nums, key=lambda x: x.get("assignmentCategory","") != "primary"):
                tn = n.get("telephoneNumber", "")
                if tn:
                    return tn
    except Exception as e:
        log.debug("get_user_teams_phone: %s", e)
    return ""


# ── Phone number inventory ────────────────────────────────────
def get_all_phone_numbers() -> list:
    """
    Fetch all tenant phone numbers.

    PRIMARY: new /beta/admin/teams/telephoneNumberManagement/numberAssignments
    FALLBACK: legacy /beta/admin/telephony/phoneNumbers (normalises field names)

    New API response fields per number:
      telephoneNumber, numberType, activationState, assignmentStatus,
      assignmentTargetId, assignmentCategory, capabilities[],
      locationId, isoCountryCode, numberSource
    """
    url = f"{TEAMS_ADMIN_BASE}/telephoneNumberManagement/numberAssignments?$top=1000"
    results, fallback = [], False
    while url:
        r = _req("get", url, headers=_gh())
        if not r.ok:
            log.warning("New number API failed (%d) — falling back to legacy endpoint",
                        r.status_code)
            fallback = True
            break
        j = r.json()
        results.extend(j.get("value", []))
        url = j.get("@odata.nextLink")

    if fallback:
        return _get_all_phone_numbers_legacy()
    return results


def _get_all_phone_numbers_legacy() -> list:
    """Legacy phone number endpoint with field-name normalisation."""
    results, url = [], f"{GRAPH_BASE}/beta/admin/telephony/phoneNumbers?$top=1000"
    while url:
        r = _req("get", url, headers=_gh())
        r.raise_for_status()
        j = r.json()
        for item in j.get("value", []):
            # Normalise old "assigned" status to match new API value
            if item.get("assignmentStatus") == "assigned":
                item["assignmentStatus"] = "userAssigned"
            results.append(item)
        url = j.get("@odata.nextLink")
    return results


def get_all_user_configurations(top: int = 999) -> list:
    """
    NEW (2024): Per-user Teams config including assigned numbers and policies.
    Endpoint: /beta/admin/teams/userConfigurations
    Each item includes: id, userPrincipalName, isEnterpriseVoiceEnabled,
    featureTypes[], telephoneNumbers[{telephoneNumber, assignmentCategory}]
    """
    results, url = [], f"{TEAMS_ADMIN_BASE}/userConfigurations?$top={top}"
    while url:
        r = _req("get", url, headers=_gh())
        r.raise_for_status()
        j = r.json()
        results.extend(j.get("value", []))
        url = j.get("@odata.nextLink")
    return results


def get_teams_locations() -> list:
    """Fetch Teams telephony locations (used for DID geo import)."""
    results, url = [], f"{GRAPH_BASE}/beta/admin/telephony/onlineTelephonyLocations?$top=999"
    while url:
        r = _req("get", url, headers=_gh())
        r.raise_for_status()
        j = r.json()
        results.extend(j.get("value", []))
        url = j.get("@odata.nextLink")
    return results


def get_did_availability(start_e164: str, end_e164: str) -> dict:
    """
    Classify every number in a range as assigned, unassigned (in tenant
    but free), or not_in_teams (not provisioned at all).
    Uses the unified get_all_phone_numbers() which handles API fallback.
    """
    def digits(n): return int("".join(c for c in n if c.isdigit()))

    tenant = {digits(r["telephoneNumber"]): r
              for r in get_all_phone_numbers()
              if r.get("telephoneNumber")}

    start_i, end_i = digits(start_e164), digits(end_e164)
    assigned, unassigned, not_in_teams = [], [], []

    for i in range(start_i, end_i + 1):
        if i in tenant:
            rec       = tenant[i]
            status    = rec.get("assignmentStatus", "unassigned")
            target_id = (rec.get("assignmentTargetId") or "").strip()
            caps      = rec.get("capabilities", [])
            # Only truly assigned when a concrete entity ID is attached
            is_assigned = (status in _ASSIGNED) and bool(target_id)
            entry  = {
                "number":             f"+{i}",
                "status":             status,
                "numberType":         rec.get("numberType"),
                "assignedTo":         target_id or None,
                "activationState":    rec.get("activationState"),
                "assignmentCategory": rec.get("assignmentCategory"),
                "capabilities":       caps,
            }
            (assigned if is_assigned else unassigned).append(entry)
        else:
            not_in_teams.append(f"+{i}")

    return {
        "total_in_block": end_i - start_i + 1,
        "assigned":       assigned,
        "unassigned":     unassigned,
        "not_in_teams":   not_in_teams,
    }


def get_all_assigned_numbers_for_inventory() -> list:
    """
    Return all tenant numbers in the normalised dict format expected by
    inventory_sync._upsert_numbers() — status, assigned_to, type, location.

    Assignment rule: a number is only "assigned" when it has BOTH
      a) an assignmentStatus value indicating assignment, AND
      b) a non-empty assignmentTargetId (the actual entity ID).
    Numbers where the status says assigned but no target ID exists are
    treated as available — this handles stale/phantom assignments
    (e.g. voiceApplicationAssigned with no call queue linked).
    """
    results = []
    for rec in get_all_phone_numbers():
        num = rec.get("telephoneNumber", "").strip()
        if not num:
            continue
        status    = rec.get("assignmentStatus", "unassigned")
        target_id = (rec.get("assignmentTargetId") or "").strip()
        caps      = rec.get("capabilities", [])

        # Determine assignment type from capabilities
        if "userAssignment" in caps and status in _ASSIGNED:
            atype = "user"
        elif "conferenceAssignment" in caps:
            atype = "conference"
        elif "voiceApplicationAssignment" in caps:
            atype = "voiceApplication"
        else:
            atype = "other"

        # A number is only truly assigned if the platform has a concrete
        # entity (objectId, conference ID, voice app ID) attached to it.
        # Status alone is not sufficient — stale assignments have status
        # set but no target ID (assignmentTargetId is null/empty).
        is_assigned = (status in _ASSIGNED) and bool(target_id)

        results.append({
            "number":        num,
            "number_norm":   "".join(c for c in num if c.isdigit()),
            "status":        "assigned" if is_assigned else "available",
            "assigned_to":   target_id or None,
            "assigned_type": atype,
            "number_type":   rec.get("numberType", ""),
            "location":      rec.get("locationId") or rec.get("isoCountryCode") or None,
        })
    return results


# ── Call forwarding (Skype.VoiceGroup — deprecated) ───────────
def get_call_forwarding(user_object_id: str) -> dict:
    """
    Read call forwarding settings via the deprecated Skype.VoiceGroup API.
    Returns {} on any error (token failure, 404, API unavailable).
    """
    try:
        token = get_teams_token()
    except RuntimeError as e:
        log.warning("get_call_forwarding: token error: %s", e)
        return {}
    r = _req("get",
        f"{ROUTING_BASE}/userRoutingSettings/{user_object_id}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    if not r.ok:
        if r.status_code != 404:
            log.warning("get_call_forwarding %s: %d — %s",
                        user_object_id, r.status_code, r.text[:200])
        return {}
    return r.json()


def set_call_forwarding(user_object_id: str, sip_uri: str,
                        forward_to: str = "", enabled: bool = True,
                        delay_seconds: int = 20) -> bool:
    """
    Enable or disable call forwarding via Skype.VoiceGroup (deprecated).

    Failure guide:
      401 — token rejected: check PSTN scope consent, service account licence
      403 — permission denied: ensure account has Teams Phone System licence
      404 — user not found in Teams PSTN routing DB
      Any error → returns False and logs a structured message
    """
    try:
        token = get_teams_token()
    except RuntimeError as e:
        log.error("set_call_forwarding: token error: %s", e)
        return False

    hdrs = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    if enabled and forward_to:
        payload = {
            "sipUri": sip_uri,
            "forwardingSettings": {
                "isEnabled":      True,
                "forwardingType": "Immediate",
                "targetType":     "SingleTarget",
                "target":         forward_to,
            },
            "unansweredSettings": {
                "isEnabled":  False,
                "targetType": "Voicemail",
                "target":     "",
                "delay":      f"00:00:{delay_seconds:02d}",
            },
        }
    else:
        payload = {
            "sipUri": sip_uri,
            "forwardingSettings": {
                "isEnabled":      False,
                "forwardingType": "Simultaneous",
                "targetType":     "Unknown",
                "target":         "",
            },
            "unansweredSettings": {
                "isEnabled":  True,
                "targetType": "Voicemail",
                "target":     "",
                "delay":      f"00:00:{delay_seconds:02d}",
            },
        }

    r = _req("post",
        f"{ROUTING_BASE}/userRoutingSettings/{user_object_id}",
        headers=hdrs, json=payload)

    if not r.ok:
        log.error(
            "set_call_forwarding failed %d for %s. "
            "Body: %s. "
            "If 401: re-consent the Skype.VoiceGroup scope in Azure AD. "
            "If 403: check service account Teams Phone licence. "
            "If 404: user may not have a PSTN number assigned in Teams.",
            r.status_code, user_object_id, r.text[:300]
        )
        return False
    return True
