"""
RELAY — Unified Cross-Platform Call Forwarding

Dispatches enable/disable call forwarding requests to the correct
platform API based on the `platform` field of a schedule or direct call.

Supported platforms: teams | webex | cucm

Usage:
    from app.utils.forwarder import set_forward, get_forward_status
    ok, msg = set_forward(platform, user_id, user_upn, forward_to, enabled=True)
"""
import logging
log = logging.getLogger(__name__)


def set_forward(platform: str, user_id: str, user_upn: str,
                forward_to: str = "", enabled: bool = True) -> tuple[bool, str]:
    """
    Enable or disable call forwarding for a user on the given platform.

    Returns (ok: bool, message: str)
    """
    platform = (platform or "teams").lower()

    if platform == "teams":
        return _set_forward_teams(user_id, user_upn, forward_to, enabled)
    elif platform == "webex":
        return _set_forward_webex(user_id, forward_to, enabled)
    elif platform == "cucm":
        return _set_forward_cucm(user_upn, forward_to, enabled)
    else:
        return False, f"Unknown platform: {platform}"


def get_forward_status(platform: str, user_id: str, user_upn: str) -> dict:
    """
    Get current call forwarding status for a user on the given platform.
    Returns dict with at minimum: {'ok': bool, 'enabled': bool, 'destination': str}
    """
    platform = (platform or "teams").lower()
    try:
        if platform == "teams":
            return _get_status_teams(user_id, user_upn)
        elif platform == "webex":
            return _get_status_webex(user_id)
        elif platform == "cucm":
            return {"ok": True, "enabled": False, "destination": "",
                    "note": "CUCM forwarding status via AXL not implemented"}
        return {"ok": False, "enabled": False, "destination": "", "error": f"Unknown platform: {platform}"}
    except Exception as e:
        return {"ok": False, "enabled": False, "destination": "", "error": str(e)}


# ── Teams ─────────────────────────────────────────────────────

def _set_forward_teams(user_id: str, user_upn: str,
                       forward_to: str, enabled: bool) -> tuple[bool, str]:
    from app.utils.graph_api import set_call_forwarding
    try:
        sip = f"sip:{user_upn}" if user_upn else ""
        ok = set_call_forwarding(user_id, sip, forward_to=forward_to, enabled=enabled)
        return bool(ok), f"Teams forwarding {'enabled' if enabled else 'disabled'}"
    except Exception as e:
        log.error("Teams forward error: %s", e)
        return False, str(e)


def _get_status_teams(user_id: str, user_upn: str) -> dict:
    from app.utils.graph_api import get_call_forwarding
    raw = get_call_forwarding(user_id)
    fwd = raw.get("forwardingSettings", {})
    return {
        "ok": True,
        "enabled": fwd.get("isEnabled", False),
        "destination": fwd.get("target", ""),
        "raw": raw,
    }


# ── Webex ─────────────────────────────────────────────────────

def _set_forward_webex(person_id: str, forward_to: str, enabled: bool) -> tuple[bool, str]:
    from app.utils.webex_api import set_webex_call_forward
    try:
        set_webex_call_forward(person_id, forward_to, enabled=enabled)
        return True, f"Webex forwarding {'enabled' if enabled else 'disabled'}"
    except Exception as e:
        log.error("Webex forward error: %s", e)
        return False, str(e)


def _get_status_webex(person_id: str) -> dict:
    from app.utils.webex_api import get_webex_call_forward
    try:
        raw  = get_webex_call_forward(person_id)
        always = raw.get("callForwarding", {}).get("always", {})
        return {
            "ok": True,
            "enabled": always.get("enabled", False),
            "destination": always.get("destination", ""),
            "raw": raw,
        }
    except Exception as e:
        return {"ok": False, "enabled": False, "destination": "", "error": str(e)}


# ── CUCM ─────────────────────────────────────────────────────

def _set_forward_cucm(userid: str, forward_to: str, enabled: bool) -> tuple[bool, str]:
    """
    Set call forward all via AXL updateLine on the user's primary DN.
    If enabled=False, clears the callForwardAll destination.
    """
    from app.utils.cucm_api import _soap_request
    import re

    # Get the user's primary DN first
    try:
        body = f"<ns:getUser><userid>{userid}</userid></ns:getUser>"
        xml  = _soap_request(body)
        m = re.search(r"<pattern>(.*?)</pattern>", xml, re.DOTALL)
        if not m:
            return False, f"Could not find primary DN for CUCM user '{userid}'"
        pattern = m.group(1).strip()
    except Exception as e:
        return False, f"CUCM getUser failed: {e}"

    # Update callForwardAll on that line
    try:
        dest_xml = f"<forwardDestination>{forward_to}</forwardDestination>" if enabled and forward_to else ""
        body = f"""<ns:updateLine>
  <pattern>{pattern}</pattern>
  <callForwardAll>
    <forwardToVoiceMail>false</forwardToVoiceMail>
    {dest_xml}
  </callForwardAll>
</ns:updateLine>"""
        _soap_request(body)
        return True, f"CUCM CFA {'set to ' + forward_to if enabled else 'cleared'} for {pattern}"
    except Exception as e:
        log.error("CUCM forward error: %s", e)
        return False, str(e)
