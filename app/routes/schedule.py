"""
RELAY — Manual Forward blueprint (cross-platform).
Mounted at /schedule/

- GET  /schedule/           — Manual Forward HTML page
- GET  /schedule/status     — JSON: forwarding status for current user
- POST /schedule/toggle     — enable/disable forwarding for current user
- POST /schedule/forward    — admin/superuser: forward any number/user
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from app.models import log_audit

schedule_bp = Blueprint("schedule", __name__)


def _resolve_user_identity():
    platform = current_user.user_platform or "teams"
    user_id  = (current_user.teams_extension or "").strip()
    user_upn = (current_user.teams_upn or current_user.webex_extension or
                current_user.cucm_extension or "").strip()
    if current_user.can_manage_others():
        return platform, user_id, user_upn, None
    if not user_id and not user_upn:
        return platform, "", "", (
            "No platform extension is assigned to your account. "
            "Contact your admin to set your Teams UPN, Webex extension, or CUCM user ID."
        )
    return platform, user_id, user_upn, None


# ── HTML page ──────────────────────────────────────────────────
@schedule_bp.route("/")
@login_required
def index():
    """Render the Manual Forward page."""
    platform, user_id, user_upn, _err = _resolve_user_identity()
    return render_template("manual_forward.html",
                           own_upn=user_upn,
                           own_id=user_id,
                           own_platform=platform)


# Keep /status for backwards compat (sidebar link) — redirect to index
@schedule_bp.route("/status")
@login_required
def status():
    return redirect(url_for("schedule.index"))


@schedule_bp.route("/api-status")
@login_required
def api_status():
    """JSON: return current live forwarding status for the logged-in user."""
    platform, user_id, user_upn, err = _resolve_user_identity()
    if err:
        return jsonify({"error": err, "platform": platform})
    if current_user.can_manage_others() and not user_id and not user_upn:
        return jsonify({"platform": platform, "enabled": False, "destination": "",
                        "note": "Admin/superuser — use platform lookup pages."})
    try:
        from app.utils.forwarder import get_forward_status
        result = get_forward_status(platform, user_id, user_upn)
        result["platform"] = platform
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e), "platform": platform}), 500


# ── Toggle own forwarding ─────────────────────────────────────
@schedule_bp.route("/toggle", methods=["POST"])
@login_required
def toggle():
    """Enable or disable forwarding for the current user's own extension."""
    platform, user_id, user_upn, err = _resolve_user_identity()
    if err:
        flash(err, "danger")
        return redirect(url_for("schedule.index"))

    enabled = request.form.get("enabled", "") == "1"
    fwd_to  = request.form.get("forward_to", "").strip()

    if enabled and not fwd_to:
        flash("Forward-to number is required when enabling forwarding.", "warning")
        return redirect(url_for("schedule.index"))

    from app.utils.forwarder import set_forward
    ok, msg = set_forward(platform, user_id, user_upn,
                          forward_to=fwd_to if enabled else "",
                          enabled=enabled)
    log_audit("UPDATE", "call_forward", None,
              f"{current_user.username} [{platform}] "
              f"{'ENABLED' if enabled else 'DISABLED'} → {fwd_to}")
    flash(f"Forwarding {'enabled' if enabled else 'disabled'}: {msg}",
          "success" if ok else "danger")
    return redirect(url_for("schedule.index"))


# ── Admin/superuser: forward any number ──────────────────────
@schedule_bp.route("/forward", methods=["POST"])
@login_required
def forward_other():
    """
    Forward any user on any platform. Accepts either:
    - user_upn/user_id (from lookup pages, schedules)
    - source_number: a plain E.164 or extension number — RELAY will
      resolve to the correct user via the platform lookup APIs.
    Returns JSON.
    """
    if not current_user.can_manage_others():
        return jsonify({"ok": False, "error": "Permission denied."}), 403

    platform      = request.form.get("platform",      "teams").strip()
    user_id       = request.form.get("user_id",       "").strip()
    user_upn      = request.form.get("user_upn",      "").strip()
    source_number = request.form.get("source_number", "").strip()
    fwd_to        = request.form.get("forward_to",    "").strip()
    enabled       = request.form.get("enabled", "1") == "1"

    # Superusers are restricted to their own assigned platform.
    # Force the platform to their user_platform regardless of what was POSTed.
    if not current_user.is_admin():
        own_platform = current_user.user_platform or "teams"
        if platform != own_platform:
            return jsonify({
                "ok": False,
                "error": f"You are assigned to {own_platform} — you cannot forward on {platform}."
            }), 403
        platform = own_platform

    # If only a source_number was given (from the Manual Forward form),
    # try to resolve it to a user via the platform lookup APIs.
    if source_number and not user_id and not user_upn:
        resolved = _resolve_number_to_user(platform, source_number)
        user_id  = resolved.get("user_id",  "")
        user_upn = resolved.get("user_upn", source_number)  # fall back to number itself

    if not user_id and not user_upn:
        return jsonify({"ok": False,
                        "error": "Please provide a phone number, extension, UPN, or email."}), 400

    from app.utils.forwarder import set_forward
    ok, msg = set_forward(platform, user_id, user_upn,
                          forward_to=fwd_to if enabled else "",
                          enabled=enabled)
    log_audit("UPDATE", "call_forward", None,
              f"{current_user.username} [{platform}] "
              f"{'ON' if enabled else 'OFF'} for {source_number or user_upn or user_id}"
              f" → {fwd_to}")
    return jsonify({"ok": ok, "message": msg, "platform": platform,
                    "resolved_upn": user_upn, "resolved_id": user_id})


def _resolve_number_to_user(platform: str, number: str) -> dict:
    """
    Given a phone number or extension, try to find the matching user's
    platform identifiers (user_id, user_upn).

    Teams  → search graph API by number via get_user_teams_phone reverse lookup
    Webex  → search people API by phone number
    CUCM   → search AXL by telephoneNumber / primaryExtension
    Returns dict with user_id and user_upn (empty strings if not found).
    """
    try:
        if platform == "teams":
            from app.models import PhoneNumber
            norm = "".join(c for c in number if c.isdigit())
            pn = PhoneNumber.query.filter_by(platform="teams", number_norm=norm).first()
            if pn and pn.assigned_to:
                return {"user_id": pn.assigned_to, "user_upn": pn.assigned_to}
        elif platform == "webex":
            from app.utils.webex_api import search_webex_users
            results = search_webex_users(number, max_results=3)
            for u in results:
                phones = u.get("phoneNumbers", [])
                for p in phones:
                    val = p.get("value", "") if isinstance(p, dict) else str(p)
                    norm_p = "".join(c for c in val if c.isdigit())
                    norm_n = "".join(c for c in number if c.isdigit())
                    if norm_p == norm_n or norm_n in norm_p:
                        return {"user_id": u.get("id",""), "user_upn": (u.get("emails",[""])[0] if isinstance(u.get("emails"),list) else "")}
        elif platform == "cucm":
            from app.utils.cucm_api import search_cucm_users
            results = search_cucm_users(number, max_results=5)
            for u in results:
                tn = u.get("telephoneNumber","")
                ext = u.get("primaryExtension","")
                norm_n = "".join(c for c in number if c.isdigit())
                if "".join(c for c in tn if c.isdigit()) == norm_n or \
                   "".join(c for c in ext if c.isdigit()) == norm_n:
                    return {"user_id": "", "user_upn": u.get("userid","")}
    except Exception:
        pass
    return {"user_id": "", "user_upn": ""}
