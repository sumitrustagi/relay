"""RELAY — Webex Calling extension / user lookup blueprint. Mounted at /webex"""
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from app.utils.webex_api import search_webex_users, get_webex_user_by_email

webex_ext_bp = Blueprint("webex_extension", __name__)


@webex_ext_bp.route("/")
@login_required
def index():
    # Platform guard: only admin can access all platforms.
    # Superuser and user can only access their own assigned platform.
    if not current_user.is_admin() and current_user.user_platform != 'webex':
        from flask import flash, redirect, url_for
        flash(f"You are assigned to {current_user.user_platform or 'no'} platform — Webex access is not available for your account.", "warning")
        return redirect(url_for("schedule_csv.index"))
    return render_template("webex_lookup.html")


@webex_ext_bp.route("/lookup")
@login_required
def lookup():
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify([])
    try:
        if "@" in query:
            user = get_webex_user_by_email(query)
            users = [user] if user else []
        else:
            users = search_webex_users(query)
        results = [
            {
                "displayName": u.get("displayName", ""),
                "upn":         (u.get("emails", [u.get("email", "")])[0]
                                if isinstance(u.get("emails"), list)
                                else u.get("email", "")),
                "email":       (u.get("emails", [u.get("email", "")])[0]
                                if isinstance(u.get("emails"), list)
                                else u.get("email", "")),
                "phones":      u.get("phoneNumbers", []),
                "extension":   u.get("extension", ""),
                "id":          u.get("id", ""),
                "orgId":       u.get("orgId", ""),
                "status":      u.get("status", ""),
            }
            for u in users if u
        ]
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@webex_ext_bp.route("/forward", methods=["POST"])
@login_required
def set_forward():
    """Enable or disable call forwarding for a Webex user."""
    from app.utils.forwarder import set_forward as _sf
    from app.models import log_audit

    person_id  = request.form.get("person_id",  "").strip()
    user_upn   = request.form.get("user_upn",   "").strip()  # email
    forward_to = request.form.get("forward_to", "").strip()
    action     = request.form.get("action", "enable")
    enabled    = action == "enable"

    if not current_user.can_manage_others():
        # Regular users may only forward their own extension
        own = (current_user.webex_extension or current_user.teams_upn or "").lower()
        if user_upn.lower() != own:
            return jsonify({"ok": False,
                            "error": "You can only manage your own forwarding."}), 403

    ok, msg = _sf("webex", person_id, user_upn,
                  forward_to=forward_to if enabled else "",
                  enabled=enabled)
    log_audit("UPDATE", "call_forward", None,
              f"{current_user.username} [webex] {'ON' if enabled else 'OFF'} "
              f"for {user_upn} → {forward_to}")
    return jsonify({"ok": ok, "message": msg})
