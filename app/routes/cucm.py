"""RELAY — Cisco CUCM blueprint. Mounted at /cucm"""
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from app.utils.cucm_api import search_cucm_users, get_cucm_user_by_id

cucm_bp = Blueprint("cucm", __name__)


@cucm_bp.route("/")
@login_required
def index():
    # Platform guard: only admin can access all platforms.
    # Superuser and user can only access their own assigned platform.
    if not current_user.is_admin() and current_user.user_platform != 'cucm':
        from flask import flash, redirect, url_for
        flash(f"You are assigned to {current_user.user_platform or 'no'} platform — CUCM access is not available for your account.", "warning")
        return redirect(url_for("schedule_csv.index"))
    return render_template("cucm_lookup.html")


@cucm_bp.route("/lookup")
@login_required
def lookup():
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify([])
    try:
        users = search_cucm_users(query)
        # Normalise to shape expected by schedule modal JS:
        # {displayName, upn (userid), id, phones, extension}
        normalised = [
            {
                "displayName": u.get("fullName") or
                               f"{u.get('firstName','')} {u.get('lastName','')}".strip(),
                "upn":         u.get("userid", ""),      # userid used as UPN for CUCM
                "userid":      u.get("userid", ""),
                "id":          u.get("userid", ""),      # no separate CUCM person ID
                "firstName":   u.get("firstName", ""),
                "lastName":    u.get("lastName", ""),
                "department":  u.get("department", ""),
                "extension":   u.get("primaryExtension", ""),
                "phones":      [u["telephoneNumber"]] if u.get("telephoneNumber") else [],
            }
            for u in users if u
        ]
        return jsonify(normalised)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@cucm_bp.route("/user/<uid>")
@login_required
def user_detail(uid):
    try:
        detail = get_cucm_user_by_id(uid)
        return jsonify(detail)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@cucm_bp.route("/forward", methods=["POST"])
@login_required
def set_forward():
    """Enable or disable call forward all for a CUCM user."""
    from app.utils.forwarder import set_forward as _sf
    from app.models import log_audit

    userid     = request.form.get("userid",     "").strip()
    forward_to = request.form.get("forward_to", "").strip()
    action     = request.form.get("action", "enable")
    enabled    = action == "enable"

    if not current_user.can_manage_others():
        own = (current_user.teams_upn or "").lower()
        if userid.lower() != own:
            return jsonify({"ok": False,
                            "error": "You can only manage your own forwarding."}), 403

    ok, msg = _sf("cucm", "", userid,
                  forward_to=forward_to if enabled else "",
                  enabled=enabled)
    log_audit("UPDATE", "call_forward", None,
              f"{current_user.username} [cucm] {'ON' if enabled else 'OFF'} "
              f"for {userid} → {forward_to}")
    return jsonify({"ok": ok, "message": msg})
