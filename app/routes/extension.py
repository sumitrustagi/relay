"""RELAY — Teams extension lookup & manual forwarding."""
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from app.utils.graph_api import get_user_by_upn, search_users

extension_bp = Blueprint("extension", __name__)


@extension_bp.route("/")
@login_required
def index():
    # Platform guard: only admin can access all platforms.
    # Superuser and user can only access their own assigned platform.
    if not current_user.is_admin() and current_user.user_platform != 'teams':
        from flask import flash, redirect, url_for
        flash(f"You are assigned to {current_user.user_platform or 'no'} platform — Teams access is not available for your account.", "warning")
        return redirect(url_for("schedule_csv.index"))
    return render_template("extension_lookup.html",
                           can_manage_others=current_user.can_manage_others(),
                           own_upn=current_user.teams_upn or "")


@extension_bp.route("/lookup")
@login_required
def lookup():
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify([])

    # Regular users can only search their own UPN/extension
    if not current_user.can_manage_others():
        own_upn = current_user.teams_upn or ""
        # Allow only if query matches their own UPN or extension
        if own_upn.lower() not in query.lower() and query.lower() not in own_upn.lower():
            return jsonify({"error": "You can only look up your own number. Contact an admin to search other users."}), 403

    try:
        if "@" in query:
            user = get_user_by_upn(query)
            users = [user] if user else []
        else:
            users = search_users(query)
        results = [
            {
                "displayName": u.get("displayName", ""),
                "upn":         u.get("userPrincipalName", ""),
                "phones":      u.get("businessPhones", []),
                "id":          u.get("id", ""),
                "mail":        u.get("mail", ""),
            }
            for u in users
        ]
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@extension_bp.route("/forward", methods=["POST"])
@login_required
def set_forward():
    """Enable or disable call forwarding for a Teams user.
    Superuser and admin can set forwarding for any user.
    Regular users can only set forwarding for their own UPN.
    """
    from app.utils.graph_api import set_call_forwarding, get_teams_token
    from app.models import MSGraphConfig, log_audit
    from app import db

    person_id  = request.form.get("person_id", "").strip()
    target_upn = request.form.get("teams_upn", "").strip()
    forward_to = request.form.get("forward_to", "").strip()
    sip_uri    = request.form.get("sip_uri", "").strip()
    action     = request.form.get("action", "enable")  # enable | disable

    # Ownership check for regular users
    if not current_user.can_manage_others():
        own_upn = (current_user.teams_upn or "").lower()
        if target_upn.lower() != own_upn:
            return jsonify({"ok": False,
                            "error": "You can only manage your own call forwarding."}), 403

    try:
        cfg = MSGraphConfig.query.first()
        if not cfg or not cfg.is_configured():
            return jsonify({"ok": False, "error": "Teams API not configured."}), 500
        token = get_teams_token()
        if action == "disable":
            ok = set_call_forwarding(person_id, sip_uri or target_upn, forward_to, enabled=False)
        else:
            if not forward_to:
                return jsonify({"ok": False, "error": "Forward-to number required."}), 400
            ok = set_call_forwarding(person_id, sip_uri or target_upn, forward_to, enabled=True)

        log_audit(
            "UPDATE", "call_forwarding", person_id,
            f"{'Enabled' if action=='enable' else 'Disabled'} forwarding "
            f"for {target_upn} → {forward_to} by {current_user.username}"
        )
        return jsonify({"ok": bool(ok),
                        "message": f"Forwarding {'enabled' if action=='enable' else 'disabled'}."})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
