"""RELAY — LDAP Server management blueprint. Mounted at /admin/ldap"""
from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, jsonify)
from flask_login import login_required, current_user
from functools import wraps
from datetime import datetime
from app import db
from app.models import LdapServer, User, log_audit

ldap_bp = Blueprint("ldap_mgmt", __name__)


def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if not current_user.is_admin():
            flash("Administrator access required.", "danger")
            return redirect(url_for("schedule_csv.index"))
        return fn(*args, **kwargs)
    return wrapper


@ldap_bp.route("/")
@admin_required
def index():
    servers    = LdapServer.query.order_by(LdapServer.name).all()
    ldap_users = User.query.filter(User.ldap_server_id != None).order_by(User.username).all()
    return render_template("admin/ldap.html", servers=servers, ldap_users=ldap_users)


@ldap_bp.route("/add", methods=["POST"])
@admin_required
def add_server():
    s = LdapServer(
        name        = request.form.get("name", "").strip(),
        host        = request.form.get("host", "").strip(),
        port        = int(request.form.get("port") or 389),
        bind_dn     = request.form.get("bind_dn",     "").strip(),
        base_dn     = request.form.get("base_dn",     "").strip(),
        user_filter = request.form.get("user_filter") or "(objectClass=person)",
        attr_name   = request.form.get("attr_name")  or "displayName",
        attr_email  = request.form.get("attr_email") or "mail",
        attr_uid    = request.form.get("attr_uid")   or "sAMAccountName",
        attr_phone  = request.form.get("attr_phone") or "telephoneNumber",
        use_ssl     = "use_ssl" in request.form,
        use_tls     = "use_tls" in request.form,
        added_by    = current_user.username,
    )
    if request.form.get("bind_password"):
        s.bind_password = request.form["bind_password"]
    if not s.name or not s.host:
        flash("Name and Host are required.", "danger")
        return redirect(url_for("ldap_mgmt.index"))
    db.session.add(s); db.session.commit()
    log_audit("CREATE", "ldap_server", s.id, f"Added LDAP server: {s.name} ({s.host})")
    flash(f"LDAP server '{s.name}' added.", "success")
    return redirect(url_for("ldap_mgmt.index"))


@ldap_bp.route("/<int:sid>/edit", methods=["POST"])
@admin_required
def edit_server(sid):
    s = LdapServer.query.get_or_404(sid)
    for field in ("name","host","bind_dn","base_dn","user_filter",
                  "attr_name","attr_email","attr_uid","attr_phone"):
        v = request.form.get(field, "").strip()
        if v: setattr(s, field, v)
    s.port    = int(request.form.get("port") or s.port)
    s.use_ssl = "use_ssl" in request.form
    s.use_tls = "use_tls" in request.form
    if request.form.get("bind_password"):
        s.bind_password = request.form["bind_password"]
    db.session.commit()
    log_audit("UPDATE", "ldap_server", sid, f"Updated: {s.name}")
    flash(f"'{s.name}' updated.", "success")
    return redirect(url_for("ldap_mgmt.index"))


@ldap_bp.route("/<int:sid>/toggle", methods=["POST"])
@admin_required
def toggle_server(sid):
    s = LdapServer.query.get_or_404(sid)
    s.is_active = not s.is_active; db.session.commit()
    flash(f"'{s.name}' {'enabled' if s.is_active else 'paused'}.", "info")
    return redirect(url_for("ldap_mgmt.index"))


@ldap_bp.route("/<int:sid>/delete", methods=["POST"])
@admin_required
def delete_server(sid):
    s = LdapServer.query.get_or_404(sid); name = s.name
    User.query.filter_by(ldap_server_id=sid).update(
        {"ldap_server_id": None}, synchronize_session=False)
    db.session.delete(s); db.session.commit()
    log_audit("DELETE", "ldap_server", sid, f"Deleted: {name}")
    flash(f"'{name}' removed.", "warning")
    return redirect(url_for("ldap_mgmt.index"))


@ldap_bp.route("/<int:sid>/test")
@admin_required
def test_server(sid):
    from app.utils.ldap_sync import test_connection
    s      = LdapServer.query.get_or_404(sid)
    result = test_connection(s)
    log_audit("ACTION", "ldap_server", sid,
              f"Connection test {s.name}: {'OK' if result['ok'] else 'FAIL'}")
    return jsonify(result)


@ldap_bp.route("/<int:sid>/sync", methods=["POST"])
@admin_required
def sync_server(sid):
    from app.utils.ldap_sync import sync_users
    from flask import current_app
    s      = LdapServer.query.get_or_404(sid)
    result = sync_users(s, current_app.app_context())
    s.last_sync_at    = datetime.utcnow()
    s.last_sync_ok    = result["ok"]
    s.last_sync_msg   = result["message"]
    s.last_sync_count = result.get("created", 0) + result.get("updated", 0)
    db.session.commit()
    log_audit("ACTION", "ldap_server", sid, f"Sync {s.name}: {result['message']}")
    flash(result["message"], "success" if result["ok"] else "danger")
    return redirect(url_for("ldap_mgmt.index"))


@ldap_bp.route("/sync-all", methods=["POST"])
@admin_required
def sync_all():
    from app.utils.ldap_sync import sync_users
    from flask import current_app
    servers = LdapServer.query.filter_by(is_active=True).all()
    total_c = total_u = 0
    for s in servers:
        r = sync_users(s, current_app.app_context())
        s.last_sync_at    = datetime.utcnow()
        s.last_sync_ok    = r["ok"]
        s.last_sync_msg   = r["message"]
        s.last_sync_count = r.get("created", 0) + r.get("updated", 0)
        total_c += r.get("created", 0); total_u += r.get("updated", 0)
    db.session.commit()
    log_audit("ACTION", "ldap_server", None,
              f"Bulk sync: {total_c} created, {total_u} updated")
    flash(f"All servers synced — {total_c} created, {total_u} updated.", "success")
    return redirect(url_for("ldap_mgmt.index"))


@ldap_bp.route("/user/<int:uid>/platform", methods=["POST"])
@admin_required
def set_user_platform(uid):
    user = User.query.get_or_404(uid)
    user.user_platform = request.form.get("user_platform") or None
    db.session.commit()
    log_audit("UPDATE", "user", uid,
              f"Platform set to {user.user_platform} for {user.username}")
    return jsonify({"ok": True, "platform": user.user_platform})


@ldap_bp.route("/user/<int:uid>/role", methods=["POST"])
@admin_required
def set_user_role(uid):
    """Set the RELAY application role for an LDAP-synced user."""
    user = User.query.get_or_404(uid)
    new_role = request.form.get("relay_role", "standard")
    valid = ("standard", "supervisor", "manager", "readonly")
    if new_role not in valid:
        return jsonify({"ok": False, "error": "Invalid role"}), 400
    user.relay_role = new_role
    db.session.commit()
    log_audit("UPDATE", "user", uid,
              f"Relay role set to {new_role} for {user.username}")
    return jsonify({"ok": True, "relay_role": new_role})


@ldap_bp.route("/bulk-assign-roles", methods=["POST"])
@admin_required
def bulk_assign_roles():
    """
    Assign relay_role to all users matching an LDAP group / OU filter.
    Expects: ldap_server_id, group_dn (or ou), relay_role
    """
    sid      = request.form.get("ldap_server_id")
    group_dn = request.form.get("group_dn", "").strip()
    role     = request.form.get("relay_role", "standard")
    srv      = LdapServer.query.get_or_404(sid)

    from app.utils.ldap_sync import _make_connection
    try:
        conn = _make_connection(srv)
        conn.search(search_base=group_dn,
                    search_filter="(objectClass=person)",
                    attributes=[srv.attr_uid])
        entries = list(conn.entries)
        conn.unbind()
    except Exception as e:
        flash(f"LDAP query failed: {e}", "danger")
        return redirect(url_for("ldap_mgmt.index"))

    updated = 0
    for entry in entries:
        uid_val = str(entry[srv.attr_uid]) if srv.attr_uid in entry else None
        if uid_val:
            user = User.query.filter_by(username=uid_val).first()
            if user:
                user.relay_role = role
                updated += 1
    db.session.commit()
    log_audit("UPDATE", "user", None,
              f"Bulk role assign: {updated} users → {role} from {group_dn}")
    flash(f"{updated} user(s) assigned role '{role}' from LDAP group.", "success")
    return redirect(url_for("ldap_mgmt.index"))
