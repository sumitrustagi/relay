"""RELAY Admin Blueprint — users, platform config, DID, audit logs."""
from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, jsonify, Response)
from flask_login import login_required, current_user
from functools import wraps
from app import db
from app.models import (User, MSGraphConfig, WebexConfig, CUCMConfig, PlatformSettings,
                         DIDCountry, DIDRegion, DIDBlock, AuditLog, LdapServer,
                         PhoneNumber, InventorySyncLog,
                         SMTPConfig, CertDevice, CERT_DEVICE_PRODUCTS, log_audit)
import csv, io

admin_bp = Blueprint("admin", __name__)


def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if not current_user.is_admin():
            flash("Administrator access required.", "danger")
            return redirect(url_for("schedule_csv.index"))
        return fn(*args, **kwargs)
    return wrapper


# ── Hub ───────────────────────────────────────────────────────
@admin_bp.route("/")
@admin_required
def index():
    users    = User.query.order_by(User.username).all()
    cfg      = MSGraphConfig.query.first()
    webex_cfg= WebexConfig.get()
    cucm_cfg = CUCMConfig.get()
    smtp_cfg = SMTPConfig.get()
    ps       = PlatformSettings.get()
    return render_template("admin/index.html",
                           users=users, cfg=cfg,
                           webex_cfg=webex_cfg,
                           cucm_cfg=cucm_cfg,
                           smtp_cfg=smtp_cfg,
                           platform_settings=ps)


# ── Platform Settings ─────────────────────────────────────────
@admin_bp.route("/platform-settings", methods=["POST"])
@admin_required
def save_platform_settings():
    ps = PlatformSettings.get()
    ps.client_name      = request.form.get("client_name", "").strip()
    ps.has_teams        = "has_teams"        in request.form
    ps.has_webex        = "has_webex"        in request.form
    ps.has_cucm         = "has_cucm"         in request.form
    ps.has_cert_monitor = "has_cert_monitor" in request.form
    ps.has_did          = "has_did"          in request.form
    ps.has_ldap         = "has_ldap"         in request.form
    db.session.commit()
    try:
        from app.utils.env_manager import write_env_vars
        ps2 = PlatformSettings.get()
        write_env_vars({"HAS_TEAMS": str(ps2.has_teams).lower(), "HAS_WEBEX": str(ps2.has_webex).lower(), "HAS_CUCM": str(ps2.has_cucm).lower(), "HAS_CERT_MONITOR": str(ps2.has_cert_monitor).lower(), "HAS_DID": str(ps2.has_did).lower(), "HAS_LDAP": str(ps2.has_ldap).lower(), "CLIENT_NAME": ps2.client_name or ""})
    except Exception: pass
    log_audit("UPDATE", "platform_settings", detail="Platform settings updated")
    flash("Platform settings saved.", "success")
    return redirect(url_for("admin.index"))


# ── MS Graph / Teams config ───────────────────────────────────
@admin_bp.route("/graph-config", methods=["POST"])
@admin_required
def save_graph_config():
    cfg = MSGraphConfig.query.first() or MSGraphConfig()
    cfg.tenant_id                = request.form.get("tenant_id", "").strip()
    cfg.client_id                = request.form.get("client_id", "").strip()
    if request.form.get("client_secret"):
        cfg.client_secret        = request.form["client_secret"]
    cfg.service_account_upn      = request.form.get("service_account_upn", "").strip()
    if request.form.get("service_account_password"):
        cfg.service_account_password = request.form["service_account_password"]
    db.session.add(cfg); db.session.commit()
    try:
        from app.utils.env_manager import write_env_vars
        write_env_vars({"TEAMS_TENANT_ID": cfg.tenant_id or "", "TEAMS_CLIENT_ID": cfg.client_id or "", "TEAMS_CLIENT_SECRET": cfg.client_secret or "", "TEAMS_SVC_UPN": cfg.service_account_upn or ""})
    except Exception: pass
    log_audit("UPDATE", "graph_config", detail="Teams/Graph API config updated")
    flash("Teams configuration saved.", "success")
    return redirect(url_for("admin.index"))


@admin_bp.route("/graph-config/refresh-token", methods=["POST"])
@admin_required
def refresh_tokens():
    from app.utils.graph_api import get_graph_token, get_teams_token
    errors = []
    cfg = MSGraphConfig.query.first()
    if cfg:
        cfg.graph_access_token = None
        cfg.teams_access_token = None
        db.session.commit()
    for fn, label in [(get_graph_token, "Graph"), (get_teams_token, "Teams")]:
        try:
            fn()
        except Exception as e:
            errors.append(f"{label}: {e}")
    if errors:
        flash("Errors: " + "; ".join(errors), "warning")
    else:
        flash("Tokens refreshed successfully.", "success")
    return redirect(url_for("admin.index"))


# ── Webex config ──────────────────────────────────────────────
@admin_bp.route("/webex-config", methods=["POST"])
@admin_required
def save_webex_config():
    w = WebexConfig.get()
    if request.form.get("client_id"):     w.client_id     = request.form["client_id"]
    if request.form.get("client_secret"): w.client_secret = request.form["client_secret"]
    if request.form.get("refresh_token"): w.refresh_token = request.form["refresh_token"]
    if request.form.get("access_token"):  w.access_token  = request.form["access_token"]
    if request.form.get("org_id"):        w.org_id        = request.form["org_id"]
    db.session.commit()
    try:
        from app.utils.env_manager import write_env_vars
        w2 = WebexConfig.get()
        write_env_vars({"WEBEX_CLIENT_ID": w2.client_id or "", "WEBEX_CLIENT_SECRET": w2.client_secret or "", "WEBEX_REFRESH_TOKEN": w2.refresh_token or "", "WEBEX_ORG_ID": w2.org_id or ""})
    except Exception: pass
    log_audit("UPDATE", "webex_config", detail="Webex config updated")
    flash("Webex configuration saved.", "success")
    return redirect(url_for("admin.index"))


# ── CUCM config ───────────────────────────────────────────────
@admin_bp.route("/cucm-config", methods=["POST"])
@admin_required
def save_cucm_config():
    from app.models import CUCMConfig
    c = CUCMConfig.get()
    if request.form.get("cucm_host"):     c.cucm_host     = request.form["cucm_host"].strip()
    if request.form.get("cucm_username"): c.cucm_username = request.form["cucm_username"].strip()
    if request.form.get("cucm_password"): c.cucm_password = request.form["cucm_password"]
    if request.form.get("cucm_version"):  c.cucm_version  = request.form["cucm_version"].strip()
    c.verify_ssl = "verify_ssl" in request.form
    db.session.commit()
    try:
        from app.utils.env_manager import write_env_vars
        from app.models import CUCMConfig as _CC; c2 = _CC.get()
        write_env_vars({"CUCM_HOST": c2.cucm_host or "", "CUCM_USERNAME": c2.cucm_username or "", "CUCM_VERSION": c2.cucm_version or "12.5"})
    except Exception: pass
    log_audit("UPDATE", "cucm_config", detail="CUCM config updated")
    flash("CUCM configuration saved.", "success")
    return redirect(url_for("admin.index"))


@admin_bp.route("/cucm-config/test", methods=["POST"])
@admin_required
def test_cucm_config():
    from app.utils.cucm_api import test_cucm_connection
    result = test_cucm_connection()
    if result["ok"]:
        flash(f"CUCM connection OK — version: {result.get('version', 'unknown')}", "success")
    else:
        flash(f"CUCM connection failed: {result.get('error', 'unknown error')}", "danger")
    return redirect(url_for("admin.index"))


# ── SMTP config ───────────────────────────────────────────────
@admin_bp.route("/smtp-config", methods=["POST"])
@admin_required
def save_smtp_config():
    s = SMTPConfig.get()
    s.host      = request.form.get("host",      "").strip()
    s.port      = int(request.form.get("port",  587) or 587)
    s.username  = request.form.get("username",  "").strip() or None
    if request.form.get("password"):
        s.password = request.form["password"]
    s.use_tls   = "use_tls"   in request.form
    s.use_ssl   = "use_ssl"   in request.form
    s.from_addr = request.form.get("from_addr", "").strip() or None
    s.from_name = request.form.get("from_name", "").strip() or None
    s.alert_to  = request.form.get("alert_to",  "").strip() or None
    s.enabled   = "enabled"   in request.form
    db.session.commit()
    try:
        from app.utils.env_manager import write_env_vars
        write_env_vars({
            "SMTP_HOST":      s.host      or "",
            "SMTP_PORT":      str(s.port  or 587),
            "SMTP_USERNAME":  s.username  or "",
            "SMTP_USE_TLS":   str(s.use_tls).lower(),
            "SMTP_USE_SSL":   str(s.use_ssl).lower(),
            "SMTP_FROM_ADDR": s.from_addr or "",
            "SMTP_FROM_NAME": s.from_name or "",
            "SMTP_ALERT_TO":  s.alert_to  or "",
            "SMTP_ENABLED":   str(s.enabled).lower(),
        })
    except Exception: pass
    log_audit("UPDATE", "smtp_config", detail="SMTP config updated")
    flash("SMTP configuration saved.", "success")
    return redirect(url_for("admin.index"))


@admin_bp.route("/smtp-config/test", methods=["POST"])
@admin_required
def test_smtp():
    # Correct import: mailer.send_test_email(), NOT a non-existent app.utils.smtp module
    from app.utils.mailer import send_test_email
    result = send_test_email()
    if result.get("ok"):
        flash("Test email sent successfully.", "success")
    else:
        flash(f"SMTP test failed: {result.get('error', 'unknown error')}", "danger")
    return redirect(url_for("admin.index"))


# ── User management ───────────────────────────────────────────
@admin_bp.route("/user/create", methods=["POST"])
@admin_required
def create_user():
    username = request.form.get("username", "").strip()
    email    = request.form.get("email",    "").strip()
    password = request.form.get("password", "")
    role     = request.form.get("role", "user")

    # Allowlist — prevent form-stuffing with arbitrary role strings
    VALID_ROLES = ("admin", "superuser", "user")
    if role not in VALID_ROLES:
        role = "user"

    if not username or not email or not password:
        flash("Username, email, and password are all required.", "danger")
        return redirect(url_for("admin.index"))
    if User.query.filter_by(username=username).first():
        flash(f"Username '{username}' already exists.", "danger")
        return redirect(url_for("admin.index"))
    if User.query.filter_by(email=email).first():
        flash(f"Email '{email}' is already in use.", "danger")
        return redirect(url_for("admin.index"))

    u = User(
        username        = username,
        email           = email,
        role            = role,
        teams_upn       = request.form.get("teams_upn",       "").strip() or None,
        teams_extension = request.form.get("teams_extension", "").strip() or None,
        user_platform   = request.form.get("user_platform",   "teams") or "teams",
    )
    u.set_password(password)
    db.session.add(u); db.session.commit()
    log_audit("CREATE", "user", u.id, f"Created user '{username}' role={role}")
    flash(f"User '{username}' created with role: {role}.", "success")
    return redirect(url_for("admin.index"))


@admin_bp.route("/user/<int:uid>/set-extension", methods=["POST"])
@admin_required
def assign_extension(uid):
    u = User.query.get_or_404(uid)
    u.teams_extension = request.form.get("teams_extension", "").strip() or None
    u.teams_upn       = request.form.get("teams_upn",       "").strip() or None
    db.session.commit()
    log_audit("UPDATE", "user", uid, f"Extension updated for {u.username}")
    flash(f"Extension updated for {u.username}.", "success")
    return redirect(url_for("admin.index"))


@admin_bp.route("/user/<int:uid>/reset-password", methods=["POST"])
@admin_required
def reset_password(uid):
    u = User.query.get_or_404(uid)
    u.set_password(request.form.get("new_password", ""))
    db.session.commit()
    log_audit("UPDATE", "user", uid, f"Password reset for {u.username}")
    flash(f"Password reset for {u.username}.", "success")
    return redirect(url_for("admin.index"))


@admin_bp.route("/user/<int:uid>/toggle", methods=["POST"])
@admin_required
def toggle_user(uid):
    u = User.query.get_or_404(uid)
    u.is_active = not u.is_active; db.session.commit()
    log_audit("UPDATE", "user", uid, f"User {u.username} active={u.is_active}")
    flash(f"User {u.username} {'enabled' if u.is_active else 'disabled'}.", "info")
    return redirect(url_for("admin.index"))


@admin_bp.route("/user/<int:uid>/delete", methods=["POST"])
@admin_required
def delete_user(uid):
    u = User.query.get_or_404(uid)
    if u.id == current_user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin.index"))
    name = u.username; db.session.delete(u); db.session.commit()
    log_audit("DELETE", "user", uid, f"Deleted user {name}")
    flash(f"User '{name}' deleted.", "warning")
    return redirect(url_for("admin.index"))


@admin_bp.route("/user/<int:uid>/change-role", methods=["POST"])
@admin_required
def change_role(uid):
    """Allow admin to change an existing user's role (admin / superuser / user)."""
    u    = User.query.get_or_404(uid)
    new_role = request.form.get("role", "user")
    VALID_ROLES = ("admin", "superuser", "user")
    if new_role not in VALID_ROLES:
        flash(f"Invalid role '{new_role}'.", "danger")
        return redirect(url_for("admin.index"))
    if u.id == current_user.id and new_role != "admin":
        flash("You cannot remove your own admin role.", "danger")
        return redirect(url_for("admin.index"))
    old_role  = u.role
    u.role    = new_role
    db.session.commit()
    log_audit("UPDATE", "user", uid,
              f"Role changed: {u.username} {old_role} → {new_role}")
    flash(f"Role for '{u.username}' changed from {old_role} to {new_role}.", "success")
    return redirect(url_for("admin.index"))


@admin_bp.route("/user/bulk-import", methods=["POST"])
@admin_required
def bulk_import_users():
    f = request.files.get("csv_file")
    if not f:
        flash("No file uploaded.", "danger")
        return redirect(url_for("admin.index"))
    # Persist the file to disk first
    try:
        from app.utils.upload_manager import save_csv
        save_csv(f, current_user.username)
        f.stream.seek(0)
    except Exception:
        f.stream.seek(0)
    reader  = csv.DictReader(io.StringIO(f.read().decode("utf-8-sig")))
    VALID_ROLES = ("admin", "superuser", "user")
    created = 0
    skipped = 0
    for row in reader:
        un = row.get("username", "").strip()
        em = row.get("email",    "").strip()
        pw = row.get("password", "").strip()
        rl = row.get("role",     "user").strip()
        if rl not in VALID_ROLES:
            rl = "user"
        if not un or not em or not pw:
            skipped += 1
            continue
        if User.query.filter_by(username=un).first():
            skipped += 1
            continue
        u = User(
            username      = un,
            email         = em,
            role          = rl,
            teams_upn     = row.get("teams_upn", "").strip() or None,
            user_platform = row.get("platform", "teams").strip() or "teams",
        )
        u.set_password(pw)
        db.session.add(u); created += 1
    db.session.commit()
    log_audit("CREATE", "user", None,
              f"Bulk import: {created} created, {skipped} skipped")
    flash(f"{created} user(s) imported, {skipped} skipped.", "success")
    return redirect(url_for("admin.index"))


# ── Upload management ─────────────────────────────────────────
@admin_bp.route("/uploads/stats")
@admin_required
def upload_stats():
    from app.utils.upload_manager import get_upload_stats
    stats = get_upload_stats()
    return jsonify(stats)


@admin_bp.route("/uploads/rotate", methods=["POST"])
@admin_required
def rotate_uploads():
    from app.utils.upload_manager import rotate_uploads
    result = rotate_uploads()
    log_audit("ACTION", "uploads", None,
              f"Manual rotation: {result['total']} files removed")
    flash(f"Upload rotation complete — {result['total']} old file(s) removed.", "success")
    return redirect(url_for("admin.index"))


@admin_bp.route("/user/bulk-template")
@admin_required
def bulk_import_template():
    si = io.StringIO()
    csv.writer(si).writerows([
        ["username", "email", "password", "role", "platform", "teams_upn", "teams_extension"],
        ["# role values: user | superuser | admin", "", "", "", "", "", ""],
        ["# platform values: teams | webex | cucm", "", "", "", "", "", ""],
        ["jsmith",      "jsmith@example.com",     "Pass@123!", "user",      "teams", "jsmith@tenant.com",     "+3227001234"],
        ["m.dupont",    "m.dupont@example.com",   "Pass@123!", "user",      "webex", "m.dupont@example.com",  "2001"],
        ["helpdesk.su", "hd.su@example.com",      "Pass@123!", "superuser", "teams", "helpdesk@tenant.com",   "+3227009999"],
        ["relay.admin", "relay.admin@example.com","Pass@123!", "admin",     "teams", "relay.admin@tenant.com",""],
    ])
    return Response(si.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":
                             "attachment; filename=relay_users_template.csv"})


# ── DID Management (Geographic Hierarchy) ────────────────────
@admin_bp.route("/did/")
@admin_required
def did_index():
    from app.models import DIDCountry, InventorySyncLog, PhoneNumber
    countries  = DIDCountry.query.order_by(DIDCountry.name).all()
    ps         = PlatformSettings.get()
    sync_logs  = {p: InventorySyncLog.latest(p) for p in ["teams","webex","cucm"]}
    inv_counts = {p: PhoneNumber.query.filter_by(platform=p).count() for p in ["teams","webex","cucm"]}
    return render_template("admin/did_management.html",
                           countries=countries, platform_settings=ps,
                           sync_logs=sync_logs, inv_counts=inv_counts)


# ── Country CRUD ──────────────────────────────────────────────
@admin_bp.route("/did/country/add", methods=["POST"])
@admin_required
def add_country():
    from app.models import DIDCountry
    name = request.form.get("name","").strip()
    iso  = request.form.get("iso_code","").strip().upper()[:2]
    if not name:
        flash("Country name required.", "danger")
        return redirect(url_for("admin.did_index"))
    if DIDCountry.query.filter(db.func.lower(DIDCountry.name)==name.lower()).first():
        flash(f"Country '{name}' already exists.", "warning")
        return redirect(url_for("admin.did_index"))
    c = DIDCountry(name=name, iso_code=iso,
                   notes=request.form.get("notes","").strip(),
                   created_by=current_user.username)
    db.session.add(c); db.session.commit()
    log_audit("CREATE","did_country",c.id,f"Added country: {name}")
    flash(f"Country '{name}' added.", "success")
    return redirect(url_for("admin.did_index"))


@admin_bp.route("/did/country/<int:cid>/delete", methods=["POST"])
@admin_required
def delete_country(cid):
    from app.models import DIDCountry
    c = DIDCountry.query.get_or_404(cid)
    name = c.name; db.session.delete(c); db.session.commit()
    log_audit("DELETE","did_country",cid,f"Deleted country: {name}")
    flash(f"Country '{name}' and all its regions/blocks deleted.", "warning")
    return redirect(url_for("admin.did_index"))


# ── Region CRUD ───────────────────────────────────────────────
@admin_bp.route("/did/country/<int:cid>/region/add", methods=["POST"])
@admin_required
def add_region(cid):
    from app.models import DIDCountry, DIDRegion
    DIDCountry.query.get_or_404(cid)
    name = request.form.get("name","").strip()
    if not name:
        flash("Region name required.", "danger")
        return redirect(url_for("admin.did_index"))
    r = DIDRegion(country_id=cid, name=name,
                  notes=request.form.get("notes","").strip(),
                  created_by=current_user.username)
    db.session.add(r); db.session.commit()
    log_audit("CREATE","did_region",r.id,f"Added region: {name}")
    flash(f"Region '{name}' added.", "success")
    return redirect(url_for("admin.did_index"))


@admin_bp.route("/did/region/<int:rid>/delete", methods=["POST"])
@admin_required
def delete_region(rid):
    from app.models import DIDRegion
    r = DIDRegion.query.get_or_404(rid)
    name = r.name; db.session.delete(r); db.session.commit()
    log_audit("DELETE","did_region",rid,f"Deleted region: {name}")
    flash(f"Region '{name}' deleted.", "warning")
    return redirect(url_for("admin.did_index"))


# ── DID Block CRUD ────────────────────────────────────────────
@admin_bp.route("/did/block/add", methods=["POST"])
@admin_required
def add_did_block():
    from app.models import DIDBlock
    country_id = request.form.get("country_id", type=int)
    region_id  = request.form.get("region_id",  type=int) or None
    start      = request.form.get("start_number","").strip()
    end        = request.form.get("end_number",  "").strip()
    if not country_id or not start or not end:
        flash("Country, start and end number are required.", "danger")
        return redirect(url_for("admin.did_index"))
    b = DIDBlock(
        country_id   = country_id,
        region_id    = region_id,
        label        = request.form.get("label","").strip() or None,
        start_number = start,
        end_number   = end,
        number_type  = request.form.get("number_type","mixed"),
        notes        = request.form.get("notes","").strip() or None,
        created_by   = current_user.username,
    )
    db.session.add(b); db.session.commit()
    log_audit("CREATE","did_block",b.id,
              f"Added block {start}–{end} country={country_id} region={region_id}")
    flash(f"DID block {start}–{end} added.", "success")
    return redirect(url_for("admin.did_index"))


@admin_bp.route("/did/block/<int:bid>/delete", methods=["POST"])
@admin_required
def delete_did_block(bid):
    from app.models import DIDBlock
    b = DIDBlock.query.get_or_404(bid)
    info = f"{b.start_number}–{b.end_number}"; db.session.delete(b); db.session.commit()
    log_audit("DELETE","did_block",bid,f"Deleted {info}")
    flash(f"DID block {info} deleted.", "warning")
    return redirect(url_for("admin.did_index"))


# ── Block scan (cross-platform) ───────────────────────────────
@admin_bp.route("/did/block/<int:bid>/scan")
@admin_required
def scan_did_block(bid):
    from app.utils.inventory_sync import scan_block_unified
    from app.models import DIDBlock
    b = DIDBlock.query.get_or_404(bid)
    try:
        result = scan_block_unified(b.start_number, b.end_number)
        log_audit("READ","did_block",bid,
                  f"Scanned {b.start_number}–{b.end_number}: "
                  f"{result.get('assigned',0)} assigned, {result.get('available',0)} free")
        return jsonify({"ok":True,"block_id":bid,
                        "label":b.label,"start":b.start_number,"end":b.end_number,
                        **result})
    except Exception as e:
        return jsonify({"ok":False,"error":str(e)}), 500


# ── Export free numbers ───────────────────────────────────────
@admin_bp.route("/did/block/<int:bid>/export-free")
@admin_required
def export_free_dids(bid):
    from app.utils.inventory_sync import scan_block_unified
    from app.models import DIDBlock
    b  = DIDBlock.query.get_or_404(bid)
    rs = scan_block_unified(b.start_number, b.end_number)
    si = io.StringIO(); w = csv.writer(si)
    w.writerow(["number","status","free_on_all_platforms"])
    for n in rs.get("numbers",[]):
        if n["status"] == "available":
            w.writerow([n["number"],"available","yes"])
    if rs.get("warnings"):
        w.writerow([])
        w.writerow(["# WARNINGS"])
        for warn in rs["warnings"]:
            w.writerow([f"# {warn}"])
    log_audit("EXPORT","did_block",bid,
              f"Free DID export {b.start_number}–{b.end_number}: {rs.get('available',0)} free")
    return Response(si.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":
                             f"attachment; filename=free_dids_{b.start_number}.csv"})


# ── Export full block (all numbers with assignment details) ───
@admin_bp.route("/did/block/<int:bid>/export-all")
@admin_required
def export_all_dids(bid):
    from app.utils.inventory_sync import scan_block_unified
    from app.models import DIDBlock
    b  = DIDBlock.query.get_or_404(bid)
    rs = scan_block_unified(b.start_number, b.end_number)
    si = io.StringIO(); w = csv.writer(si)
    w.writerow(["number","status","platform","assigned_to","assignment_type",
                "number_type","location"])
    for n in rs.get("numbers",[]):
        if n["status"] == "available":
            w.writerow([n["number"],"available","","","","",""])
        else:
            for det in n["details"]:
                w.writerow([n["number"],"assigned",
                            det.get("platform",""),det.get("assigned_to",""),
                            det.get("type",""),det.get("number_type",""),
                            det.get("location","")])
    log_audit("EXPORT","did_block",bid,
              f"Full DID export {b.start_number}–{b.end_number}: {rs.get('total',0)} numbers")
    return Response(si.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":
                             f"attachment; filename=all_dids_{b.start_number}.csv"})


# ── Inventory sync ────────────────────────────────────────────
@admin_bp.route("/did/sync", methods=["POST"])
@admin_required
def sync_inventory():
    from app.utils.inventory_sync import sync_all
    results = sync_all()
    parts   = [f"{p}: {r['total']} numbers" if r["ok"] else f"{p}: ERROR — {r['error']}"
               for p,r in results.items()]
    flash("Inventory synced — " + " | ".join(parts) if parts else "No platforms to sync.", "success")
    log_audit("ACTION","did_inventory",None,"Manual sync: " + "; ".join(parts))
    return redirect(url_for("admin.did_index"))


@admin_bp.route("/did/sync/<platform>", methods=["POST"])
@admin_required
def sync_inventory_platform(platform):
    from app.utils.inventory_sync import sync_platform
    if platform not in ("teams","webex","cucm"):
        flash("Unknown platform.", "danger")
        return redirect(url_for("admin.did_index"))
    r = sync_platform(platform)
    if r["ok"]:
        flash(f"{platform.title()} sync complete — {r['total']} numbers.", "success")
    else:
        flash(f"{platform.title()} sync failed: {r['error']}", "danger")
    return redirect(url_for("admin.did_index"))


# ── Auto-import locations from platforms ─────────────────────
@admin_bp.route("/did/import-locations", methods=["POST"])
@admin_required
def import_locations():
    from app.models import DIDCountry, DIDRegion
    ps = PlatformSettings.get()
    created_c = created_r = 0
    errors = []

    def _get_or_create_country(name, iso=""):
        c = DIDCountry.query.filter(
            db.func.lower(DIDCountry.name)==name.lower()).first()
        if not c:
            c = DIDCountry(name=name, iso_code=iso, created_by="system")
            db.session.add(c); db.session.flush()
            return c, True
        return c, False

    if ps.has_teams:
        try:
            from app.utils.graph_api import get_teams_locations
            for loc in get_teams_locations():
                cname = loc.get("countryOrRegion","") or loc.get("city","") or loc.get("id","")
                if not cname: continue
                c, new = _get_or_create_country(cname, loc.get("countryOrRegion","")[:2].upper())
                if new: created_c += 1
                rname = loc.get("displayName","") or loc.get("city","")
                if rname and rname.lower() != cname.lower():
                    exists = DIDRegion.query.filter_by(country_id=c.id).filter(
                        db.func.lower(DIDRegion.name)==rname.lower()).first()
                    if not exists:
                        db.session.add(DIDRegion(country_id=c.id, name=rname, created_by="system"))
                        created_r += 1
        except Exception as e:
            errors.append(f"Teams: {e}")

    if ps.has_webex:
        try:
            from app.utils.webex_api import get_webex_locations
            for loc in get_webex_locations():
                addr  = loc.get("address",{})
                cname = addr.get("country","") or loc.get("name","")
                if not cname: continue
                c, new = _get_or_create_country(cname)
                if new: created_c += 1
                rname = addr.get("state","") or loc.get("name","")
                if rname:
                    exists = DIDRegion.query.filter_by(country_id=c.id).filter(
                        db.func.lower(DIDRegion.name)==rname.lower()).first()
                    if not exists:
                        db.session.add(DIDRegion(country_id=c.id, name=rname, created_by="system"))
                        created_r += 1
        except Exception as e:
            errors.append(f"Webex: {e}")

    if ps.has_cucm:
        try:
            from app.utils.cucm_api import get_cucm_locations
            for loc in get_cucm_locations():
                name = loc.get("name","")
                if not name or name.lower() in ("hub_none",""):
                    continue
                c, new = _get_or_create_country("CUCM")
                if new: created_c += 1
                exists = DIDRegion.query.filter_by(country_id=c.id).filter(
                    db.func.lower(DIDRegion.name)==name.lower()).first()
                if not exists:
                    db.session.add(DIDRegion(country_id=c.id, name=name, created_by="system"))
                    created_r += 1
        except Exception as e:
            errors.append(f"CUCM: {e}")

    db.session.commit()
    msg = f"{created_c} countries and {created_r} regions imported."
    if errors:
        msg += " Errors: " + "; ".join(errors)
        flash(msg, "warning")
    else:
        flash(msg, "success")
    log_audit("ACTION","did_country",None,msg)
    return redirect(url_for("admin.did_index"))


