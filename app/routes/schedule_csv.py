"""RELAY — Multi-Platform Schedule blueprint (recurring + one-shot forwarding rules)."""
from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, Response)
from flask_login import login_required, current_user
from app import db
from app.models import TimeWindowSchedule, Schedule, PlatformSettings, log_audit
import csv, io
from datetime import datetime

schedule_csv_bp = Blueprint("schedule_csv", __name__)


def _own_only_check(user_upn_field):
    """Return True if current user is trying to create for someone else when they shouldn't."""
    if current_user.can_manage_others():
        return False
    own = (current_user.teams_upn or current_user.webex_extension or "").lower()
    return user_upn_field.lower() not in (own, "")


# ── Index ─────────────────────────────────────────────────────
@schedule_csv_bp.route("/")
@login_required
def index():
    ps = PlatformSettings.get()
    if current_user.is_admin():
        # Admin sees ALL schedules across all users
        tw_rules  = TimeWindowSchedule.query.order_by(TimeWindowSchedule.name).all()
        schedules = Schedule.query.order_by(Schedule.activate_at.desc()).all()
    elif current_user.is_superuser():
        # Superuser sees only schedules they personally created
        tw_rules  = TimeWindowSchedule.query.filter_by(
            created_by=current_user.username).order_by(TimeWindowSchedule.name).all()
        schedules = Schedule.query.filter_by(
            created_by=current_user.username).order_by(Schedule.activate_at.desc()).all()
    else:
        # Regular users see schedules for their own UPN
        own_upn = current_user.teams_upn or ""
        tw_rules  = TimeWindowSchedule.query.filter(
            (TimeWindowSchedule.user_upn == own_upn) |
            (TimeWindowSchedule.teams_upn == own_upn)
        ).all()
        schedules = Schedule.query.filter(
            (Schedule.user_upn == own_upn) |
            (Schedule.teams_upn == own_upn)
        ).all()
    return render_template("schedule_csv.html",
                           tw_rules=tw_rules, schedules=schedules,
                           platform_settings=ps)


# ── Recurring time-window rules ───────────────────────────────
@schedule_csv_bp.route("/tw/add", methods=["POST"])
@login_required
def add_tw():
    days = ",".join(request.form.getlist("days"))
    if not days:
        flash("Select at least one day.", "danger")
        return redirect(url_for("schedule_csv.index"))

    platform  = request.form.get("platform", "teams")
    user_upn  = request.form.get("user_upn", "").strip()
    user_id   = request.form.get("user_id",  "").strip()
    disp_name = request.form.get("display_name", "").strip()

    if not current_user.is_admin():
        # Superuser and user: force platform to own user_platform
        platform  = current_user.user_platform or "teams"
    if not current_user.can_manage_others():
        # Regular user: also force own identity
        user_upn  = current_user.teams_upn or current_user.webex_extension or current_user.cucm_extension or ""
        user_id   = ""
        disp_name = current_user.display_name or current_user.username

    tw = TimeWindowSchedule(
        name         = request.form.get("name", "").strip(),
        platform     = platform,
        user_upn     = user_upn,
        user_id      = user_id,
        display_name = disp_name,
        teams_upn    = user_upn if platform == "teams" else "",
        user_object_id = user_id if platform == "teams" else "",
        forward_to   = request.form.get("forward_to", "").strip(),
        days         = days,
        start_time   = request.form.get("start_time", "09:00"),
        end_time     = request.form.get("end_time", "17:00"),
        note         = request.form.get("note", "").strip(),
        created_by   = current_user.username,
    )
    db.session.add(tw); db.session.commit()
    log_audit("CREATE", "tw_schedule", tw.id, f"TW rule '{tw.name}' [{platform}] for {user_upn}")
    flash(f"Time-window rule '{tw.name}' created for {platform.title()}.", "success")
    return redirect(url_for("schedule_csv.index"))


@schedule_csv_bp.route("/tw/<int:tid>/toggle", methods=["POST"])
@login_required
def toggle_tw(tid):
    tw = TimeWindowSchedule.query.get_or_404(tid)
    # Admin can toggle any; superuser only their own created; user only their own UPN
    if current_user.is_admin():
        pass  # unrestricted
    elif current_user.is_superuser():
        if tw.created_by != current_user.username:
            flash("You can only modify rules you created.", "danger")
            return redirect(url_for("schedule_csv.index"))
    else:
        own = current_user.teams_upn or ""
        if (tw.user_upn or tw.teams_upn or "") != own:
            flash("You can only modify your own rules.", "danger")
            return redirect(url_for("schedule_csv.index"))
    tw.is_enabled = not tw.is_enabled; db.session.commit()
    log_audit("UPDATE", "tw_schedule", tid, f"Toggled '{tw.name}'")
    flash(f"Rule '{tw.name}' {'enabled' if tw.is_enabled else 'disabled'}.", "info")
    return redirect(url_for("schedule_csv.index"))


@schedule_csv_bp.route("/tw/<int:tid>/delete", methods=["POST"])
@login_required
def delete_tw(tid):
    tw = TimeWindowSchedule.query.get_or_404(tid)
    if current_user.is_admin():
        pass
    elif current_user.is_superuser():
        if tw.created_by != current_user.username:
            flash("You can only delete rules you created.", "danger")
            return redirect(url_for("schedule_csv.index"))
    else:
        own = current_user.teams_upn or ""
        if (tw.user_upn or tw.teams_upn or "") != own:
            flash("You can only delete your own rules.", "danger")
            return redirect(url_for("schedule_csv.index"))
    name = tw.name; db.session.delete(tw); db.session.commit()
    log_audit("DELETE", "tw_schedule", tid, f"Deleted '{name}'")
    flash(f"Rule '{name}' deleted.", "warning")
    return redirect(url_for("schedule_csv.index"))


# ── One-shot schedules ────────────────────────────────────────
@schedule_csv_bp.route("/schedule/add", methods=["POST"])
@login_required
def add_schedule():
    activate   = request.form.get("activate_at", "").strip()
    deactivate = request.form.get("deactivate_at", "").strip()
    try:
        act_dt = datetime.strptime(activate, "%Y-%m-%dT%H:%M")
    except ValueError:
        flash("Invalid activation datetime.", "danger")
        return redirect(url_for("schedule_csv.index"))
    deact_dt = None
    if deactivate:
        try:
            deact_dt = datetime.strptime(deactivate, "%Y-%m-%dT%H:%M")
        except ValueError:
            flash("Invalid deactivation datetime.", "danger")
            return redirect(url_for("schedule_csv.index"))

    platform  = request.form.get("platform", "teams")
    user_upn  = request.form.get("user_upn", "").strip()
    user_id   = request.form.get("user_id",  "").strip()
    disp_name = request.form.get("display_name", "").strip()

    if not current_user.is_admin():
        # Superuser and user: force platform to own user_platform
        platform  = current_user.user_platform or "teams"
    if not current_user.can_manage_others():
        # Regular user: also force own identity
        user_upn  = current_user.teams_upn or current_user.webex_extension or current_user.cucm_extension or ""
        user_id   = ""
        disp_name = current_user.display_name or current_user.username

    s = Schedule(
        name          = request.form.get("name", "").strip(),
        platform      = platform,
        user_upn      = user_upn,
        user_id       = user_id,
        display_name  = disp_name,
        teams_upn     = user_upn if platform == "teams" else "",
        user_object_id= user_id  if platform == "teams" else "",
        forward_to    = request.form.get("forward_to", "").strip(),
        activate_at   = act_dt,
        deactivate_at = deact_dt,
        note          = request.form.get("note", "").strip(),
        created_by    = current_user.username,
    )
    db.session.add(s); db.session.commit()
    log_audit("CREATE", "schedule", s.id, f"One-shot '{s.name}' [{platform}] for {user_upn}")
    flash(f"Schedule '{s.name}' created for {platform.title()}.", "success")
    return redirect(url_for("schedule_csv.index"))


@schedule_csv_bp.route("/schedule/<int:sid>/delete", methods=["POST"])
@login_required
def delete_schedule(sid):
    s = Schedule.query.get_or_404(sid)
    if current_user.is_admin():
        pass
    elif current_user.is_superuser():
        if s.created_by != current_user.username:
            flash("You can only delete schedules you created.", "danger")
            return redirect(url_for("schedule_csv.index"))
    else:
        own = current_user.teams_upn or ""
        if (s.user_upn or s.teams_upn or "") != own:
            flash("You can only delete your own schedules.", "danger")
            return redirect(url_for("schedule_csv.index"))
    name = s.name; db.session.delete(s); db.session.commit()
    log_audit("DELETE", "schedule", sid, f"Deleted '{name}'")
    flash(f"Schedule '{name}' deleted.", "warning")
    return redirect(url_for("schedule_csv.index"))


# ── CSV bulk upload ───────────────────────────────────────────
@schedule_csv_bp.route("/upload", methods=["POST"])
@login_required
def upload_csv():
    """
    All roles can upload a CSV of one-shot schedules.
    Admin / superuser: every row is created as supplied.
    Regular user: every row is silently forced to their own platform,
                  UPN, and user_id regardless of what the CSV contains.
    """
    f = request.files.get("csv_file")
    if not f:
        flash("No file selected.", "danger")
        return redirect(url_for("schedule_csv.index"))

    try:
        from app.utils.upload_manager import save_csv
        save_csv(f, current_user.username)
        f.stream.seek(0)
    except Exception:
        f.stream.seek(0)

    # Resolve the current user's own identity once (used for regular users)
    own_platform  = current_user.user_platform  or "teams"
    own_upn       = (current_user.teams_upn or
                     current_user.webex_extension or
                     current_user.cucm_extension or "").strip()
    own_user_id   = (current_user.teams_extension or "").strip()
    own_disp_name = (current_user.display_name or current_user.username)

    reader  = csv.DictReader(io.StringIO(f.read().decode("utf-8-sig")))
    created = skipped = 0

    for row in reader:
        act = row.get("activate_at", "").strip()
        fwd = row.get("forward_to",  "").strip()
        if not act or not fwd:
            skipped += 1
            continue

        try:
            act_dt = datetime.strptime(act, "%Y-%m-%dT%H:%M")
        except ValueError:
            skipped += 1
            continue

        deact_dt = None
        if row.get("deactivate_at", "").strip():
            try:
                deact_dt = datetime.strptime(row["deactivate_at"].strip(), "%Y-%m-%dT%H:%M")
            except ValueError:
                pass

        if current_user.can_manage_others():
            # Admin / superuser — use whatever is in the CSV
            plat     = row.get("platform", "teams").strip() or "teams"
            upn      = (row.get("user_upn", "") or row.get("teams_upn", "")).strip()
            uid      = row.get("user_id", "").strip()
            disp     = row.get("display_name", "").strip()
            if not upn:
                skipped += 1
                continue
        else:
            # Regular user — always forward their own extension regardless of CSV content
            plat     = own_platform
            upn      = own_upn
            uid      = own_user_id
            disp     = own_disp_name
            if not upn:
                flash("Your account has no extension set. Contact admin.", "danger")
                return redirect(url_for("schedule_csv.index"))

        s = Schedule(
            name          = row.get("name", "Import").strip() or "CSV Import",
            platform      = plat,
            user_upn      = upn,
            user_id       = uid,
            display_name  = disp,
            teams_upn     = upn if plat == "teams" else "",
            user_object_id= uid if plat == "teams" else "",
            forward_to    = fwd,
            activate_at   = act_dt,
            deactivate_at = deact_dt,
            note          = row.get("note", "").strip(),
            created_by    = current_user.username,
        )
        db.session.add(s)
        created += 1

    db.session.commit()
    log_audit("CREATE", "schedule", None,
              f"CSV upload: {created} schedules created, {skipped} skipped "
              f"({'own extension enforced' if not current_user.can_manage_others() else 'any user'})")
    flash(f"{created} schedule(s) imported, {skipped} skipped.", "success")
    return redirect(url_for("schedule_csv.index"))


@schedule_csv_bp.route("/template")
@login_required
def download_template():
    si = io.StringIO(); w = csv.writer(si)
    if current_user.can_manage_others():
        # Admin / superuser — full template with user targeting across platforms
        w.writerows([
            ["name", "platform", "user_upn", "user_id", "display_name",
             "forward_to", "activate_at", "deactivate_at", "note"],
            ["# platform: teams | webex | cucm  |  activate_at / deactivate_at: YYYY-MM-DDTHH:MM (UTC)"],
            ["Night Cover Teams", "teams", "j.smith@contoso.com",
             "azure-object-id", "John Smith", "+3227009999", "2026-01-06T18:00", "2026-01-07T08:00", ""],
            ["Webex OOH",         "webex", "m.dupont@contoso.com",
             "webex-person-id",   "Marc Dupont", "+3227008888", "2026-01-06T18:00", "", ""],
            ["CUCM Holiday",      "cucm",  "adupont",
             "",                  "Anna Dupont", "+3227007777", "2026-12-24T17:00", "2026-01-02T08:00", "Xmas"],
        ])
    else:
        # Regular user — only forward_to, times, name, note needed.
        # user_upn / platform / user_id are ignored on import — own account is used automatically.
        w.writerows([
            ["name", "forward_to", "activate_at", "deactivate_at", "note"],
            ["# forward_to: E.164 (+3227001234) or extension (1001)"],
            ["# activate_at / deactivate_at: YYYY-MM-DDTHH:MM (UTC) — leave deactivate_at blank to forward indefinitely"],
            ["# Your account extension is applied automatically — user_upn and platform are not required"],
            ["Holiday cover", "+3227001234", "2026-12-24T16:00", "2026-01-02T08:00", "Christmas"],
            ["Training day",  "+3227005678", "2026-03-20T08:00", "2026-03-20T17:00", ""],
        ])
    return Response(si.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=schedules_template.csv"})
