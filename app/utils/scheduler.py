"""Background scheduler — evaluates forwarding rules every 60 s."""
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
import logging

_scheduler = None
log = logging.getLogger(__name__)


def start_scheduler(app):
    global _scheduler
    if _scheduler and _scheduler.running:
        return
    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(_run_jobs, "interval", seconds=60, args=[app],
                       id="relay_main_job", replace_existing=True)

    # Daily cert scan at 07:00 UTC
    _scheduler.add_job(_cert_scan, "cron", hour=7, minute=0,
                       args=[app], id="cert_daily_scan", replace_existing=True)

    # Weekly upload rotation — Sundays at 02:00 UTC
    _scheduler.add_job(_rotate_uploads, "cron", day_of_week="sun", hour=2, minute=0,
                       args=[app], id="upload_weekly_rotate", replace_existing=True)

    _scheduler.start()


def _run_jobs(app):
    with app.app_context():
        try:
            _evaluate_rules()
        except Exception as exc:
            log.error("Scheduler error: %s", exc)


def _cert_scan(app):
    with app.app_context():
        try:
            from app.models import CertDomain, CertDevice, PlatformSettings
            if not PlatformSettings.get().has_cert_monitor:
                return
            from app.utils.cert_checker import check_cert
            from app.models import CertResult
            from app import db
            count = 0
            for d in CertDomain.query.filter_by(is_active=True).all():
                res = check_cert(d.hostname, d.port)
                cr = CertResult(domain_id=d.id, risk=res["risk"],
                                days_left=res["days_left"], not_before=res["not_before"],
                                not_after=res["not_after"], issuer_org=res["issuer_org"],
                                issuer_cn=res["issuer_cn"], subject_cn=res["subject_cn"],
                                san_count=res["san_count"], error=res["error"])
                db.session.add(cr); count += 1
            for d in CertDevice.query.filter_by(is_active=True).all():
                res = check_cert(d.hostname, d.port)
                cr = CertResult(device_id=d.id, risk=res["risk"],
                                days_left=res["days_left"], not_before=res["not_before"],
                                not_after=res["not_after"], issuer_org=res["issuer_org"],
                                issuer_cn=res["issuer_cn"], subject_cn=res["subject_cn"],
                                san_count=res["san_count"], error=res["error"])
                db.session.add(cr); count += 1
            db.session.commit()
            log.info("Daily cert scan: %d items scanned", count)
            # Send alert emails after scanning
            try:
                from app.utils.mailer import send_cert_expiry_alerts
                result = send_cert_expiry_alerts()
                if result.get("ok") and result.get("sent", 0) > 0:
                    log.info("Cert expiry alerts sent for %d item(s)", result["sent"])
            except Exception as mail_exc:
                log.warning("Cert alert email failed: %s", mail_exc)
        except Exception as exc:
            log.error("Cert scan error: %s", exc)


def _evaluate_rules():
    """Evaluate all enabled TimeWindowSchedule and one-shot Schedule records.
    Uses the unified forwarder so Teams, Webex and CUCM are all handled."""
    from app import db
    from app.models import TimeWindowSchedule, Schedule
    from app.utils.forwarder import set_forward

    now = datetime.utcnow()

    # ── Time-window (recurring) rules ───────────────────────────────────────
    for tw in TimeWindowSchedule.query.filter_by(is_enabled=True).all():
        should = tw.is_window_active(now)
        platform = tw.platform or "teams"
        user_id  = tw.user_id or tw.user_object_id or ""
        user_upn = tw.user_upn or tw.teams_upn or ""
        try:
            if should and not tw.cf_active:
                ok, msg = set_forward(platform, user_id, user_upn,
                                      forward_to=tw.forward_to, enabled=True)
                if ok:
                    tw.cf_active = True
                    tw.last_action = f"ENABLED → {tw.forward_to} [{platform}]"
                else:
                    tw.last_action = f"Enable FAILED [{platform}]: {msg}"
            elif not should and tw.cf_active:
                ok, msg = set_forward(platform, user_id, user_upn, enabled=False)
                if ok:
                    tw.cf_active = False
                    tw.last_action = f"DISABLED [{platform}]"
                else:
                    tw.last_action = f"Disable FAILED [{platform}]: {msg}"
            tw.last_checked = now
        except Exception as exc:
            tw.last_action = f"ERROR: {exc}"
            log.error("TW rule %d error: %s", tw.id, exc)

    # ── One-shot schedules ───────────────────────────────────────────────────
    for sched in Schedule.query.filter_by(is_active=True).all():
        platform = sched.platform or "teams"
        user_id  = sched.user_id or sched.user_object_id or ""
        user_upn = sched.user_upn or sched.teams_upn or ""
        try:
            if not sched.activated and now >= sched.activate_at:
                ok, msg = set_forward(platform, user_id, user_upn,
                                      forward_to=sched.forward_to, enabled=True)
                if ok:
                    sched.activated = True
                else:
                    log.warning("One-shot %d activate failed [%s]: %s", sched.id, platform, msg)
            if sched.activated and not sched.deactivated and sched.deactivate_at:
                if now >= sched.deactivate_at:
                    ok, msg = set_forward(platform, user_id, user_upn, enabled=False)
                    if ok:
                        sched.deactivated = True
        except Exception as exc:
            log.warning("One-shot schedule %d error: %s", sched.id, exc)

    db.session.commit()


def _rotate_uploads(app):
    with app.app_context():
        try:
            from app.utils.upload_manager import rotate_uploads
            result = rotate_uploads()
            log.info("Weekly upload rotation: %d file(s) removed", result["total"])
        except Exception as exc:
            log.error("Upload rotation error: %s", exc)
