"""RELAY — Email alert utility for certificate expiry notifications."""
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime


def _load_cfg():
    from app.models import SMTPConfig
    return SMTPConfig.get()


def _send(subject: str, body_html: str, recipients: list[str]) -> dict:
    cfg = _load_cfg()
    if not cfg.is_configured():
        return {"ok": False, "error": "SMTP not configured"}
    if not recipients:
        return {"ok": False, "error": "No recipients"}

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"{cfg.from_name} <{cfg.from_addr}>"
    msg["To"]      = ", ".join(recipients)
    msg.attach(MIMEText(body_html, "html"))

    try:
        ctx = ssl.create_default_context()
        if cfg.use_ssl:
            with smtplib.SMTP_SSL(cfg.host, cfg.port, context=ctx, timeout=15) as s:
                if cfg.username:
                    s.login(cfg.username, cfg.password)
                s.sendmail(cfg.from_addr, recipients, msg.as_string())
        else:
            with smtplib.SMTP(cfg.host, cfg.port, timeout=15) as s:
                if cfg.use_tls:
                    s.starttls(context=ctx)
                if cfg.username:
                    s.login(cfg.username, cfg.password)
                s.sendmail(cfg.from_addr, recipients, msg.as_string())
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def send_test_email() -> dict:
    cfg = _load_cfg()
    recipients = [r.strip() for r in (cfg.alert_to or "").split(",") if r.strip()]
    return _send(
        subject="RELAY — SMTP Test",
        body_html=f"""
        <div style="font-family:sans-serif;max-width:600px;margin:0 auto;">
          <div style="background:#003366;color:#fff;padding:20px 24px;border-radius:8px 8px 0 0;">
            <h2 style="margin:0;">RELAY Certificate Monitor</h2>
            <p style="margin:4px 0 0;opacity:.75;font-size:14px;">SMTP Test Email</p>
          </div>
          <div style="padding:24px;background:#f8f9fa;border:1px solid #dee2e6;border-top:none;border-radius:0 0 8px 8px;">
            <p>This is a test email from RELAY. If you received this, your SMTP configuration is working correctly.</p>
            <p style="color:#6c757d;font-size:13px;">Sent at {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
          </div>
        </div>""",
        recipients=recipients,
    )


def send_cert_expiry_alerts() -> dict:
    """
    Send expiry alert emails for all domains and devices nearing expiry.
    Called by scheduler or manually from admin.
    Returns summary dict.
    """
    from app.models import CertDomain, CertDevice
    cfg = _load_cfg()
    if not cfg.enabled or not cfg.is_configured():
        return {"ok": False, "skipped": True, "error": "SMTP disabled or not configured"}

    recipients = [r.strip() for r in (cfg.alert_to or "").split(",") if r.strip()]
    if not recipients:
        return {"ok": False, "error": "No alert recipients configured"}

    # Collect items near expiry
    alerts = []

    for domain in CertDomain.query.filter_by(is_active=True).all():
        r = domain.latest
        if r and r.days_left is not None and r.days_left <= domain.notify_days:
            alerts.append({
                "name":      domain.hostname,
                "kind":      "Domain",
                "days_left": r.days_left,
                "risk":      r.risk,
                "expires":   r.not_after,
            })

    for dev in CertDevice.query.filter_by(is_active=True).all():
        r = dev.latest
        if r and r.days_left is not None and r.days_left <= dev.notify_days:
            alerts.append({
                "name":      f"{dev.product_label} — {dev.label or dev.hostname}",
                "kind":      "Device",
                "days_left": r.days_left,
                "risk":      r.risk,
                "expires":   r.not_after,
            })

    if not alerts:
        return {"ok": True, "sent": 0, "message": "No items near expiry"}

    RISK_COLOUR = {
        "CRITICAL": "#dc3545", "EXPIRED": "#212529",
        "WARNING": "#fd7e14",  "ATTENTION": "#ffc107",
    }

    rows = "".join(f"""
      <tr>
        <td style="padding:8px 12px;border-bottom:1px solid #dee2e6;">{a['name']}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #dee2e6;">{a['kind']}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #dee2e6;font-weight:bold;
                   color:{RISK_COLOUR.get(a['risk'],'#000')};">{a['risk']}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #dee2e6;">{a['days_left']}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #dee2e6;font-family:monospace;">{a['expires'] or '—'}</td>
      </tr>""" for a in alerts)

    body = f"""
    <div style="font-family:sans-serif;max-width:700px;margin:0 auto;">
      <div style="background:#003366;color:#fff;padding:20px 24px;border-radius:8px 8px 0 0;">
        <h2 style="margin:0;">⚠️ Certificate Expiry Alert</h2>
        <p style="margin:4px 0 0;opacity:.75;font-size:14px;">RELAY Certificate Monitor — {len(alerts)} item(s) require attention</p>
      </div>
      <div style="padding:0;border:1px solid #dee2e6;border-top:none;border-radius:0 0 8px 8px;overflow:hidden;">
        <table style="width:100%;border-collapse:collapse;font-size:14px;">
          <thead>
            <tr style="background:#f1f3f5;">
              <th style="padding:10px 12px;text-align:left;">Name</th>
              <th style="padding:10px 12px;text-align:left;">Type</th>
              <th style="padding:10px 12px;text-align:left;">Risk</th>
              <th style="padding:10px 12px;text-align:left;">Days Left</th>
              <th style="padding:10px 12px;text-align:left;">Expires</th>
            </tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
      <p style="color:#6c757d;font-size:12px;margin-top:12px;">
        Generated by RELAY at {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}. Log in to renew certificates.
      </p>
    </div>"""

    result = _send(
        subject=f"RELAY — {len(alerts)} Certificate(s) Expiring Soon",
        body_html=body,
        recipients=recipients,
    )
    result["sent"] = len(alerts) if result["ok"] else 0
    return result
