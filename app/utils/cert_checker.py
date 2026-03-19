"""SSL/TLS certificate inspection — stdlib only, no extra deps."""
import ssl, socket
from datetime import datetime, timezone


def check_cert(hostname, port=443, timeout=10, verify=True):
    """
    Retrieve and inspect a TLS certificate.

    verify=True  (default): strict CA verification — best for public domains.
    verify=False           : no CA verification — required for SBC/device certs
                             that use self-signed or internal CA certificates.
                             The certificate details are still fully read and
                             reported; only the chain trust check is skipped.
    """
    now = datetime.now(timezone.utc)
    try:
        ctx = ssl.create_default_context()
        if not verify:
            # Disable verification so we can read the cert even if it is
            # self-signed or issued by an internal/private CA
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname if verify else None) as tls:
                cert = tls.getpeercert()
        not_after  = datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left  = (not_after - now).days
        issuer     = dict(x[0] for x in cert.get("issuer",  []))
        subject    = dict(x[0] for x in cert.get("subject", []))
        sans       = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        if days_left < 0:   risk = "EXPIRED"
        elif days_left <= 7:  risk = "CRITICAL"
        elif days_left <= 30: risk = "WARNING"
        elif days_left <= 60: risk = "ATTENTION"
        else:                 risk = "HEALTHY"
        return {"ok": True, "hostname": hostname, "port": port, "risk": risk,
                "days_left": days_left,
                "not_before": not_before.strftime("%Y-%m-%d"),
                "not_after":  not_after.strftime("%Y-%m-%d"),
                "issuer_org": issuer.get("organizationName", "—"),
                "issuer_cn":  issuer.get("commonName", "—"),
                "subject_cn": subject.get("commonName", hostname),
                "san_count":  len(sans), "sans": sans[:10],
                "checked_at": now.isoformat(), "error": None}
    except ssl.SSLCertVerificationError as e:
        return _err(hostname, port, now, "CRITICAL", f"Verification failed: {e}")
    except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
        return _err(hostname, port, now, "UNKNOWN",  f"Connection failed: {e}")
    except Exception as e:
        return _err(hostname, port, now, "UNKNOWN",  str(e))


def _err(hostname, port, now, risk, msg):
    return {"ok": False, "hostname": hostname, "port": port, "risk": risk,
            "days_left": None, "not_before": None, "not_after": None,
            "issuer_org": "—", "issuer_cn": "—", "subject_cn": hostname,
            "san_count": 0, "sans": [], "checked_at": now.isoformat(), "error": msg}
