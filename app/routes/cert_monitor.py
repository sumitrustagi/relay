"""RELAY — Certificate Monitor blueprint. Mounted at /admin/certs"""
from datetime import datetime, timezone
from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, jsonify, Response)
from flask_login import login_required, current_user
from functools import wraps
from app import db
from app.models import (CertDomain, CertDevice, CertResult,
                        CERT_DEVICE_PRODUCTS, log_audit)

cert_bp = Blueprint("cert_monitor", __name__)


def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if not current_user.is_admin():
            flash("Administrator access required.", "danger")
            return redirect(url_for("schedule_csv.index"))
        return fn(*args, **kwargs)
    return wrapper


def _scan_host(hostname, port):
    from app.utils.cert_checker import check_cert
    return check_cert(hostname, port)


def _make_result(source_id, source_type, res):
    kwargs = dict(
        risk=res["risk"], days_left=res["days_left"],
        not_before=res["not_before"], not_after=res["not_after"],
        issuer_org=res["issuer_org"], issuer_cn=res["issuer_cn"],
        subject_cn=res["subject_cn"], san_count=res["san_count"],
        error=res["error"]
    )
    if source_type == "domain":
        kwargs["domain_id"] = source_id
    else:
        kwargs["device_id"] = source_id
    return CertResult(**kwargs)


def _generate_csr_pem(obj):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    name_attrs = []
    if obj.csr_country:
        name_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, obj.csr_country.upper()[:2]))
    if obj.csr_state:
        name_attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, obj.csr_state))
    if obj.csr_locality:
        name_attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, obj.csr_locality))
    if obj.csr_org:
        name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, obj.csr_org))
    if obj.csr_ou:
        name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, obj.csr_ou))
    cn = obj.csr_cn or obj.hostname
    name_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()).decode()
    san_list = [x509.DNSName(cn)]
    if obj.csr_sans:
        for s in obj.csr_sans.split(","):
            s = s.strip()
            if s and s != cn:
                san_list.append(x509.DNSName(s))
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name(name_attrs))
           .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
           .sign(key, hashes.SHA256()))
    return key_pem, csr.public_bytes(serialization.Encoding.PEM).decode()


def _upload_cert_logic(obj, request_obj):
    """
    Accept a certificate chain from either:
      - A file upload (cert_chain_file)
      - Pasted PEM text (cert_chain_pem)

    Supports all common PEM certificate types:
      -----BEGIN CERTIFICATE-----
      -----BEGIN X509 CERTIFICATE-----
      -----BEGIN TRUSTED CERTIFICATE-----
      -----BEGIN PKCS7-----  (extracts embedded certs)
    """
    import re as _re

    pem_text = ""

    # 1. Try file upload first
    file = request_obj.files.get("cert_chain_file")
    if file and file.filename:
        raw = file.read()
        # Try UTF-8, fall back to latin-1 for binary formats
        try:
            pem_text = raw.decode("utf-8").strip()
        except UnicodeDecodeError:
            pem_text = raw.decode("latin-1").strip()

    # 2. Fall back to pasted text — strip any whitespace/encoding artifacts
    if not pem_text:
        pem_text = request_obj.form.get("cert_chain_pem", "").strip()

    if not pem_text:
        return None, "No certificate data provided."

    # Normalise line endings (Windows \r\n → \n)
    pem_text = pem_text.replace("\r\n", "\n").replace("\r", "\n")

    # Accept all common PEM header types
    valid_headers = [
        "-----BEGIN CERTIFICATE-----",
        "-----BEGIN X509 CERTIFICATE-----",
        "-----BEGIN TRUSTED CERTIFICATE-----",
        "-----BEGIN PKCS7-----",
        "-----BEGIN CERTIFICATE CHAIN-----",
    ]
    if not any(h in pem_text for h in valid_headers):
        return None, (
            "Content does not appear to be a valid PEM certificate. "
            "Expected a block starting with -----BEGIN CERTIFICATE----- "
            "or similar. Make sure you copied the full PEM including the "
            "header and footer lines."
        )

    # Parse to get basic cert info for the flash message
    cert_info = "stored"
    try:
        from cryptography import x509 as _x509

        # Handle PKCS7 bundles — extract embedded certs
        if "-----BEGIN PKCS7-----" in pem_text:
            try:
                from cryptography.hazmat.primitives.serialization import pkcs7
                p7 = pkcs7.load_pem_pkcs7_certificates(pem_text.encode())
                if p7:
                    leaf = p7[0]
                    blocks_pem = "\n".join(
                        c.public_bytes(
                            __import__("cryptography").hazmat.primitives.serialization.Encoding.PEM
                        ).decode()
                        for c in p7
                    )
                    pem_text = blocks_pem
                else:
                    return None, "PKCS7 bundle contained no certificates."
            except Exception as e:
                return None, f"PKCS7 parse error: {e}"

        # Normalise alternate header types to standard so cryptography lib can parse
        normalised = pem_text
        for alt in ("-----BEGIN X509 CERTIFICATE-----",
                    "-----BEGIN TRUSTED CERTIFICATE-----",
                    "-----BEGIN CERTIFICATE CHAIN-----"):
            normalised = normalised.replace(
                alt, "-----BEGIN CERTIFICATE-----"
            ).replace(
                alt.replace("BEGIN", "END"), "-----END CERTIFICATE-----"
            )

        # Extract all cert blocks
        blocks = _re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            normalised, _re.DOTALL
        )
        if not blocks:
            return None, "No certificate blocks found in PEM data."

        leaf = _x509.load_pem_x509_certificate(blocks[0].encode())
        cn_attrs = leaf.subject.get_attributes_for_oid(_x509.oid.NameOID.COMMON_NAME)
        leaf_cn = cn_attrs[0].value if cn_attrs else "(unknown)"

        try:
            not_after = leaf.not_valid_after_utc
        except AttributeError:
            not_after = leaf.not_valid_after.replace(tzinfo=timezone.utc)

        days_left = (not_after - datetime.now(timezone.utc)).days
        chain_count = len(blocks)
        cert_info = (
            f"CN={leaf_cn}, expires {not_after.strftime('%Y-%m-%d')} "
            f"({days_left}d), {chain_count} cert(s) in chain"
        )

    except ImportError:
        pass  # cryptography not available — store as-is
    except Exception as e:
        return None, f"Certificate parse error: {e}"

    return pem_text, cert_info


def _result_from_pem(pem_text, source_id, source_type, flash_fn=None):
    """
    Build a CertResult from an uploaded PEM chain rather than a live scan.
    Sets checked_at 1 second ahead of now so it always sorts above older scan results.
    Returns a CertResult instance (not yet committed), or None if parsing fails.
    """
    import re as _re
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    # Set 1 second in the future so this result always sorts first (desc order)
    checked_at = datetime.utcnow() + timedelta(seconds=1)

    def _make(risk, days_left, not_before, not_after,
              issuer_org, issuer_cn, subject_cn, san_count, error=None):
        kwargs = dict(
            risk=risk, days_left=days_left,
            not_before=not_before, not_after=not_after,
            issuer_org=issuer_org, issuer_cn=issuer_cn,
            subject_cn=subject_cn, san_count=san_count,
            error=error, checked_at=checked_at,
        )
        if source_type == "domain":
            kwargs["domain_id"] = source_id
        else:
            kwargs["device_id"] = source_id
        return CertResult(**kwargs)

    try:
        from cryptography import x509 as _x509

        # Normalise alternate PEM headers so cryptography can parse them
        normalised = pem_text
        for alt in ("-----BEGIN X509 CERTIFICATE-----",
                    "-----BEGIN TRUSTED CERTIFICATE-----",
                    "-----BEGIN CERTIFICATE CHAIN-----"):
            normalised = normalised.replace(
                alt, "-----BEGIN CERTIFICATE-----"
            ).replace(
                alt.replace("BEGIN", "END"), "-----END CERTIFICATE-----"
            )

        blocks = _re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            normalised, _re.DOTALL
        )
        if not blocks:
            if flash_fn:
                flash_fn("Uploaded PEM contained no parseable certificate blocks.", "warning")
            return None

        leaf = _x509.load_pem_x509_certificate(blocks[0].encode())

        try:
            not_after  = leaf.not_valid_after_utc
            not_before = leaf.not_valid_before_utc
        except AttributeError:
            not_after  = leaf.not_valid_after.replace(tzinfo=timezone.utc)
            not_before = leaf.not_valid_before.replace(tzinfo=timezone.utc)

        days_left = (not_after - now).days
        if days_left < 0:    risk = "EXPIRED"
        elif days_left <= 7:  risk = "CRITICAL"
        elif days_left <= 30: risk = "WARNING"
        elif days_left <= 60: risk = "ATTENTION"
        else:                 risk = "HEALTHY"

        NameOID = _x509.oid.NameOID
        def _attr(name_obj, oid):
            a = name_obj.get_attributes_for_oid(oid)
            return a[0].value if a else "—"

        issuer_org = _attr(leaf.issuer,  NameOID.ORGANIZATION_NAME)
        issuer_cn  = _attr(leaf.issuer,  NameOID.COMMON_NAME)
        subject_cn = _attr(leaf.subject, NameOID.COMMON_NAME)
        try:
            san_ext = leaf.extensions.get_extension_for_class(_x509.SubjectAlternativeName)
            sans = san_ext.value.get_values_for_type(_x509.DNSName)
        except Exception:
            sans = []

        return _make(risk, days_left,
                     not_before.strftime("%Y-%m-%d"),
                     not_after.strftime("%Y-%m-%d"),
                     issuer_org, issuer_cn, subject_cn, len(sans))

    except ImportError:
        # cryptography not installed — create a minimal placeholder result
        # so the dashboard at least stops showing the old scan error
        if flash_fn:
            flash_fn("Install the 'cryptography' package for full cert parsing. "
                     "Certificate stored but details unavailable.", "warning")
        return _make("UNKNOWN", None, None, None, "—", "—", "—", 0,
                     error="cryptography package not installed — cert stored, deploy to device then scan")

    except Exception as e:
        if flash_fn:
            flash_fn(f"Certificate stored but could not parse details: {e}", "warning")
        return _make("UNKNOWN", None, None, None, "—", "—", "—", 0,
                     error=f"Parse error: {e}")


def _push_oracle_cert(device, pem_text):
    """
    Push certificate to Oracle/Acme Packet SBC via REST API v1.2.
    Flow: authenticate → lock → import cert XML → save → activate → unlock
    Returns (ok: bool, message: str)
    """
    import requests, urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    host     = device.ip_address or device.hostname
    port     = device.mgmt_port  or 443
    username = device.username   or "admin"
    password = device.password   or ""
    base     = f"https://{host}:{port}/rest/v1.2"
    timeout  = 15

    try:
        # 1. Get bearer token
        r = requests.post(f"{base}/auth/token",
                          json={"username": username, "password": password},
                          verify=False, timeout=timeout)
        if r.status_code != 200:
            return False, f"Oracle auth failed: HTTP {r.status_code} — {r.text[:200]}"
        token = r.json().get("access_token") or r.json().get("token")
        if not token:
            return False, f"Oracle auth: no token in response — {r.text[:200]}"
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Lock configuration
        r = requests.post(f"{base}/configuration/lock", headers=headers,
                          verify=False, timeout=timeout)
        if r.status_code not in (200, 204):
            return False, f"Oracle config lock failed: HTTP {r.status_code}"

        record_name = (device.csr_cn or device.hostname).replace(".", "_")
        cert_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<ImportCertificate>
  <recordName>{record_name}</recordName>
  <format>x509</format>
  <certificateRequest>{pem_text.strip()}</certificateRequest>
</ImportCertificate>"""

        # 3. Import certificate
        r = requests.put(f"{base}/configuration/certificates/import",
                         headers={**headers, "Content-Type": "application/xml"},
                         data=cert_xml.encode(),
                         verify=False, timeout=timeout)
        if r.status_code not in (200, 204):
            requests.post(f"{base}/configuration/unlock", headers=headers,
                          verify=False, timeout=timeout)
            return False, f"Oracle cert import failed: HTTP {r.status_code} — {r.text[:300]}"

        # 4. Save config
        requests.post(f"{base}/configuration/save", headers=headers,
                      verify=False, timeout=timeout)

        # 5. Activate config
        requests.post(f"{base}/configuration/activate", headers=headers,
                      verify=False, timeout=timeout)

        # 6. Unlock
        requests.post(f"{base}/configuration/unlock", headers=headers,
                      verify=False, timeout=timeout)

        return True, "Certificate successfully pushed to Oracle Acme Packet SBC (device reboot may be required)"

    except requests.exceptions.ConnectTimeout:
        return False, f"Timed out connecting to {host}:{port}"
    except requests.exceptions.ConnectionError as e:
        return False, f"Could not connect to {host}:{port} — {e}"
    except Exception as e:
        return False, f"Oracle push error: {e}"


def _push_ribbon_cert(device, pem_text):
    """
    Push certificate to Ribbon SBC Edge (1000/2000/SWe Lite) via REST API.
    Flow: login (session cookie) → POST certificate multipart → logout
    Returns (ok: bool, message: str)
    """
    import requests, urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    host     = device.ip_address or device.hostname
    port     = device.mgmt_port  or 443
    username = device.username   or "admin"
    password = device.password   or ""
    base     = f"https://{host}:{port}/rest"
    timeout  = 15

    session = requests.Session()
    session.verify = False

    try:
        # 1. Login — returns session token cookie
        r = session.post(f"{base}/login",
                         data={"Username": username, "Password": password},
                         timeout=timeout)
        if r.status_code not in (200, 201):
            return False, f"Ribbon login failed: HTTP {r.status_code} — {r.text[:200]}"

        # 2. Upload certificate as multipart file
        r = session.post(
            f"{base}/v1/certificate",
            files={"file": ("cert.pem", pem_text.encode(), "application/x-pem-file")},
            timeout=timeout,
        )

        # 3. Logout cleanly
        try:
            session.post(f"{base}/logout", timeout=5)
        except Exception:
            pass

        if r.status_code in (200, 201):
            return True, "Certificate successfully pushed to Ribbon SBC Edge"
        else:
            return False, f"Ribbon cert upload failed: HTTP {r.status_code} — {r.text[:300]}"

    except requests.exceptions.ConnectTimeout:
        return False, f"Timed out connecting to {host}:{port}"
    except requests.exceptions.ConnectionError as e:
        return False, f"Could not connect to {host}:{port} — {e}"
    except Exception as e:
        return False, f"Ribbon push error: {e}"


def _push_cert_to_device(device, pem_text):
    """
    Dispatcher — calls the correct push function based on product_type.
    Returns (ok: bool, message: str)
    """
    pt = device.product_type

    if pt == "audiocodes_sbc":
        return _push_audiocodes_cert(device, pem_text)

    elif pt == "oracle_sbc":
        return _push_oracle_cert(device, pem_text)

    elif pt == "ribbon_sbc":
        return _push_ribbon_cert(device, pem_text)

    elif pt == "anynode_sbc":
        try:
            from app.utils.cisco_cert_push import push_anynode_cert_ssh
            return push_anynode_cert_ssh(device, pem_text)
        except ImportError as e:
            return False, f"cisco_cert_push module not found: {e}"

    elif pt == "cisco_cucm":
        try:
            from app.utils.cisco_cert_push import push_cucm_cert
            return push_cucm_cert(device, pem_text)
        except ImportError as e:
            return False, f"cisco_cert_push module not found: {e}"

    elif pt in ("cisco_sbc", "cisco_gw"):
        try:
            from app.utils.cisco_cert_push import push_cube_cert_ssh
            return push_cube_cert_ssh(device, pem_text)
        except ImportError as e:
            return False, f"cisco_cert_push module not found: {e}"

    elif pt == "cisco_expressway":
        try:
            from app.utils.cisco_cert_push import push_expressway_cert
            return push_expressway_cert(device, pem_text)
        except ImportError as e:
            return False, f"cisco_cert_push module not found: {e}"

    else:
        return (False,
                f"Automated certificate push is not yet supported for '{pt}'. "
                "Please deploy the certificate manually, then click Scan to verify.")


    """
    Push the signed certificate (and private key if stored) to an AudioCodes SBC
    via its REST API.

    Steps:
      1. GET /api/v1/files/tls          → discover available TLS context IDs
      2. PUT /api/v1/files/tls/<id>/privateKey   (if private key available)
      3. PUT /api/v1/files/tls/<id>/certificate

    Returns (ok: bool, message: str)
    """
    import requests, urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    host     = device.ip_address or device.hostname
    port     = device.mgmt_port  or 443
    username = device.username   or "Admin"
    password = device.password   or ""
    auth     = (username, password)
    timeout  = 15
    base     = f"https://{host}:{port}/api/v1"

    # 1. Discover TLS context IDs — default is index 0 on AudioCodes
    tls_id = 0
    try:
        r = requests.get(f"{base}/files/tls", auth=auth,
                         verify=False, timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            contexts = data.get("tls", [])
            if contexts:
                # Use the first context (usually "default") unless device stores a preferred one
                tls_id = contexts[0].get("id", 0)
    except Exception:
        pass  # fall through to default 0

    tls_base = f"{base}/files/tls/{tls_id}"
    key_errors = []

    # 2. Push private key (camelCase endpoint: /privateKey)
    if device.private_key_pem:
        try:
            r = requests.put(
                f"{tls_base}/privateKey",
                auth=auth,
                files={"file": ("private.key",
                                device.private_key_pem.encode(),
                                "application/octet-stream")},
                verify=False, timeout=timeout,
            )
            if r.status_code not in (200, 204):
                key_errors.append(f"HTTP {r.status_code}: {r.text[:200]}")
        except Exception as e:
            key_errors.append(str(e))

    # 3. Push certificate chain
    try:
        r = requests.put(
            f"{tls_base}/certificate",
            auth=auth,
            files={"file": ("cert.pem",
                            pem_text.encode(),
                            "application/octet-stream")},
            verify=False, timeout=timeout,
        )
        if r.status_code == 200:
            if key_errors:
                return False, ("Certificate pushed OK but private key failed — "
                               + "; ".join(key_errors))
            return True, f"Certificate successfully pushed to AudioCodes SBC (TLS context {tls_id})"
        elif r.status_code == 400:
            return False, f"AudioCodes rejected the certificate: {r.text[:300]}"
        elif r.status_code == 409:
            return False, ("AudioCodes returned 409 — device may be synchronising, "
                           "wait a moment then try again")
        else:
            return False, f"AudioCodes returned HTTP {r.status_code}: {r.text[:300]}"
    except requests.exceptions.ConnectTimeout:
        return False, f"Timed out connecting to {host}:{port} — check IP/port/firewall"
    except requests.exceptions.ConnectionError as e:
        return False, f"Could not connect to {host}:{port} — {e}"
    except Exception as e:
        return False, f"Push error: {e}"


@cert_bp.route("/")
@admin_required
def index():
    from app.models import SMTPConfig
    domains = CertDomain.query.order_by(CertDomain.hostname).all()
    devices = CertDevice.query.order_by(CertDevice.product_type, CertDevice.hostname).all()
    smtp    = SMTPConfig.get()
    return render_template("admin/cert_monitor.html",
                           domains=domains, devices=devices,
                           smtp=smtp,
                           product_list=CERT_DEVICE_PRODUCTS)


# ── Domain CRUD ────────────────────────────────────────────────
@cert_bp.route("/add", methods=["POST"])
@admin_required
def add_domain():
    hostname = request.form.get("hostname", "").strip().lower()
    if not hostname:
        flash("Hostname required.", "danger")
        return redirect(url_for("cert_monitor.index"))
    if CertDomain.query.filter_by(hostname=hostname).first():
        flash(f"'{hostname}' already monitored.", "warning")
        return redirect(url_for("cert_monitor.index"))
    d = CertDomain(
        hostname    = hostname,
        port        = int(request.form.get("port") or 443),
        label       = request.form.get("label", "").strip() or None,
        notify_days = int(request.form.get("notify_days") or 30),
        added_by    = current_user.username,
    )
    db.session.add(d); db.session.commit()
    log_audit("CREATE", "cert_domain", d.id, f"Added: {hostname}")
    flash(f"'{hostname}' added.", "success")
    return redirect(url_for("cert_monitor.index"))


@cert_bp.route("/<int:did>/delete", methods=["POST"])
@admin_required
def delete_domain(did):
    d = CertDomain.query.get_or_404(did); name = d.hostname
    db.session.delete(d); db.session.commit()
    log_audit("DELETE", "cert_domain", did, f"Removed: {name}")
    flash(f"'{name}' removed.", "warning")
    return redirect(url_for("cert_monitor.index"))


# ── Device CRUD ────────────────────────────────────────────────
@cert_bp.route("/device/add", methods=["POST"])
@admin_required
def add_device():
    hostname = request.form.get("hostname", "").strip()
    if not hostname:
        flash("Hostname / FQDN required.", "danger")
        return redirect(url_for("cert_monitor.index"))
    d = CertDevice(
        product_type = request.form.get("product_type", "cisco_cucm"),
        label        = request.form.get("label", "").strip() or None,
        hostname     = hostname,
        port         = int(request.form.get("port") or 443),
        ip_address   = request.form.get("ip_address", "").strip() or None,
        username     = request.form.get("username", "").strip() or None,
        transport    = request.form.get("transport", "tls"),
        mgmt_port    = int(request.form.get("mgmt_port") or 0) or None,
        ssh_port     = int(request.form.get("ssh_port") or 0) or None,
        sip_port     = int(request.form.get("sip_port") or 0) or None,
        notify_days  = int(request.form.get("notify_days") or 30),
        added_by     = current_user.username,
    )
    if request.form.get("password"):
        d.password = request.form["password"]
    db.session.add(d); db.session.commit()
    log_audit("CREATE", "cert_device", d.id, f"Added device: {d.product_type} {hostname}")
    flash(f"Device '{hostname}' added.", "success")
    return redirect(url_for("cert_monitor.index"))


@cert_bp.route("/device/<int:did>/delete", methods=["POST"])
@admin_required
def delete_device(did):
    d = CertDevice.query.get_or_404(did); name = d.hostname
    db.session.delete(d); db.session.commit()
    log_audit("DELETE", "cert_device", did, f"Removed device: {name}")
    flash(f"Device '{name}' removed.", "warning")
    return redirect(url_for("cert_monitor.index"))


# ── Scan ───────────────────────────────────────────────────────
@cert_bp.route("/<int:did>/scan")
@admin_required
def scan_domain(did):
    d = CertDomain.query.get_or_404(did)
    res = _scan_host(d.hostname, d.port)
    cr = _make_result(d.id, "domain", res)
    db.session.add(cr); db.session.commit()
    log_audit("READ", "cert_domain", did, f"Scanned {d.hostname}: {res['risk']}")
    return jsonify({**res, "id": cr.id})


@cert_bp.route("/device/<int:did>/scan")
@admin_required
def scan_device(did):
    d = CertDevice.query.get_or_404(did)
    res = _scan_host(d.hostname, d.port)
    cr = _make_result(d.id, "device", res)
    db.session.add(cr); db.session.commit()
    log_audit("READ", "cert_device", did, f"Scanned device {d.hostname}: {res['risk']}")
    return jsonify({**res, "id": cr.id})


@cert_bp.route("/scan-all", methods=["POST"])
@admin_required
def scan_all():
    count = 0
    for d in CertDomain.query.filter_by(is_active=True).all():
        res = _scan_host(d.hostname, d.port)
        db.session.add(_make_result(d.id, "domain", res)); count += 1
    for d in CertDevice.query.filter_by(is_active=True).all():
        res = _scan_host(d.hostname, d.port)
        db.session.add(_make_result(d.id, "device", res)); count += 1
    db.session.commit()
    log_audit("ACTION", "cert_monitor", None, f"Bulk scan: {count} items")
    flash(f"Scanned {count} items.", "success")
    return redirect(url_for("cert_monitor.index"))


# ── Alerts ─────────────────────────────────────────────────────
@cert_bp.route("/send-alerts", methods=["POST"])
@admin_required
def send_alerts():
    from app.utils.mailer import send_cert_expiry_alerts
    result = send_cert_expiry_alerts()
    if result.get("skipped"):
        flash("SMTP not enabled or configured — no alerts sent.", "warning")
    elif result["ok"]:
        flash(f"Alert email sent for {result.get('sent', 0)} item(s).", "success")
    else:
        flash(f"Alert send failed: {result.get('error')}", "danger")
    return redirect(url_for("cert_monitor.index"))


# ── CSR generate (domain) ─────────────────────────────────────
@cert_bp.route("/<int:did>/generate-csr", methods=["POST"])
@admin_required
def generate_csr(did):
    d = CertDomain.query.get_or_404(did)
    d.csr_cn       = request.form.get("csr_cn",       d.hostname).strip()
    d.csr_org      = request.form.get("csr_org",      "").strip() or None
    d.csr_ou       = request.form.get("csr_ou",       "").strip() or None
    d.csr_country  = request.form.get("csr_country",  "").strip() or None
    d.csr_state    = request.form.get("csr_state",    "").strip() or None
    d.csr_locality = request.form.get("csr_locality", "").strip() or None
    d.csr_sans     = request.form.get("csr_sans",     "").strip() or None
    try:
        key_pem, csr_pem = _generate_csr_pem(d)
    except ImportError:
        flash("Install 'cryptography' package first.", "danger")
        return redirect(url_for("cert_monitor.index"))
    except Exception as e:
        flash(f"CSR generation failed: {e}", "danger")
        return redirect(url_for("cert_monitor.index"))
    d.private_key_pem  = key_pem
    d.csr_pem          = csr_pem
    d.csr_generated_at = datetime.now(timezone.utc)
    db.session.commit()
    log_audit("ACTION", "cert_domain", did, f"CSR generated {d.hostname}")
    flash(f"CSR generated for '{d.hostname}'.", "success")
    return redirect(url_for("cert_monitor.index"))


# ── CSR generate (device) ─────────────────────────────────────
@cert_bp.route("/device/<int:did>/generate-csr", methods=["POST"])
@admin_required
def generate_device_csr(did):
    d = CertDevice.query.get_or_404(did)
    d.csr_cn       = request.form.get("csr_cn",       d.hostname).strip()
    d.csr_org      = request.form.get("csr_org",      "").strip() or None
    d.csr_ou       = request.form.get("csr_ou",       "").strip() or None
    d.csr_country  = request.form.get("csr_country",  "").strip() or None
    d.csr_state    = request.form.get("csr_state",    "").strip() or None
    d.csr_locality = request.form.get("csr_locality", "").strip() or None
    d.csr_sans     = request.form.get("csr_sans",     "").strip() or None
    try:
        key_pem, csr_pem = _generate_csr_pem(d)
    except ImportError:
        flash("Install 'cryptography' package first.", "danger")
        return redirect(url_for("cert_monitor.index"))
    except Exception as e:
        flash(f"CSR generation failed: {e}", "danger")
        return redirect(url_for("cert_monitor.index"))
    d.private_key_pem  = key_pem
    d.csr_pem          = csr_pem
    d.csr_generated_at = datetime.now(timezone.utc)
    db.session.commit()
    log_audit("ACTION", "cert_device", did, f"CSR generated {d.hostname}")
    flash(f"CSR generated for device '{d.hostname}'.", "success")
    return redirect(url_for("cert_monitor.index"))


# ── Downloads (domain) ────────────────────────────────────────
@cert_bp.route("/<int:did>/download-csr")
@admin_required
def download_csr(did):
    d = CertDomain.query.get_or_404(did)
    if not d.csr_pem:
        flash("No CSR found.", "warning")
        return redirect(url_for("cert_monitor.index"))
    return Response(d.csr_pem, mimetype="application/pkcs10",
                    headers={"Content-Disposition":
                             f"attachment; filename={d.hostname.replace('.','_')}.csr"})


@cert_bp.route("/<int:did>/download-key")
@admin_required
def download_key(did):
    d = CertDomain.query.get_or_404(did)
    if not d.private_key_pem:
        flash("No key found.", "warning")
        return redirect(url_for("cert_monitor.index"))
    return Response(d.private_key_pem, mimetype="application/x-pem-file",
                    headers={"Content-Disposition":
                             f"attachment; filename={d.hostname.replace('.','_')}.key"})


@cert_bp.route("/<int:did>/upload-cert", methods=["POST"])
@admin_required
def upload_cert(did):
    d = CertDomain.query.get_or_404(did)
    pem, info = _upload_cert_logic(d, request)
    if pem is None:
        flash(info, "danger")
        return redirect(url_for("cert_monitor.index"))
    d.cert_chain_pem   = pem
    d.cert_uploaded_at = datetime.now(timezone.utc)
    cr = _result_from_pem(pem, d.id, "domain", flash_fn=flash)
    if cr:
        db.session.add(cr)
    db.session.commit()
    log_audit("ACTION", "cert_domain", did, f"Cert uploaded {d.hostname}")
    flash(f"Certificate stored: {info}", "success")
    return redirect(url_for("cert_monitor.index"))


@cert_bp.route("/<int:did>/download-chain")
@admin_required
def download_chain(did):
    d = CertDomain.query.get_or_404(did)
    if not d.cert_chain_pem:
        flash("No chain uploaded.", "warning")
        return redirect(url_for("cert_monitor.index"))
    return Response(d.cert_chain_pem, mimetype="application/x-pem-file",
                    headers={"Content-Disposition":
                             f"attachment; filename={d.hostname.replace('.','_')}_chain.pem"})


# ── Downloads (device) ────────────────────────────────────────
@cert_bp.route("/device/<int:did>/download-csr")
@admin_required
def download_device_csr(did):
    d = CertDevice.query.get_or_404(did)
    if not d.csr_pem:
        flash("No CSR found.", "warning")
        return redirect(url_for("cert_monitor.index"))
    return Response(d.csr_pem, mimetype="application/pkcs10",
                    headers={"Content-Disposition":
                             f"attachment; filename={d.hostname.replace('.','_')}_device.csr"})


@cert_bp.route("/device/<int:did>/download-key")
@admin_required
def download_device_key(did):
    d = CertDevice.query.get_or_404(did)
    if not d.private_key_pem:
        flash("No key found.", "warning")
        return redirect(url_for("cert_monitor.index"))
    return Response(d.private_key_pem, mimetype="application/x-pem-file",
                    headers={"Content-Disposition":
                             f"attachment; filename={d.hostname.replace('.','_')}_device.key"})


@cert_bp.route("/device/<int:did>/upload-cert", methods=["POST"])
@admin_required
def upload_device_cert(did):
    d = CertDevice.query.get_or_404(did)
    pem, info = _upload_cert_logic(d, request)
    if pem is None:
        flash(info, "danger")
        return redirect(url_for("cert_monitor.index"))
    d.cert_chain_pem   = pem
    d.cert_uploaded_at = datetime.now(timezone.utc)
    # Create a CertResult from the uploaded PEM so the dashboard reflects it immediately
    cr = _result_from_pem(pem, d.id, "device", flash_fn=flash)
    if cr:
        db.session.add(cr)
    db.session.commit()
    log_audit("ACTION", "cert_device", did, f"Cert uploaded {d.hostname}")
    flash(f"Certificate stored for device: {info}", "success")

    # Auto-push to device via REST API
    if not (d.ip_address or d.hostname) or not d.username:
        flash("Certificate stored but not pushed — device has no IP/username configured.", "warning")
    else:
        try:
            ok, msg = _push_cert_to_device(d, pem)
            if ok:
                flash(f"✓ Pushed to device: {msg}", "success")
            else:
                flash(f"Certificate stored but push to device failed: {msg}", "warning")
        except Exception as e:
            flash(f"Certificate stored but push failed unexpectedly: {e}", "danger")

    return redirect(url_for("cert_monitor.index"))


@cert_bp.route("/device/<int:did>/download-chain")
@admin_required
def download_device_chain(did):
    d = CertDevice.query.get_or_404(did)
    if not d.cert_chain_pem:
        flash("No chain uploaded.", "warning")
        return redirect(url_for("cert_monitor.index"))
    return Response(d.cert_chain_pem, mimetype="application/x-pem-file",
                    headers={"Content-Disposition":
                             f"attachment; filename={d.hostname.replace('.','_')}_device_chain.pem"})
