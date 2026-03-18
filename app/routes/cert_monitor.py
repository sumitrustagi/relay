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


# ── Index ──────────────────────────────────────────────────────
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
    db.session.commit()
    log_audit("ACTION", "cert_device", did, f"Cert uploaded {d.hostname}")
    flash(f"Certificate stored for device: {info}", "success")
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
