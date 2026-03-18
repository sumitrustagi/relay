"""
RELAY — Cisco Certificate Push Module
======================================
Handles automated certificate deployment for all Cisco device types:

  cisco_cucm        → Cisco UC Certificate Management REST API
                       POST /platformcom/api/v1/certmgr/config/certificate
                       (CUCM 11.5+ / IM&P / Unity Connection)

  cisco_expressway  → Expressway REST API
                       POST /api/provisioning/security/certificate/server

  cisco_sbc         → Cisco CUBE (IOS-XE) via SSH
                       crypto pki import <trustpoint> pem terminal

  cisco_gw          → Cisco IOS Analog Gateway via SSH
                       Same crypto pki import flow as CUBE

  anynode_sbc       → Anynode SBC via SSH (Linux)
                       SCP cert + key to /etc/anynode/certs/ and restart

Requirements:
  pip install requests paramiko

Each push function returns (ok: bool, message: str).
"""

import logging
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
#  CUCM  —  UC Certificate Management REST API
#  Supported products: CUCM, IM&P, Unity Connection (all 11.5+)
#  Docs: https://developer.cisco.com/docs/certificate-management/
# ══════════════════════════════════════════════════════════════════════════════

# Map of cert service names CUCM uses.  The device model stores which service
# (e.g. "tomcat", "callmanager") to target; default is "tomcat" (HTTPS/web UI).
CUCM_CERT_SERVICES = [
    "tomcat",        # Web UI / Tomcat HTTPS
    "callmanager",   # SIP TLS / phone registration
    "ipsec",         # IPSec tunnels
    "tvs",           # Trust Verification Service
    "capf",          # Certificate Authority Proxy Function
]


def push_cucm_cert(device, pem_text):
    """
    Upload a signed certificate chain to CUCM (or IM&P / CUC) using
    Cisco's UC Certificate Management REST API.

    The signed cert replaces the certificate for the target service
    (default: tomcat).  The private key already lives on CUCM — it was
    generated there when the CSR was created, so we only send the cert.

    Endpoint:
      POST https://<host>:8443/platformcom/api/v1/certmgr/config/certificate

    Body (multipart):
      file        — PEM file
      service     — target cert service (tomcat, callmanager, …)

    Returns (ok: bool, message: str)
    """
    host     = device.ip_address or device.hostname
    port     = device.mgmt_port  or 8443
    username = device.username   or "admin"
    password = device.password   or ""
    # Allow callers to store a preferred service name on the device label
    service  = getattr(device, "cucm_cert_service", None) or "tomcat"
    timeout  = 20

    base = f"https://{host}:{port}"
    session = requests.Session()
    session.verify = False

    try:
        # ── 1. Authenticate (session cookie) ─────────────────────────────────
        login_resp = session.post(
            f"{base}/platformcom/api/v1/certmgr/login",
            json={"username": username, "password": password},
            timeout=timeout,
        )
        if login_resp.status_code not in (200, 201):
            # Fall back to HTTP Basic Auth — older CUCM versions don't use
            # the /login endpoint; they accept Basic on every request.
            session.auth = (username, password)

        # ── 2. Upload signed certificate ──────────────────────────────────────
        upload_resp = session.post(
            f"{base}/platformcom/api/v1/certmgr/config/certificate",
            files={
                "file": (f"{service}.pem", pem_text.encode(), "application/x-pem-file"),
            },
            data={"service": service},
            timeout=timeout,
        )

        if upload_resp.status_code in (200, 201):
            msg = (
                f"Certificate uploaded to CUCM ({service}). "
                "Restart the relevant Cisco service for it to take effect "
                f"(Serviceability → Tools → Control Center → Cisco {service.capitalize()})."
            )
            return True, msg

        elif upload_resp.status_code == 400:
            detail = _json_msg(upload_resp) or upload_resp.text[:300]
            return False, f"CUCM rejected the certificate: {detail}"

        elif upload_resp.status_code == 401:
            return False, "CUCM authentication failed — check username/password"

        elif upload_resp.status_code == 404:
            return False, (
                f"CUCM cert API not found at {base}/platformcom/api/v1/certmgr — "
                "ensure CUCM is version 11.5+ and the platform API is reachable"
            )

        else:
            detail = _json_msg(upload_resp) or upload_resp.text[:300]
            return False, f"CUCM returned HTTP {upload_resp.status_code}: {detail}"

    except requests.exceptions.ConnectTimeout:
        return False, f"Timed out connecting to CUCM at {host}:{port}"
    except requests.exceptions.ConnectionError as e:
        return False, f"Could not connect to CUCM at {host}:{port} — {e}"
    except Exception as e:
        log.exception("push_cucm_cert unexpected error")
        return False, f"CUCM push error: {e}"
    finally:
        try:
            session.post(f"{base}/platformcom/api/v1/certmgr/logout", timeout=5)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  Cisco Expressway / VCS  —  REST API
#  Docs: Cisco-Expressway-REST-API-Reference-Guide (X8.9+)
# ══════════════════════════════════════════════════════════════════════════════

def push_expressway_cert(device, pem_text):
    """
    Upload a signed server certificate (and optionally the private key) to
    a Cisco Expressway or VCS via its REST API.

    Endpoints:
      POST /api/provisioning/security/certificate/server
           Body: multipart — cert_file (required), key_file (if RELAY has key)

    The Expressway must be restarted for the new certificate to take effect.

    Returns (ok: bool, message: str)
    """
    host     = device.ip_address or device.hostname
    port     = device.mgmt_port  or 443
    username = device.username   or "admin"
    password = device.password   or ""
    timeout  = 20

    base = f"https://{host}:{port}"
    session = requests.Session()
    session.verify = False
    session.auth   = (username, password)

    try:
        # Build multipart — include private key only if RELAY generated the CSR
        files = {
            "cert_file": ("server.pem", pem_text.encode(), "application/x-pem-file"),
        }
        if device.private_key_pem:
            files["key_file"] = (
                "server.key",
                device.private_key_pem.encode(),
                "application/x-pem-file",
            )

        resp = session.post(
            f"{base}/api/provisioning/security/certificate/server",
            files=files,
            timeout=timeout,
        )

        if resp.status_code in (200, 201, 204):
            key_note = " and private key" if device.private_key_pem else ""
            return True, (
                f"Certificate{key_note} uploaded to Expressway. "
                "⚠️  You must restart the Expressway for the new certificate to take effect "
                "(Maintenance → Restart options → Restart)."
            )
        elif resp.status_code == 400:
            return False, f"Expressway rejected the certificate: {_json_msg(resp) or resp.text[:300]}"
        elif resp.status_code == 401:
            return False, "Expressway authentication failed — check username/password"
        elif resp.status_code == 403:
            return False, "Expressway returned 403 Forbidden — check user has admin rights"
        elif resp.status_code == 404:
            return False, (
                f"Expressway REST API not found at {base}/api/provisioning — "
                "ensure software version is X8.9+ and the API is enabled"
            )
        elif resp.status_code == 409:
            return False, (
                "Expressway returned 409 — a CSR may still be pending on the device. "
                "Discard or complete the in-progress CSR on the Expressway first."
            )
        else:
            return False, f"Expressway returned HTTP {resp.status_code}: {resp.text[:300]}"

    except requests.exceptions.ConnectTimeout:
        return False, f"Timed out connecting to Expressway at {host}:{port}"
    except requests.exceptions.ConnectionError as e:
        return False, f"Could not connect to Expressway at {host}:{port} — {e}"
    except Exception as e:
        log.exception("push_expressway_cert unexpected error")
        return False, f"Expressway push error: {e}"


# ══════════════════════════════════════════════════════════════════════════════
#  Cisco CUBE / IOS-XE / IOS Analog Gateway  —  SSH
#  Uses paramiko to drive the IOS CLI.
#  The cert is imported into an IOS PKI trustpoint via:
#    crypto pki import <trustpoint> pem terminal
# ══════════════════════════════════════════════════════════════════════════════

_CUBE_TRUSTPOINT = "RELAY_CERT"   # default trustpoint name RELAY will use


def push_cube_cert_ssh(device, pem_text):
    """
    Import a signed certificate + private key into a Cisco IOS-XE / IOS
    device (CUBE or Analog Gateway) via SSH using paramiko.

    Steps:
      1. SSH to device
      2. Enter config mode
      3. Create/verify PKI trustpoint
      4. Import PEM certificate via terminal (interactive)
      5. Write memory

    The private key is sent as part of the PEM import if RELAY generated the CSR.

    Returns (ok: bool, message: str)
    """
    try:
        import paramiko
        import time
        import re as _re
    except ImportError:
        return False, (
            "paramiko is required for CUBE SSH push — "
            "run: pip install paramiko"
        )

    host      = device.ip_address or device.hostname
    port      = device.mgmt_port  or 22
    username  = device.username   or "admin"
    password  = device.password   or ""
    trustpoint = _CUBE_TRUSTPOINT
    timeout   = 30

    def _send(shell, cmd, wait=1.5):
        """Send a command and wait for output."""
        shell.send(cmd + "\n")
        time.sleep(wait)
        out = ""
        while shell.recv_ready():
            out += shell.recv(4096).decode("utf-8", errors="replace")
        return out

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host, port=port,
            username=username, password=password,
            look_for_keys=False, allow_agent=False,
            timeout=timeout,
        )
        shell = client.invoke_shell(width=250, height=50)
        time.sleep(1)
        shell.recv(4096)  # drain banner

        # Enter enable + config mode
        _send(shell, "enable",    wait=0.8)
        _send(shell, password,    wait=0.8)   # enable password (same as login for CUBE)
        _send(shell, "conf t",    wait=0.8)

        # Create trustpoint
        _send(shell, f"crypto pki trustpoint {trustpoint}", wait=0.5)
        _send(shell, " enrollment terminal pem",            wait=0.5)
        _send(shell, " revocation-check none",              wait=0.5)
        _send(shell, " exit",                               wait=0.5)

        # ── Import private key (if RELAY generated the CSR) ──────────────────
        if device.private_key_pem:
            _send(shell, f"crypto pki import {trustpoint} pem terminal", wait=0.8)
            # IOS prompts: "% Enter PEM-formatted encrypted general purpose key."
            # Feed key blocks then quit marker
            for line in device.private_key_pem.strip().splitlines():
                _send(shell, line, wait=0.05)
            out = _send(shell, "quit", wait=2)
            if "error" in out.lower() or "invalid" in out.lower():
                client.close()
                return False, f"IOS rejected private key: {out.strip()[-300:]}"

        # ── Import certificate ────────────────────────────────────────────────
        _send(shell, f"crypto pki import {trustpoint} certificate", wait=0.8)
        # IOS prompts: "% Enter the base 64 encoded certificate."
        for line in pem_text.strip().splitlines():
            _send(shell, line, wait=0.05)
        out = _send(shell, "quit", wait=3)

        if "successfully" in out.lower() or "imported" in out.lower():
            _send(shell, "end",        wait=0.5)
            _send(shell, "write mem",  wait=3)
            client.close()
            return True, (
                f"Certificate imported to IOS trustpoint '{trustpoint}' "
                "and configuration saved. Bind the trustpoint to your SIP TLS profile "
                f"(crypto signaling default trustpoint {trustpoint}) if not already done."
            )
        elif "error" in out.lower() or "invalid" in out.lower():
            client.close()
            return False, f"IOS rejected certificate: {out.strip()[-300:]}"
        else:
            # IOS sometimes just returns the prompt on success
            _send(shell, "end",       wait=0.5)
            _send(shell, "write mem", wait=3)
            client.close()
            return True, (
                f"Certificate sent to IOS trustpoint '{trustpoint}'. "
                "Verify with: show crypto pki certificates"
            )

    except paramiko.AuthenticationException:
        return False, f"SSH authentication failed for {host}:{port} — check username/password"
    except paramiko.SSHException as e:
        return False, f"SSH error connecting to {host}:{port} — {e}"
    except OSError as e:
        return False, f"Could not connect to {host}:{port} — {e}"
    except Exception as e:
        log.exception("push_cube_cert_ssh unexpected error")
        return False, f"CUBE SSH push error: {e}"
    finally:
        try:
            client.close()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  Anynode SBC  —  SSH (Linux-based)
#  Copies cert + key to /etc/anynode/certs/ via SFTP, then restarts
#  the anynode service via SSH.
# ══════════════════════════════════════════════════════════════════════════════

_ANYNODE_CERT_DIR = "/etc/anynode/certs"
_ANYNODE_SERVICE  = "anynode"


def push_anynode_cert_ssh(device, pem_text):
    """
    Deploy a signed certificate (and private key) to an Anynode SBC via SSH.

    Steps:
      1. SSH to the Linux host running Anynode
      2. SFTP the cert PEM (and key if available) to /etc/anynode/certs/
      3. Restart the anynode service

    Anynode looks for:
      /etc/anynode/certs/<hostname>.pem   — certificate chain
      /etc/anynode/certs/<hostname>.key   — private key

    Returns (ok: bool, message: str)
    """
    try:
        import paramiko
        import io
        import time
    except ImportError:
        return False, (
            "paramiko is required for Anynode SSH push — "
            "run: pip install paramiko"
        )

    host     = device.ip_address or device.hostname
    port     = device.mgmt_port  or 22
    username = device.username   or "root"
    password = device.password   or ""
    # Use CN or hostname as the base filename
    cn       = (device.csr_cn or device.hostname).replace(".", "_").replace("*", "wildcard")
    timeout  = 30

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host, port=port,
            username=username, password=password,
            look_for_keys=False, allow_agent=False,
            timeout=timeout,
        )

        sftp = client.open_sftp()

        # Ensure cert directory exists
        try:
            sftp.stat(_ANYNODE_CERT_DIR)
        except FileNotFoundError:
            _ssh_exec(client, f"mkdir -p {_ANYNODE_CERT_DIR}")

        # Write certificate chain
        cert_path = f"{_ANYNODE_CERT_DIR}/{cn}.pem"
        with sftp.open(cert_path, "w") as f:
            f.write(pem_text)
        _ssh_exec(client, f"chmod 644 {cert_path}")

        # Write private key (readable only by root)
        key_note = ""
        if device.private_key_pem:
            key_path = f"{_ANYNODE_CERT_DIR}/{cn}.key"
            with sftp.open(key_path, "w") as f:
                f.write(device.private_key_pem)
            _ssh_exec(client, f"chmod 600 {key_path}")
            key_note = f" and key to {key_path}"

        sftp.close()

        # Restart anynode service
        restart_out, restart_err = _ssh_exec(
            client, f"systemctl restart {_ANYNODE_SERVICE}"
        )
        time.sleep(2)
        status_out, _ = _ssh_exec(
            client, f"systemctl is-active {_ANYNODE_SERVICE}"
        )
        client.close()

        if "active" in status_out.strip():
            return True, (
                f"Certificate{key_note} deployed to {cert_path} and "
                f"'{_ANYNODE_SERVICE}' service restarted successfully."
            )
        else:
            return False, (
                f"Certificate copied to {cert_path}{key_note} but "
                f"'{_ANYNODE_SERVICE}' service did not come back active after restart. "
                f"Status: {status_out.strip() or restart_err.strip()}"
            )

    except paramiko.AuthenticationException:
        return False, f"SSH authentication failed for {host}:{port} — check username/password"
    except paramiko.SSHException as e:
        return False, f"SSH error connecting to {host}:{port} — {e}"
    except OSError as e:
        return False, f"Could not connect to {host}:{port} — {e}"
    except Exception as e:
        log.exception("push_anynode_cert_ssh unexpected error")
        return False, f"Anynode SSH push error: {e}"
    finally:
        try:
            client.close()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _json_msg(resp):
    """Try to extract a human-readable message from a JSON error response."""
    try:
        data = resp.json()
        return (
            data.get("message")
            or data.get("messages", [None])[0]
            or data.get("description")
            or data.get("error")
        )
    except Exception:
        return None


def _ssh_exec(client, cmd, timeout=30):
    """Execute a command over an open paramiko client, return (stdout, stderr)."""
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    return stdout.read().decode("utf-8", errors="replace"), \
           stderr.read().decode("utf-8", errors="replace")
