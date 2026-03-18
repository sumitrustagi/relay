#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  RELAY — Interactive Installer
#  Version 1.0  |  Ubuntu 20.04 / 22.04 / 24.04  |  Powered by whiptail
#
#  What this installer does:
#    1. Installs system dependencies
#    2. Asks which calling platforms to enable
#    3. Asks which add-on modules to include
#    4. Sets up the web domain, port, and SSL
#    5. Creates the admin account
#    6. Optionally hardens the server
#    7. Deploys and starts RELAY
#
#  API credentials (Teams, Webex, CUCM) and service settings (SMTP, LDAP)
#  are configured AFTER installation through the RELAY Admin GUI.
#  The installer only sets platform flags — no secrets touch the shell.
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

RELAY_VERSION="1.0"
LOG=/tmp/relay-install-$(date +%Y%m%d_%H%M%S).log
exec > >(tee -a "$LOG") 2>&1

# ── Error trap ─────────────────────────────────────────────────────────────────
# On unexpected exit, show the last 20 lines of the log in a whiptail msgbox
# so the user can see what failed without having to find the log file.
_on_error() {
    local exit_code=$?
    local line_no=$1
    # Only show dialog if whiptail is available and we're not in a subshell gauge
    if command -v whiptail &>/dev/null && [[ "${RELAY_GAUGE_ACTIVE:-}" != "1" ]]; then
        whiptail --title "Installation Failed" --scrolltext \
            --msgbox "Installation failed at line ${line_no} (exit code ${exit_code}).\n\nLast log entries:\n\n$(tail -20 \"$LOG\" 2>/dev/null)\n\nFull log: ${LOG}" \
            30 80 2>/dev/null || true
    fi
    echo -e "${RED}[FAIL]${NC}    Installation failed at line ${line_no}. Exit code: ${exit_code}"
    echo    "         Full log: ${LOG}"
}
trap '_on_error $LINENO' ERR

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}    $*"; }
success() { echo -e "${GREEN}[OK]${NC}      $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; }
die()     { echo -e "${RED}[FAIL]${NC}    $*"; exit 1; }

[[ $EUID -ne 0 ]] && die "Run as root: sudo bash relay-install.sh"

# ── Install whiptail if missing ───────────────────────────────────────────────
if ! command -v whiptail &>/dev/null; then
    apt-get update -qq && apt-get install -y whiptail &>/dev/null
fi

# ── Terminal size — recalculates on every call and on SIGWINCH ────────────────
get_term_size() {
    H=$(tput lines 2>/dev/null || echo 24)
    W=$(tput cols  2>/dev/null || echo 80)
    DH=$(( H > 24 ? H - 4 : 20 ))
    DW=$(( W > 76 ? W - 8 : 72 ))
}
get_term_size
trap 'get_term_size' SIGWINCH

# ── Resize-safe whiptail wrapper ──────────────────────────────────────────────
# whiptail exits 255 on SIGWINCH (resize). With set -euo pipefail that would
# kill the script before ret=$? captures anything.
# `|| ret=$?` suppresses set -e so the loop can catch 255 and retry cleanly.
# The standard 3>&1 1>&2 2>&3 fd-swap still works correctly even with the
# exec > >(tee) 2>&1 redirect at the top of the script.
wt() {
    local ret=0
    while true; do
        whiptail "$@" || ret=$?
        [[ $ret -eq 255 ]] || return $ret
        ret=0
        get_term_size
    done
}

pyesc() { printf '%s' "$1" | sed "s/'/'\\\\''/g"; }

# ══════════════════════════════════════════════════════════════════════════════
# SCREEN 1 — Welcome
# ══════════════════════════════════════════════════════════════════════════════
wt --title "RELAY v${RELAY_VERSION} — Installer" \
  --msgbox "\n\
  ██████╗ ███████╗██╗      █████╗ ██╗   ██╗\n\
  ██╔══██╗██╔════╝██║     ██╔══██╗╚██╗ ██╔╝\n\
  ██████╔╝█████╗  ██║     ███████║ ╚████╔╝ \n\
  ██╔══██╗██╔══╝  ██║     ██╔══██║  ╚██╔╝  \n\
  ██║  ██║███████╗███████╗██║  ██║   ██║   \n\
  ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝   \n\n\
  Multi-Platform Call Forwarding Manager\n\
  Version ${RELAY_VERSION}  |  Powered by HCLTech\n\n\
  This wizard will:\n\
    • Choose platforms and add-on modules\n\
    • Create the admin account\n\
    • Deploy and start RELAY\n\n\
  API credentials (Teams, Webex, CUCM) and service settings\n\
  (SMTP, LDAP) are configured in the Admin GUI after install.\n\n\
  Press ENTER to continue." \
  $DH $DW

# ══════════════════════════════════════════════════════════════════════════════
# SCREEN 2 — Pre-flight
# ══════════════════════════════════════════════════════════════════════════════
{
set +e  # Prevent silent exit on apt failures inside gauge
  echo 5;  info "Updating package index..."
  apt-get update -qq
  echo 25; info "Installing system packages..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
      python3 python3-pip python3-venv \
      nginx certbot python3-certbot-nginx \
      sqlite3 curl git rsync fail2ban logrotate \
      whiptail 2>&1 | tail -1
  # NOTE: Do NOT upgrade the system pip3 here.
  # Ubuntu 22.04+ enforces PEP 668 (externally-managed-environment) which
  # blocks pip3 from modifying system packages. Pip is upgraded inside the
  # virtualenv instead (see Phase 1 step 2).
  echo 100
} | whiptail --title "Pre-flight — System Dependencies" \
    --gauge "Installing dependencies..." $DH $DW 0

# ══════════════════════════════════════════════════════════════════════════════
# SCREEN 3 — Installation path & user
# ══════════════════════════════════════════════════════════════════════════════
INSTALL_DIR=$(wt --title "Installation Directory" \
  --inputbox "\nWhere should RELAY be installed?\n\n  Default: /opt/relay" \
  $DH $DW "/opt/relay" 3>&1 1>&2 2>&3) || die "Cancelled."
[[ -z "$INSTALL_DIR" ]] && INSTALL_DIR="/opt/relay"

APP_USER=$(wt --title "Application User" \
  --inputbox "\nLinux system user that will own and run RELAY:\n\n  (Created automatically if it does not exist)" \
  $DH $DW "relay" 3>&1 1>&2 2>&3) || die "Cancelled."
[[ -z "$APP_USER" ]] && APP_USER="relay"

# ══════════════════════════════════════════════════════════════════════════════
# SCREEN 4 — Platform selection
# ══════════════════════════════════════════════════════════════════════════════
PLATFORM_CHOICE=$(wt --title "Calling Platforms" \
  --menu "\nSelect which calling platforms RELAY will manage.\n\nYou can enable or disable platforms later in Admin → Platform Settings." \
  $DH $DW 7 \
  "1" "Microsoft Teams only" \
  "2" "Webex Calling only" \
  "3" "Cisco CUCM only" \
  "4" "Teams + Webex Calling" \
  "5" "Teams + Cisco CUCM" \
  "6" "Webex Calling + Cisco CUCM" \
  "7" "All three — Teams + Webex + CUCM" \
  3>&1 1>&2 2>&3) || die "Cancelled."

case "$PLATFORM_CHOICE" in
  1) HAS_TEAMS=true;  HAS_WEBEX=false; HAS_CUCM=false; PLAT_LABEL="Microsoft Teams" ;;
  2) HAS_TEAMS=false; HAS_WEBEX=true;  HAS_CUCM=false; PLAT_LABEL="Webex Calling" ;;
  3) HAS_TEAMS=false; HAS_WEBEX=false; HAS_CUCM=true;  PLAT_LABEL="Cisco CUCM" ;;
  4) HAS_TEAMS=true;  HAS_WEBEX=true;  HAS_CUCM=false; PLAT_LABEL="Teams + Webex" ;;
  5) HAS_TEAMS=true;  HAS_WEBEX=false; HAS_CUCM=true;  PLAT_LABEL="Teams + CUCM" ;;
  6) HAS_TEAMS=false; HAS_WEBEX=true;  HAS_CUCM=true;  PLAT_LABEL="Webex + CUCM" ;;
  7) HAS_TEAMS=true;  HAS_WEBEX=true;  HAS_CUCM=true;  PLAT_LABEL="Teams + Webex + CUCM" ;;
  *) die "Invalid selection." ;;
esac

# ══════════════════════════════════════════════════════════════════════════════
# SCREEN 5 — Add-on modules
#
# Note: LDAP Sync and Audit Logging are offered together as a bundle.
#       SMTP (for cert alerts) and LDAP server details are configured
#       via the Admin GUI after installation — not here.
# ══════════════════════════════════════════════════════════════════════════════
ADDONS=$(wt --title "Add-on Modules" \
  --checklist "\nSelect optional modules to include.\n\nUse SPACE to toggle, ENTER to confirm.\n\nNote: LDAP Sync includes Audit Logging.\nSMTP and LDAP server credentials are configured\nvia the Admin GUI after installation." \
  $DH $DW 3 \
  "cert_monitor" "Certificate Monitor  — SSL/TLS expiry tracking for domains & devices" ON \
  "did_mgmt"     "DID Management       — Phone number inventory across all platforms"   ON \
  "ldap_audit"   "LDAP Sync + Auditing — AD user import, role assignment, full audit trail" OFF \
  3>&1 1>&2 2>&3) || die "Cancelled."

HAS_CERT_MONITOR=false
HAS_DID=false
HAS_LDAP=false
HAS_AUDIT=false

[[ "$ADDONS" == *"cert_monitor"* ]] && HAS_CERT_MONITOR=true
[[ "$ADDONS" == *"did_mgmt"*     ]] && HAS_DID=true
# LDAP and Audit are bundled — enable both together
if [[ "$ADDONS" == *"ldap_audit"* ]]; then
    HAS_LDAP=true
    HAS_AUDIT=true
fi

# ══════════════════════════════════════════════════════════════════════════════
# SCREEN 6 — Web / domain settings
# ══════════════════════════════════════════════════════════════════════════════
DOMAIN=$(wt --title "Domain Name" \
  --inputbox "\nFully qualified domain name for RELAY:\n\n  Used for Nginx server_name and optional Let's Encrypt SSL.\n  Use 'localhost' for a local/internal install.\n\n  Example: relay.yourcompany.com" \
  $DH $DW "" 3>&1 1>&2 2>&3) || die "Cancelled."
[[ -z "$DOMAIN" ]] && DOMAIN="localhost"

APP_PORT=$(wt --title "Application Port" \
  --inputbox "\nInternal Gunicorn port (Nginx will proxy to this):" \
  $DH $DW "5000" 3>&1 1>&2 2>&3) || die "Cancelled."
[[ -z "$APP_PORT" ]] && APP_PORT="5000"

CLIENT_NAME=$(wt --title "Organisation Name" \
  --inputbox "\nYour organisation name (shown in the RELAY sidebar):\n\n  Leave blank to hide." \
  $DH $DW "" 3>&1 1>&2 2>&3) || true

SSL_CHOICE="none"
if [[ "$DOMAIN" != "localhost" ]]; then
  SSL_CHOICE=$(wt --title "SSL Certificate" \
    --menu "\nHow should RELAY serve HTTPS?" \
    $DH $DW 3 \
    "letsencrypt" "Let's Encrypt — auto-renewing, requires public domain" \
    "selfsigned"  "Self-signed   — for internal / dev use" \
    "none"        "HTTP only     — configure SSL manually later" \
    3>&1 1>&2 2>&3) || SSL_CHOICE="none"
fi

# ══════════════════════════════════════════════════════════════════════════════
# SCREEN 7 — Admin account
# ══════════════════════════════════════════════════════════════════════════════
ADMIN_USER=$(wt --title "Admin Account" \
  --inputbox "\nRELAY GUI admin username:" \
  $DH $DW "admin" 3>&1 1>&2 2>&3) || die "Cancelled."
[[ -z "$ADMIN_USER" ]] && ADMIN_USER="admin"

ADMIN_EMAIL=$(wt --title "Admin Account" \
  --inputbox "\nAdmin email address:" \
  $DH $DW "admin@${DOMAIN}" 3>&1 1>&2 2>&3) || die "Cancelled."

while true; do
  ADMIN_PASS=$(wt --title "Admin Account" \
    --passwordbox "\nAdmin password (minimum 8 characters):" \
    $DH $DW "" 3>&1 1>&2 2>&3) || die "Cancelled."
  ADMIN_PASS2=$(wt --title "Admin Account" \
    --passwordbox "\nConfirm admin password:" \
    $DH $DW "" 3>&1 1>&2 2>&3) || die "Cancelled."
  if [[ "$ADMIN_PASS" == "$ADMIN_PASS2" && ${#ADMIN_PASS} -ge 8 ]]; then
    break
  elif [[ "$ADMIN_PASS" != "$ADMIN_PASS2" ]]; then
    wt --title "Password Mismatch" --msgbox "\nPasswords do not match. Please try again." $DH $DW
  else
    wt --title "Password Too Short" --msgbox "\nPassword must be at least 8 characters." $DH $DW
  fi
done

# ══════════════════════════════════════════════════════════════════════════════
# SCREEN 7.5 — CLI Management User
# ══════════════════════════════════════════════════════════════════════════════
# A dedicated Linux user for server-side troubleshooting.
# This user can run 'relay' CLI commands (start/stop/restart/logs/db/etc)
# via a scoped sudoers entry — no full root access.
# ══════════════════════════════════════════════════════════════════════════════
CLI_USER=$(wt --title "CLI Management User" \
  --inputbox "\nCreate a dedicated Linux user for CLI troubleshooting.\n\n\
This user can:\n\
  • Start / stop / restart the RELAY service\n\
  • View application and system logs\n\
  • Run flask db upgrade (migrations)\n\
  • Run the 'relay' CLI management tool\n\
  • Run grep, journalctl, tail, python3 (relay venv)\n\n\
They CANNOT: sudo to root, read .env, modify system files.\n\n\
CLI username (leave blank to skip):" \
  $DH $DW "relaymgr" 3>&1 1>&2 2>&3) || die "Cancelled."

CLI_USER_CREATED=false

if [[ -n "$CLI_USER" ]]; then
  while true; do
    CLI_PASS=$(wt --title "CLI Management User" \
      --passwordbox "\nPassword for '${CLI_USER}' (minimum 8 characters):" \
      $DH $DW "" 3>&1 1>&2 2>&3) || die "Cancelled."
    CLI_PASS2=$(wt --title "CLI Management User" \
      --passwordbox "\nConfirm password:" \
      $DH $DW "" 3>&1 1>&2 2>&3) || die "Cancelled."
    if [[ "$CLI_PASS" == "$CLI_PASS2" && ${#CLI_PASS} -ge 8 ]]; then
      CLI_USER_CREATED=true
      break
    elif [[ "$CLI_PASS" != "$CLI_PASS2" ]]; then
      wt --title "Password Mismatch" --msgbox "\nPasswords do not match. Please try again." $DH $DW
    else
      wt --title "Password Too Short" --msgbox "\nPassword must be at least 8 characters." $DH $DW
    fi
  done
fi

# ══════════════════════════════════════════════════════════════════════════════
# SCREEN 8 — Security hardening
# ══════════════════════════════════════════════════════════════════════════════
RUN_SECURE=false
SSH_HARDEN=false

wt --title "Security Hardening" \
  --yesno "\nRun security hardening after installation?\n\n\
  Applies:\n\
  • File permission lockdown (.env 600, app files 750/640)\n\
  • UFW firewall (SSH + 80 + 443 only)\n\
  • Fail2ban (SSH + nginx brute-force protection)\n\
  • Nginx security headers (CSP, X-Frame, nosniff…)\n\
  • systemd service sandboxing\n\
  • Log rotation (app + nginx logs)\n\
  • Certbot auto-renewal timer\n\n\
  Recommended for any internet-facing server." \
  $DH $DW && RUN_SECURE=true || RUN_SECURE=false

if [[ "$RUN_SECURE" == true ]]; then
  wt --title "SSH Hardening" \
    --yesno "\nAlso harden SSH?\n\n\
  • Disable root login\n\
  • Disable password authentication (key-based only)\n\
  • Reduce MaxAuthTries to 3\n\n\
  ⚠  WARNING: Confirm you have SSH key access before\n\
  saying Yes — otherwise you will be locked out." \
    $DH $DW && SSH_HARDEN=true || SSH_HARDEN=false
fi

# ══════════════════════════════════════════════════════════════════════════════
# SCREEN 9 — Confirmation summary
# ══════════════════════════════════════════════════════════════════════════════
ADDON_LABEL=""
[[ "$HAS_CERT_MONITOR" == true ]] && ADDON_LABEL+="  ✔ Certificate Monitor\n"
[[ "$HAS_DID"          == true ]] && ADDON_LABEL+="  ✔ DID Management\n"
[[ "$HAS_LDAP"         == true ]] && ADDON_LABEL+="  ✔ LDAP Sync + Audit Logging\n"
[[ -z "$ADDON_LABEL" ]]          && ADDON_LABEL="  (none)\n"

SECURE_LABEL="No"
[[ "$RUN_SECURE" == true && "$SSH_HARDEN" == false ]] && SECURE_LABEL="Yes"
[[ "$SSH_HARDEN" == true ]] && SECURE_LABEL="Yes + SSH hardening"

CLI_LABEL="${CLI_USER:-skipped}"

wt --title "✅  Summary — Please Confirm" \
  --yesno "\n\
  ┌─ Installation ─────────────────────────────────┐\n\
  │  Directory  : ${INSTALL_DIR}\n\
  │  Run as     : ${APP_USER}\n\
  └────────────────────────────────────────────────┘\n\n\
  ┌─ Platforms ────────────────────────────────────┐\n\
  │  ${PLAT_LABEL}\n\
  └────────────────────────────────────────────────┘\n\n\
  ┌─ Add-on Modules ───────────────────────────────┐\n\
$(echo -e "$ADDON_LABEL")\
  └────────────────────────────────────────────────┘\n\n\
  ┌─ Web ──────────────────────────────────────────┐\n\
  │  Domain     : ${DOMAIN}\n\
  │  Port       : ${APP_PORT}\n\
  │  SSL        : ${SSL_CHOICE}\n\
  └────────────────────────────────────────────────┘\n\n\
  ┌─ Admin Account ────────────────────────────────┐\n\
  │  Username   : ${ADMIN_USER}\n\
  │  Email      : ${ADMIN_EMAIL}\n\
  └────────────────────────────────────────────────┘\n\n\
  ┌─ CLI Management User ──────────────────────────┐\n\
  │  Username   : ${CLI_LABEL}\n\
  └────────────────────────────────────────────────┘\n\n\
  ┌─ Security Hardening ───────────────────────────┐\n\
  │  Harden     : ${SECURE_LABEL}\n\
  └────────────────────────────────────────────────┘\n\n\
  API credentials are configured in Admin → Platform Settings\n\
  after installation.  Proceed?" \
  $DH $DW || die "Installation cancelled by user."

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — INSTALLATION
# ══════════════════════════════════════════════════════════════════════════════
(
# Disable exit-on-error inside the gauge subshell.
# set -euo pipefail is inherited from the parent, which would cause any
# failing command to silently exit the subshell and close the gauge.
# We handle errors explicitly here instead.
set +e

echo 5; info "Creating system user and directories..."
id "$APP_USER" &>/dev/null || useradd -r -s /bin/bash -d "$INSTALL_DIR" "$APP_USER"
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/uploads/csv" \
         "$INSTALL_DIR/uploads/certs" \
         "$INSTALL_DIR/uploads/temp" \
         "$INSTALL_DIR/instance"
rsync -a --exclude='relay-install.sh' --exclude='.git' \
    . "$INSTALL_DIR/" 2>/dev/null || cp -r . "$INSTALL_DIR/"
chown -R "$APP_USER":"$APP_USER" "$INSTALL_DIR"
chmod -R 750 "$INSTALL_DIR"
chmod 700 "$INSTALL_DIR/uploads"
echo 15

echo 20; info "Creating Python virtualenv..."
cd "$INSTALL_DIR"
# Create venv as APP_USER (must own it to install packages)
sudo -u "$APP_USER" python3 -m venv "${INSTALL_DIR}/venv"
# Upgrade pip inside the venv — this is safe and NOT affected by PEP 668
sudo -u "$APP_USER" "${INSTALL_DIR}/venv/bin/pip" install --quiet --upgrade pip
sudo -u "$APP_USER" "${INSTALL_DIR}/venv/bin/pip" install --quiet gunicorn
echo 35

echo 40; info "Installing Python requirements..."
if [[ ! -f "${INSTALL_DIR}/requirements.txt" ]]; then
    warn "requirements.txt not found in ${INSTALL_DIR} — skipping pip install"
else
    sudo -u "$APP_USER" "${INSTALL_DIR}/venv/bin/pip" install --quiet \
        -r "${INSTALL_DIR}/requirements.txt" || \
        die "Failed to install Python requirements. Check ${LOG} for details."
fi
echo 55

echo 60; info "Writing .env file..."
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
UPLOAD_DIR="$INSTALL_DIR/uploads"
cat > "$INSTALL_DIR/.env" << ENVEOF
# RELAY Environment — generated by relay-install.sh on $(date)
# ─────────────────────────────────────────────────────────────
# DO NOT edit manually — use Admin → Platform Settings in the GUI
# to change platform flags and API credentials. Changes made in
# the GUI are written back here automatically.
# ─────────────────────────────────────────────────────────────

SECRET_KEY=${SECRET_KEY}
DATABASE_URL=sqlite:///${INSTALL_DIR}/instance/relay.db
FLASK_ENV=production

# Upload storage
RELAY_UPLOAD_DIR=${UPLOAD_DIR}

# Organisation branding
CLIENT_NAME=${CLIENT_NAME}

# ── Platform flags ────────────────────────────────────────────
# Managed via Admin GUI — do not edit manually
HAS_TEAMS=${HAS_TEAMS}
HAS_WEBEX=${HAS_WEBEX}
HAS_CUCM=${HAS_CUCM}
HAS_CERT_MONITOR=${HAS_CERT_MONITOR}
HAS_DID=${HAS_DID}
HAS_LDAP=${HAS_LDAP}
HAS_AUDIT=${HAS_AUDIT}

# ── API credentials (GUI-managed) ────────────────────────────
# Teams / MS Graph — set via Admin → Admin Panel → Teams Config
TEAMS_TENANT_ID=
TEAMS_CLIENT_ID=
TEAMS_CLIENT_SECRET=
TEAMS_SVC_UPN=
TEAMS_SVC_PASS=

# Webex Calling — set via Admin → Admin Panel → Webex Config
WEBEX_CLIENT_ID=
WEBEX_CLIENT_SECRET=
WEBEX_REFRESH_TOKEN=
WEBEX_ORG_ID=

# Cisco CUCM — set via Admin → Admin Panel → CUCM Config
CUCM_HOST=
CUCM_USERNAME=
CUCM_PASSWORD=
CUCM_VERSION=12.5

# SMTP (cert alerts) — set via Admin → Admin Panel → SMTP Config
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
SMTP_FROM=
SMTP_ALERT_TO=
SMTP_TLS=true
SMTP_ENABLED=false

# LDAP — set via Admin → LDAP Sync

ENVEOF
chown "$APP_USER":"$APP_USER" "$INSTALL_DIR/.env"
chmod 600 "$INSTALL_DIR/.env"
echo 65

echo 70; info "Running database initialisation..."
sudo -u "$APP_USER" bash -c "
  set -e
  source '${INSTALL_DIR}/venv/bin/activate'
  export FLASK_APP=run.py
  export SECRET_KEY='${SECRET_KEY}'
  export DATABASE_URL='sqlite:///${INSTALL_DIR}/instance/relay.db'
  export RELAY_UPLOAD_DIR='${UPLOAD_DIR}'
  cd '${INSTALL_DIR}'

  if [ -f migrations/env.py ]; then
    flask db upgrade
  else
    echo 'ERROR: migrations/env.py not found; cannot initialise database.' >&2
    exit 1
  fi
"
echo 75

echo 78; info "Seeding admin account and platform settings..."
SEED_SCRIPT=$(mktemp /tmp/relay_seed_XXXXXX.py)
cat > "$SEED_SCRIPT" << PYEOF
import os, sys
sys.path.insert(0, '${INSTALL_DIR}')
os.chdir('${INSTALL_DIR}')
os.environ['SECRET_KEY']       = '${SECRET_KEY}'
os.environ['DATABASE_URL']     = 'sqlite:///${INSTALL_DIR}/instance/relay.db'
os.environ['RELAY_UPLOAD_DIR'] = '${UPLOAD_DIR}'

# Import Flask app but patch create_app to skip the APScheduler start.
# We only need DB access for seeding — starting the scheduler in a
# one-shot seed script would spawn background threads and never exit cleanly.
import app as _app_module
_orig_start = None
try:
    from app.utils import scheduler as _sched_mod
    _orig_start = _sched_mod.start_scheduler
    _sched_mod.start_scheduler = lambda app: None   # no-op during seed
except Exception:
    pass

from app import create_app, db
from app.models import User, PlatformSettings

flask_app = create_app('production')
with flask_app.app_context():
    if not User.query.filter_by(username='$(pyesc "${ADMIN_USER}")').first():
        u = User(username='$(pyesc "${ADMIN_USER}")', email='$(pyesc "${ADMIN_EMAIL}")', role='admin')
        u.set_password('$(pyesc "${ADMIN_PASS}")')
        db.session.add(u)
    ps = PlatformSettings.get()
    ps.has_teams        = ${HAS_TEAMS}
    ps.has_webex        = ${HAS_WEBEX}
    ps.has_cucm         = ${HAS_CUCM}
    ps.has_cert_monitor = ${HAS_CERT_MONITOR}
    ps.has_did          = ${HAS_DID}
    ps.has_ldap         = ${HAS_LDAP}
    ps.has_audit        = ${HAS_AUDIT}
    ps.client_name      = '$(pyesc "${CLIENT_NAME}")'
    db.session.commit()
    print("Seed complete — admin user and platform settings saved.")
PYEOF
sed -i 's/= true$/= True/g; s/= false$/= False/g' "$SEED_SCRIPT"
chown "$APP_USER":"$APP_USER" "$SEED_SCRIPT"
sudo -u "$APP_USER" bash -c "
  source '${INSTALL_DIR}/venv/bin/activate'
  export SECRET_KEY='${SECRET_KEY}'
  export DATABASE_URL='sqlite:///${INSTALL_DIR}/instance/relay.db'
  export RELAY_UPLOAD_DIR='${UPLOAD_DIR}'
  python3 '${SEED_SCRIPT}'
"
rm -f "$SEED_SCRIPT"
echo 82

echo 85; info "Configuring Nginx..."
cat > /etc/nginx/sites-available/relay << NGINX
server {
    listen 80;
    server_name ${DOMAIN};
    access_log /var/log/nginx/relay_access.log;
    error_log  /var/log/nginx/relay_error.log;

    # Limit upload size (CSV files, cert chains)
    client_max_body_size 20M;

    location / {
        proxy_pass         http://127.0.0.1:${APP_PORT};
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout 120s;
    }
}
NGINX
ln -sf /etc/nginx/sites-available/relay /etc/nginx/sites-enabled/relay
rm -f /etc/nginx/sites-enabled/default
nginx -t &>/dev/null && systemctl reload nginx
echo 88

# SSL setup
if [[ "${SSL_CHOICE}" == "letsencrypt" ]]; then
    info "Requesting Let's Encrypt certificate..."
    certbot --nginx -d "${DOMAIN}" --non-interactive --agree-tos \
        -m "${ADMIN_EMAIL}" --redirect &>/dev/null || warn "certbot failed — configure SSL manually."
elif [[ "${SSL_CHOICE}" == "selfsigned" ]]; then
    info "Generating self-signed certificate..."
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/ssl/private/relay.key \
        -out    /etc/ssl/certs/relay.crt \
        -subj "/CN=${DOMAIN}" &>/dev/null
    sed -i "s|listen 80;|listen 443 ssl;\n    ssl_certificate     /etc/ssl/certs/relay.crt;\n    ssl_certificate_key /etc/ssl/private/relay.key;|" \
        /etc/nginx/sites-available/relay
    nginx -t &>/dev/null && systemctl reload nginx
fi
echo 92

echo 93; info "Creating systemd service..."
cat > /etc/systemd/system/relay.service << SERVICE
[Unit]
Description=RELAY — Multi-Platform Call Forwarding Manager v${RELAY_VERSION}
After=network.target

[Service]
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
Environment="FLASK_APP=run.py"
ExecStart=${INSTALL_DIR}/venv/bin/gunicorn \
    run:app \
    --workers 3 \
    --bind 127.0.0.1:${APP_PORT} \
    --timeout 120 \
    --access-logfile /var/log/relay-access.log \
    --error-logfile  /var/log/relay-error.log
Restart=always
RestartSec=5
KillSignal=SIGINT

[Install]
WantedBy=multi-user.target
SERVICE
systemctl daemon-reload
systemctl enable relay
systemctl restart relay
echo 98

# Log files
touch /var/log/relay-access.log /var/log/relay-error.log
chown "$APP_USER":"$APP_USER" /var/log/relay-access.log /var/log/relay-error.log

# ── CLI management tool ───────────────────────────────────────────────────────
# Write the 'relay' CLI script to /usr/local/bin/relay
# Available to the CLI management user (and any sudo-authorised user).
cat > /usr/local/bin/relay << CLISCRIPT
#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  RELAY CLI Management Tool
#  Usage: relay <command> [options]
#
#  Commands:
#    status          Show service status + uptime
#    start           Start the RELAY service
#    stop            Stop the RELAY service
#    restart         Restart the RELAY service
#    reload          Graceful reload (gunicorn SIGHUP)
#    logs [n]        Tail live logs (default 50 lines)
#    errors [n]      Show last n error log lines
#    access [n]      Show last n access log lines
#    db-upgrade      Run flask db upgrade (apply pending migrations)
#    db-check        Show current Alembic revision
#    check           Health check — HTTP ping to the app
#    version         Show RELAY version from .env / source
#    users           List all RELAY GUI user accounts (username, role, platform)
#    platforms       Show enabled platforms from PlatformSettings
#    nginx-test      Test Nginx configuration
#    nginx-reload    Reload Nginx
#    disk            Show disk usage for install directory
#    processes       Show Gunicorn worker processes
#    grep <pattern>  Search application logs for a pattern
#    py <file.py>    Run a Python script inside the RELAY virtualenv
#    root            Manage root account lock (enable/disable/status)
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR}"
APP_USER="${APP_USER}"
VENV="\${INSTALL_DIR}/venv/bin"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
CYN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()  { echo -e "\${GRN}[OK]\${NC}    \$*"; }
err() { echo -e "\${RED}[ERR]\${NC}   \$*"; }
inf() { echo -e "\${CYN}[INFO]\${NC}  \$*"; }
hdr() { echo -e "\${BOLD}\$*\${NC}"; }

cmd="\${1:-help}"
shift 2>/dev/null || true

_svc()   { sudo /usr/bin/systemctl "\$@" relay; }
_venv()  { sudo -u "\$APP_USER" bash -c "cd \${INSTALL_DIR} && source \${VENV}/activate && \$*"; }
_flask() { sudo -u "\$APP_USER" bash -c "cd \${INSTALL_DIR} && source \${VENV}/activate && FLASK_APP=run.py \$*"; }

case "\$cmd" in

  status)
    hdr "=== RELAY Service Status ==="
    _svc status --no-pager
    echo ""
    inf "Gunicorn workers: \$(pgrep -c -f 'gunicorn.*run:app' 2>/dev/null || echo 0)"
    ;;

  start)
    inf "Starting RELAY..."; _svc start; ok "Started."
    ;;

  stop)
    inf "Stopping RELAY..."; _svc stop; ok "Stopped."
    ;;

  restart)
    inf "Restarting RELAY..."; _svc restart; ok "Restarted."
    ;;

  reload)
    inf "Reloading Gunicorn workers (graceful)..."
    sudo pkill -HUP -f "gunicorn.*run:app" 2>/dev/null && ok "Reload signal sent." || err "No Gunicorn process found — try: relay restart"
    ;;

  logs)
    n="\${1:-50}"
    hdr "=== RELAY Live Logs (last \${n} lines, Ctrl+C to exit) ==="
    sudo journalctl -u relay -n "\$n" -f
    ;;

  errors)
    n="\${1:-50}"
    hdr "=== RELAY Error Log (last \${n} lines) ==="
    sudo tail -n "\$n" /var/log/relay-error.log
    ;;

  access)
    n="\${1:-50}"
    hdr "=== RELAY Access Log (last \${n} lines) ==="
    sudo tail -n "\$n" /var/log/relay-access.log
    ;;

  db-upgrade)
    hdr "=== Running flask db upgrade ==="
    _flask "flask db upgrade"
    ok "Database migration complete."
    ;;

  db-check)
    hdr "=== Current database revision ==="
    _flask "flask db current 2>/dev/null || echo 'No alembic_version table yet — run: relay db-upgrade'"
    ;;

  check)
    hdr "=== RELAY Health Check ==="
    PORT=\$(grep -o 'bind 127.0.0.1:[0-9]*' /etc/systemd/system/relay.service 2>/dev/null | grep -o '[0-9]*$' || echo "${APP_PORT}")
    STATUS="000"
    for i in 1 2 3 4 5; do
      STATUS=\$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:\${PORT}/auth/login" 2>/dev/null || echo "000")
      [[ "\$STATUS" != "000" ]] && break
      inf "Waiting for Gunicorn workers to bind (attempt \${i}/5)..."
      sleep 2
    done
    if [[ "\$STATUS" == "200" ]]; then
      ok "App responding — HTTP \${STATUS}"
    else
      err "Unexpected response — HTTP \${STATUS} (app may still be starting — run 'relay check' again)"
    fi
    _svc status --no-pager -l | head -5
    ;;

  version)
    hdr "=== RELAY Version ==="
    grep "RELAY_VERSION" "\${INSTALL_DIR}/relay-install.sh" 2>/dev/null | head -1 || echo "Version not found in installer."
    inf "Install dir: \${INSTALL_DIR}"
    inf "Python: \$(\${VENV}/python3 --version 2>&1)"
    ;;

  users)
    hdr "=== RELAY GUI Users ==="
    _venv "python3 -c \"
from run import app
from app.models import User
with app.app_context():
    users = User.query.order_by(User.username).all()
    print(f'{\\"-\\"*72}')
    print(f'{\\\"Username\\\":<20} {\\\"Role\\\":<12} {\\\"Platform\\\":<10} {\\\"Active\\\":<8} Email')
    print(f'{\\"-\\"*72}')
    for u in users:
        active = '✓' if u.is_active else '✗'
        print(f'{u.username:<20} {u.role:<12} {u.user_platform or \\\"-\\\":<10} {active:<8} {u.email}')
    print(f'{\\"-\\"*72}')
    print(f'Total: {len(users)} user(s)')
\""
    ;;

  platforms)
    hdr "=== RELAY Platform Settings ==="
    _venv "python3 -c \"
from run import app
from app.models import PlatformSettings, CUCMCluster
with app.app_context():
    ps = PlatformSettings.get()
    flags = [
        ('Teams',         ps.has_teams),
        ('Webex Calling', ps.has_webex),
        ('Cisco CUCM',    ps.has_cucm),
        ('Cert Monitor',  ps.has_cert_monitor),
        ('DID Mgmt',      ps.has_did),
        ('LDAP Sync',     ps.has_ldap),
    ]
    for name, val in flags:
        icon = '✓' if val else '✗'
        print(f'  {icon}  {name}')
    clusters = CUCMCluster.query.all()
    if clusters:
        print(f'\\n  CUCM Clusters ({len(clusters)}):')
        for c in clusters:
            state = 'enabled' if c.is_enabled else 'disabled'
            print(f'    • {c.label} — {c.cucm_host} v{c.cucm_version} [{state}]')
\""
    ;;

  nginx-test)
    hdr "=== Nginx Configuration Test ==="
    sudo /usr/sbin/nginx -t
    ;;

  nginx-reload)
    hdr "=== Reloading Nginx ==="
    sudo /usr/sbin/nginx -t && sudo /usr/bin/systemctl reload nginx && ok "Nginx reloaded."
    ;;

  disk)
    hdr "=== Disk Usage ==="
    inf "Install directory:"
    sudo du -sh "\${INSTALL_DIR}" 2>/dev/null
    inf "Upload storage:"
    sudo du -sh "\${INSTALL_DIR}/uploads/"* 2>/dev/null || true
    inf "Database:"
    sudo du -sh "\${INSTALL_DIR}/instance/relay.db" 2>/dev/null || true
    inf "System disk:"
    df -h / | tail -1
    ;;

  processes)
    hdr "=== RELAY / Gunicorn Processes ==="
    ps aux | grep -E "gunicorn|relay" | grep -v grep || inf "No relay processes found."
    ;;

  grep)
    if [[ -z "\${1:-}" ]]; then err "Usage: relay grep <pattern>"; exit 1; fi
    hdr "=== Searching logs for: \$* ==="
    sudo journalctl -u relay --no-pager | grep --color=auto "\$@" | tail -100
    ;;

  py)
    if [[ -z "\${1:-}" ]]; then err "Usage: relay py <script.py>"; exit 1; fi
    inf "Running \$1 inside RELAY virtualenv..."
    _venv "python3 \$*"
    ;;

  root)
    subcmd="\${1:-status}"
    case "\$subcmd" in
      enable)
        hdr "=== Enabling root account ==="
        sudo /usr/bin/passwd -u root
        ok "Root account unlocked. Use 'su -' or 'sudo -i' with the password set during OS installation."
        warn "Remember to run 'relay root disable' when you are done."
        ;;
      disable)
        hdr "=== Disabling root account ==="
        sudo /usr/bin/passwd -l root
        ok "Root account locked. Direct root login is no longer possible."
        ;;
      status)
        hdr "=== Root account status ==="
        STATUS=\$(sudo /usr/bin/passwd -S root 2>/dev/null | awk '{print \$2}')
        case "\$STATUS" in
          L|LK)
            echo -e "  \${GRN}●\${NC}  Root account is LOCKED (disabled)"
            inf "Root login is not possible. Run 'relay root enable' to unlock temporarily."
            ;;
          P)
            echo -e "  \${YLW}●\${NC}  Root account is UNLOCKED (active)"
            warn "Root login is currently possible. Run 'relay root disable' when finished."
            ;;
          *)
            inf "Root account status: \${STATUS:-unknown}"
            ;;
        esac
        echo ""
        inf "Last root login:"
        sudo last root | head -3 || true
        ;;
      *)
        err "Usage: relay root <enable|disable|status>"
        ;;
    esac
    ;;

  help|--help|-h|"")
    hdr "RELAY CLI Management Tool v${RELAY_VERSION}"
    echo ""
    echo "  Usage: relay <command> [options]"
    echo ""
    echo "  Service control:"
    echo "    relay status          Service status + worker count"
    echo "    relay start           Start the service"
    echo "    relay stop            Stop the service"
    echo "    relay restart         Restart the service"
    echo "    relay reload          Graceful Gunicorn reload"
    echo ""
    echo "  Logs:"
    echo "    relay logs [n]        Live logs (default 50 lines)"
    echo "    relay errors [n]      Error log tail"
    echo "    relay access [n]      Access log tail"
    echo "    relay grep <pattern>  Search logs for pattern"
    echo ""
    echo "  Database:"
    echo "    relay db-upgrade      Apply pending migrations"
    echo "    relay db-check        Show current revision"
    echo ""
    echo "  Application:"
    echo "    relay check           HTTP health check"
    echo "    relay version         Show version info"
    echo "    relay users           List GUI user accounts"
    echo "    relay platforms       Show enabled platforms + CUCM clusters"
    echo "    relay py <script.py>  Run Python inside RELAY venv"
    echo ""
    echo "  System:"
    echo "    relay nginx-test      Test Nginx config"
    echo "    relay nginx-reload    Reload Nginx"
    echo "    relay disk            Disk usage summary"
    echo "    relay processes       Show running processes"
    echo ""
    echo "  Root access:"
    echo "    relay root status     Show whether root is locked or unlocked"
    echo "    relay root enable     Unlock root account (password set at OS install)"
    echo "    relay root disable    Lock root account (recommended after use)"
    ;;

  *)
    err "Unknown command: \$cmd"
    echo "Run 'relay help' for available commands."
    exit 1
    ;;
esac
CLISCRIPT

chmod 755 /usr/local/bin/relay
info "relay CLI tool installed at /usr/local/bin/relay"

# ── Create CLI management user ────────────────────────────────────────────────
if [[ "${CLI_USER_CREATED}" == true ]]; then
  info "Creating CLI management user: ${CLI_USER}..."

  id "${CLI_USER}" &>/dev/null || useradd -m -s /bin/bash "${CLI_USER}"
  echo "${CLI_USER}:${CLI_PASS}" | chpasswd

  cat > "/etc/sudoers.d/relay-cli-${CLI_USER}" << SUDOERS
# RELAY CLI management user — scoped sudo permissions
# Generated by relay-install.sh on $(date)
# DO NOT edit manually — managed by RELAY installer

# Service control
${CLI_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl start relay
${CLI_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl stop relay
${CLI_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl restart relay
${CLI_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl status relay
${CLI_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl reload nginx
${CLI_USER} ALL=(root) NOPASSWD: /usr/sbin/nginx -t
${CLI_USER} ALL=(root) NOPASSWD: /usr/sbin/nginx

# Process signals
${CLI_USER} ALL=(root) NOPASSWD: /usr/bin/pkill -HUP -f gunicorn*

# Log access
${CLI_USER} ALL=(root) NOPASSWD: /usr/bin/journalctl
${CLI_USER} ALL=(root) NOPASSWD: /usr/bin/tail -n * /var/log/relay-access.log
${CLI_USER} ALL=(root) NOPASSWD: /usr/bin/tail -n * /var/log/relay-error.log

# Run as relay system user (for flask db, python3, venv commands)
${CLI_USER} ALL=(${APP_USER}) NOPASSWD: /bin/bash

# Disk and process inspection
${CLI_USER} ALL=(root) NOPASSWD: /usr/bin/du -sh *
${CLI_USER} ALL=(root) NOPASSWD: /bin/ps aux

# Root account lock/unlock — password remains with the OS installer
${CLI_USER} ALL=(root) NOPASSWD: /usr/bin/passwd -u root
${CLI_USER} ALL=(root) NOPASSWD: /usr/bin/passwd -l root
${CLI_USER} ALL=(root) NOPASSWD: /usr/bin/passwd -S root
${CLI_USER} ALL=(root) NOPASSWD: /usr/bin/last root
SUDOERS

  chmod 440 "/etc/sudoers.d/relay-cli-${CLI_USER}"
  visudo -c -f "/etc/sudoers.d/relay-cli-${CLI_USER}" &>/dev/null \
    && info "Sudoers entry validated for ${CLI_USER}." \
    || warn "Sudoers validation warning — check /etc/sudoers.d/relay-cli-${CLI_USER}"

  info "CLI user '${CLI_USER}' created. SSH in and run: relay help"
fi

echo 100

) | whiptail --title "Phase 1 — Installing RELAY v${RELAY_VERSION}" \
    --gauge "Starting installation..." $DH $DW 0

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — SECURITY HARDENING
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$RUN_SECURE" == true ]]; then
(
set +e  # Prevent silent exit-on-error inside gauge subshell

echo 5; info "Locking down file permissions..."
chmod 600 "$INSTALL_DIR/.env"
chmod 600 "$INSTALL_DIR/instance/relay.db" 2>/dev/null || true
find "$INSTALL_DIR" -type d -exec chmod 750 {} \;
find "$INSTALL_DIR" -type f -exec chmod 640 {} \;
find "$INSTALL_DIR/venv/bin" -type f -exec chmod 750 {} \;
chmod 700 "$INSTALL_DIR/uploads"
chown -R "$APP_USER":"$APP_USER" "$INSTALL_DIR"
echo 20

echo 25; info "Configuring UFW firewall..."
ufw --force reset &>/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh    comment 'SSH management'
ufw allow 80/tcp comment 'RELAY HTTP'
ufw allow 443/tcp comment 'RELAY HTTPS'
ufw --force enable
echo 40

echo 45; info "Configuring Fail2ban..."
cat > /etc/fail2ban/jail.d/relay.conf << 'F2B'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
backend  = systemd

[sshd]
enabled = true

[nginx-http-auth]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/relay_error.log

[nginx-limit-req]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/relay_error.log
maxretry = 10
F2B
systemctl enable fail2ban &>/dev/null && systemctl restart fail2ban
echo 55

echo 60; info "Applying Nginx security headers..."
cat > /etc/nginx/snippets/relay-security-headers.conf << 'HDRS'
add_header X-Frame-Options           "SAMEORIGIN"     always;
add_header X-Content-Type-Options    "nosniff"        always;
add_header X-XSS-Protection          "1; mode=block"  always;
add_header Referrer-Policy           "strict-origin-when-cross-origin" always;
add_header Permissions-Policy        "geolocation=(), microphone=(), camera=()" always;
add_header Content-Security-Policy   "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net fonts.googleapis.com; font-src 'self' fonts.gstatic.com cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';" always;
HDRS
NGINX_SITE="/etc/nginx/sites-available/relay"
grep -q "relay-security-headers" "$NGINX_SITE" || \
    sed -i '/location \/ {/i \    include snippets/relay-security-headers.conf;\n' "$NGINX_SITE"
grep -q "server_tokens off" /etc/nginx/nginx.conf || \
    sed -i '/http {/a \\t server_tokens off;' /etc/nginx/nginx.conf
nginx -t &>/dev/null && systemctl reload nginx
echo 70

echo 75; info "Hardening systemd service..."
SERVICE_FILE="/etc/systemd/system/relay.service"
if [[ -f "$SERVICE_FILE" ]] && ! grep -q "NoNewPrivileges" "$SERVICE_FILE"; then
    sed -i '/\[Service\]/a \
NoNewPrivileges=true\
PrivateTmp=true\
ProtectSystem=strict\
ProtectHome=true\
ReadWritePaths='"$INSTALL_DIR"' /var/log\
CapabilityBoundingSet=\
LockPersonality=true\
RestrictRealtime=true\
RestrictSUIDSGID=true' "$SERVICE_FILE"
    systemctl daemon-reload && systemctl restart relay
fi
echo 82

echo 85; info "Configuring log rotation..."
cat > /etc/logrotate.d/relay << LOGR
# RELAY application logs
/var/log/relay-access.log /var/log/relay-error.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 ${APP_USER} adm
    sharedscripts
    postrotate
        systemctl reload relay 2>/dev/null || true
    endscript
}

# Nginx logs for RELAY
/var/log/nginx/relay_access.log /var/log/nginx/relay_error.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 640 www-data adm
    sharedscripts
    postrotate
        [ -s /run/nginx.pid ] && kill -USR1 \$(cat /run/nginx.pid) || true
    endscript
}

# RELAY installer / debug logs
/tmp/relay-install-*.log {
    rotate 3
    compress
    missingok
    notifempty
}
LOGR
echo 90

echo 92; info "Setting up certbot auto-renewal..."
if systemctl list-units --type=timer 2>/dev/null | grep -q certbot; then
    systemctl enable certbot.timer &>/dev/null && systemctl start certbot.timer &>/dev/null
else
    crontab -l 2>/dev/null | grep -q certbot || \
    (crontab -l 2>/dev/null; \
     echo "0 3 * * * certbot renew --quiet --deploy-hook 'systemctl reload nginx'") \
     | crontab -
fi
echo 95

if [[ "${SSH_HARDEN}" == true ]]; then
    echo 96; info "Hardening SSH..."
    SSHD_CFG="/etc/ssh/sshd_config"
    cp "$SSHD_CFG" "${SSHD_CFG}.bak.$(date +%Y%m%d)"
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/'              "$SSHD_CFG"
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CFG"
    sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/'                      "$SSHD_CFG"
    grep -q "^MaxAuthTries"           "$SSHD_CFG" || echo "MaxAuthTries 3"           >> "$SSHD_CFG"
    grep -q "^PermitRootLogin"        "$SSHD_CFG" || echo "PermitRootLogin no"       >> "$SSHD_CFG"
    grep -q "^PasswordAuthentication" "$SSHD_CFG" || echo "PasswordAuthentication no" >> "$SSHD_CFG"
    sshd -t && systemctl reload sshd
fi
echo 100

) | whiptail --title "Phase 2 — Security Hardening" \
    --gauge "Applying security hardening..." $DH $DW 0
fi

# ══════════════════════════════════════════════════════════════════════════════
# POST-INSTALL HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════════════
info "Running post-install health check..."
HEALTH_FAIL=""

# Give gunicorn a moment to fully start
sleep 3

# Check systemd service is active
if ! systemctl is-active --quiet relay; then
    HEALTH_FAIL+="  ✘ relay.service is NOT running\n"
    warn "relay.service failed to start — check: journalctl -u relay -n 30"
else
    success "relay.service is running"
fi

# Check gunicorn is reachable directly
if curl -sf http://127.0.0.1:"${APP_PORT}" -o /dev/null 2>/dev/null; then
    success "Gunicorn responded on port ${APP_PORT}"
else
    HEALTH_FAIL+="  ✘ Gunicorn not responding on port ${APP_PORT}\n"
    warn "Gunicorn not responding — check: journalctl -u relay -n 30"
fi

# Check nginx is active
if ! systemctl is-active --quiet nginx; then
    HEALTH_FAIL+="  ✘ nginx is NOT running\n"
    warn "nginx failed — check: nginx -t"
else
    success "nginx is running"
fi

if [[ -n "$HEALTH_FAIL" ]]; then
    wt --title "⚠  Health Check — Issues Found" \
      --msgbox "\nSome checks failed after installation:\n\n${HEALTH_FAIL}\nSee the install log for details:\n  ${LOG}" \
      $DH $DW
fi

# ══════════════════════════════════════════════════════════════════════════════
# FINAL SCREEN
# ══════════════════════════════════════════════════════════════════════════════
PROTO="http"
[[ "$SSL_CHOICE" != "none" ]] && PROTO="https"

HARDEN_STATUS="Skipped"
[[ "$RUN_SECURE" == true && "$SSH_HARDEN" == false ]] && HARDEN_STATUS="Applied"
[[ "$SSH_HARDEN" == true ]]                           && HARDEN_STATUS="Applied + SSH hardened"

CLI_COMPLETE_MSG=""
if [[ "$CLI_USER_CREATED" == true ]]; then
  CLI_COMPLETE_MSG="  ┌─ CLI Management User ──────────────────────────┐\n\
  │  User     : ${CLI_USER}\n\
  │  SSH in and run: relay help\n\
  └────────────────────────────────────────────────┘\n\n"
fi

wt --title "🎉  RELAY v${RELAY_VERSION} — Installation Complete" \
  --msgbox "\n\
  RELAY is installed and running!\n\n\
  ┌─ Access ───────────────────────────────────────┐\n\
  │  URL        : ${PROTO}://${DOMAIN}\n\
  │  Username   : ${ADMIN_USER}\n\
  │  Password   : (as entered)\n\
  └────────────────────────────────────────────────┘\n\n\
$(echo -e "$CLI_COMPLETE_MSG")\
  ┌─ CLI Tool (any authorised user) ───────────────┐\n\
  │  relay status       relay restart\n\
  │  relay logs         relay errors\n\
  │  relay users        relay platforms\n\
  │  relay db-upgrade   relay check\n\
  │  relay help         (full command list)\n\
  └────────────────────────────────────────────────┘\n\n\
  ┌─ Next Steps ───────────────────────────────────┐\n\
  │  1. Open the URL above and sign in\n\
  │  2. Admin → Admin Panel → configure:\n\
  │       • Teams API credentials\n\
  │       • Webex Calling credentials\n\
  │       • Cisco CUCM clusters\n\
  │       • SMTP for certificate alerts\n\
  │  3. Admin → LDAP Sync → add LDAP servers\n\
  │  4. Admin → Cert Monitor → add domains\n\
  └────────────────────────────────────────────────┘\n\n\
  Security hardening : ${HARDEN_STATUS}\n\
  Install log        : ${LOG}" \
  $DH $DW

echo ""
echo -e "${GREEN}${BOLD}RELAY v${RELAY_VERSION} setup complete.${NC}"
echo -e "  URL:  ${PROTO}://${DOMAIN}"
echo -e "  Log:  ${LOG}"

# ── Lock root account ─────────────────────────────────────────────────────────
# Root is locked as the final step of every installation.
# The password set during Ubuntu OS installation is retained — it is NOT deleted.
# Use:  relay root enable   → temporarily unlock when needed
#       relay root disable  → lock again when done
passwd -l root &>/dev/null && \
  echo -e "${CYAN}[INFO]${NC}    Root account locked. Use: relay root enable / relay root disable"
