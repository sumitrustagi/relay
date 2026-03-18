from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager


# ═══════════════════════════════════════════════════════════════
#  PLATFORM SETTINGS
# ═══════════════════════════════════════════════════════════════
class PlatformSettings(db.Model):
    __tablename__ = "platform_settings"
    id               = db.Column(db.Integer, primary_key=True)
    client_name      = db.Column(db.String(120), default="")
    has_teams        = db.Column(db.Boolean, default=True)
    has_webex        = db.Column(db.Boolean, default=False)
    has_cucm         = db.Column(db.Boolean, default=False)
    has_cert_monitor = db.Column(db.Boolean, default=False)
    has_did          = db.Column(db.Boolean, default=True)
    has_ldap         = db.Column(db.Boolean, default=False)
    has_audit        = db.Column(db.Boolean, default=False)

    @classmethod
    def get(cls):
        ps = cls.query.first()
        if not ps:
            import os
            ps = cls(
                has_teams        = os.getenv("HAS_TEAMS",        "true").lower()  == "true",
                has_webex        = os.getenv("HAS_WEBEX",        "false").lower() == "true",
                has_cucm         = os.getenv("HAS_CUCM",         "false").lower() == "true",
                has_cert_monitor = os.getenv("HAS_CERT_MONITOR", "false").lower() == "true",
                has_did          = os.getenv("HAS_DID",          "true").lower()  == "true",
                has_ldap         = os.getenv("HAS_LDAP",         "false").lower() == "true",
                has_audit        = os.getenv("HAS_AUDIT",        "false").lower() == "true",
                client_name      = os.getenv("CLIENT_NAME", ""),
            )
            db.session.add(ps)
            db.session.commit()
        return ps


# ═══════════════════════════════════════════════════════════════
#  USER
# ═══════════════════════════════════════════════════════════════
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id               = db.Column(db.Integer, primary_key=True)
    username         = db.Column(db.String(80),  unique=True, nullable=False)
    email            = db.Column(db.String(120), unique=True, nullable=False)
    password         = db.Column(db.String(255), nullable=False)
    role             = db.Column(db.String(20),  nullable=False, default="user")
    is_active        = db.Column(db.Boolean, default=True)
    display_name     = db.Column(db.String(120))
    teams_upn        = db.Column(db.String(255))
    teams_extension  = db.Column(db.String(50))
    webex_extension  = db.Column(db.String(50))
    cucm_extension   = db.Column(db.String(50))
    user_platform    = db.Column(db.String(20))   # teams | webex | cucm
    relay_role       = db.Column(db.String(20), default="standard")
    # relay_role: standard | supervisor | manager | readonly
    ldap_dn          = db.Column(db.String(500))
    ldap_server_id   = db.Column(db.Integer, db.ForeignKey("ldap_servers.id"), nullable=True)
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, raw):   self.password = generate_password_hash(raw)
    def check_password(self, raw): return check_password_hash(self.password, raw)
    def is_admin(self):            return self.role == "admin"
    def is_superuser(self):        return self.role == "superuser"
    # can_manage_others: superuser can schedule/forward/CSV for ANY user, but has NO admin panel access
    def can_manage_others(self):   return self.role in ("admin", "superuser")
    # Legacy alias kept for templates that still use it
    def can_lookup_any(self):      return self.role in ("admin", "superuser")


@login_manager.user_loader
def load_user(uid):
    return User.query.get(int(uid))


# ═══════════════════════════════════════════════════════════════
#  MS GRAPH CONFIG
# ═══════════════════════════════════════════════════════════════
class MSGraphConfig(db.Model):
    __tablename__ = "ms_graph_config"
    id                       = db.Column(db.Integer, primary_key=True)
    tenant_id                = db.Column(db.String(255))
    client_id                = db.Column(db.String(255))
    client_secret            = db.Column(db.String(255))
    service_account_upn      = db.Column(db.String(255))
    service_account_password = db.Column(db.String(255))
    graph_access_token       = db.Column(db.Text)
    graph_token_expiry       = db.Column(db.DateTime)
    teams_access_token       = db.Column(db.Text)
    teams_token_expiry       = db.Column(db.DateTime)
    updated_at               = db.Column(db.DateTime, default=datetime.utcnow,
                                          onupdate=datetime.utcnow)

    def is_configured(self):
        return bool(self.tenant_id and self.client_id and self.client_secret)


# ═══════════════════════════════════════════════════════════════
#  WEBEX CONFIG
# ═══════════════════════════════════════════════════════════════
class WebexConfig(db.Model):
    __tablename__ = "webex_config"
    id             = db.Column(db.Integer, primary_key=True)
    client_id      = db.Column(db.String(255))
    client_secret  = db.Column(db.String(255))
    refresh_token  = db.Column(db.Text)
    access_token   = db.Column(db.Text)
    token_expiry   = db.Column(db.DateTime)
    org_id         = db.Column(db.String(255))

    @classmethod
    def get(cls):
        w = cls.query.first()
        if not w:
            w = cls()
            db.session.add(w)
            db.session.commit()
        return w

    def is_configured(self):
        return bool(self.client_id and self.client_secret and self.refresh_token)


# ═══════════════════════════════════════════════════════════════
#  CUCM CONFIG
# ═══════════════════════════════════════════════════════════════
class CUCMCluster(db.Model):
    """
    One row per CUCM cluster. Replaces the old singleton CUCMConfig.
    Multiple clusters are supported — each has its own AXL credentials,
    publisher host, schema version, and enabled flag.
    """
    __tablename__ = "cucm_clusters"
    id            = db.Column(db.Integer, primary_key=True)
    label         = db.Column(db.String(120), nullable=False)  # e.g. "UK HQ", "US West"
    cucm_host     = db.Column(db.String(255))   # Publisher IP or FQDN
    cucm_username = db.Column(db.String(255))
    cucm_password = db.Column(db.String(255))
    cucm_version  = db.Column(db.String(10), default="12.5")
    verify_ssl    = db.Column(db.Boolean, default=False)
    is_enabled    = db.Column(db.Boolean, default=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at    = db.Column(db.DateTime, default=datetime.utcnow,
                               onupdate=datetime.utcnow)
    created_by    = db.Column(db.String(80))

    def is_configured(self):
        return bool(self.cucm_host and self.cucm_username and self.cucm_password)

    @property
    def password(self):
        return self.cucm_password or ""

    @password.setter
    def password(self, v):
        if v:
            self.cucm_password = v


# Keep CUCMConfig as a backwards-compatible alias so existing code
# that calls CUCMConfig.get() still works (returns first enabled cluster).
class CUCMConfig:
    """Legacy shim — returns the first enabled CUCMCluster as a singleton."""
    @classmethod
    def get(cls):
        c = CUCMCluster.query.filter_by(is_enabled=True).first()
        if not c:
            # Return a blank cluster object (not persisted) so callers don't crash
            c = CUCMCluster(label="Default", cucm_version="12.5")
        return c


# ═══════════════════════════════════════════════════════════════
#  SMTP CONFIG  (for cert expiry alerts)
# ═══════════════════════════════════════════════════════════════
class SMTPConfig(db.Model):
    __tablename__ = "smtp_config"
    id            = db.Column(db.Integer, primary_key=True)
    host          = db.Column(db.String(255), default="")
    port          = db.Column(db.Integer, default=587)
    username      = db.Column(db.String(255), default="")
    _password     = db.Column("password", db.String(255), default="")
    use_tls       = db.Column(db.Boolean, default=True)
    use_ssl       = db.Column(db.Boolean, default=False)
    from_addr     = db.Column(db.String(255), default="")
    from_name     = db.Column(db.String(100), default="RELAY Cert Monitor")
    alert_to      = db.Column(db.Text, default="")  # comma-separated recipients
    enabled       = db.Column(db.Boolean, default=False)

    @classmethod
    def get(cls):
        s = cls.query.first()
        if not s:
            s = cls(); db.session.add(s); db.session.commit()
        return s

    @property
    def password(self):
        return self._password or ""

    @password.setter
    def password(self, v):
        if v: self._password = v

    def is_configured(self):
        return bool(self.host and self.from_addr and self.alert_to)


# ═══════════════════════════════════════════════════════════════
#  CERT DEVICES  (SBCs, gateways, CUCM, Expressway, etc.)
# ═══════════════════════════════════════════════════════════════
CERT_DEVICE_PRODUCTS = [
    ("audiocodes_sbc",  "Audiocodes SBC",          "fas fa-server",   "#e05c2e"),
    ("anynode_sbc",     "Anynode SBC",              "fas fa-network-wired", "#2563eb"),
    ("oracle_sbc",      "Oracle (Acme Packet) SBC", "fas fa-database", "#c74634"),
    ("ribbon_sbc",      "Ribbon SBC",               "fas fa-ribbon",   "#6f42c1"),
    ("cisco_sbc",       "Cisco SBC (CUBE)",         "fas fa-cube",     "#049fd9"),
    ("cisco_gw",        "Cisco Analog Gateway",     "fas fa-phone",    "#00bceb"),
    ("cisco_cucm",      "Cisco CUCM",               "fas fa-building", "#049fd9"),
    ("cisco_expressway","Cisco Expressway / VCS",   "fas fa-road",     "#0078d4"),
]
CERT_PRODUCT_MAP = {k: (label, icon, colour)
                    for k, label, icon, colour in CERT_DEVICE_PRODUCTS}


class CertDevice(db.Model):
    """
    A managed device in the cert monitor.
    Extends hostname-based monitoring with product type, credentials
    and per-product connectivity fields.
    """
    __tablename__ = "cert_devices"
    id           = db.Column(db.Integer, primary_key=True)
    product_type = db.Column(db.String(30), nullable=False)
    label        = db.Column(db.String(120))
    hostname     = db.Column(db.String(255), nullable=False)
    port         = db.Column(db.Integer, default=443)
    ip_address   = db.Column(db.String(100))   # optional mgmt IP
    username     = db.Column(db.String(255))
    _password    = db.Column("password", db.String(255))
    # Protocol / transport
    transport    = db.Column(db.String(10), default="tls")  # tls|tcp|udp
    sip_port     = db.Column(db.Integer)        # SIP signalling port (SBCs)
    mgmt_port    = db.Column(db.Integer)        # separate mgmt-plane port
    # REST / SNMP
    api_endpoint = db.Column(db.String(255))    # REST base URL if different
    snmp_community = db.Column(db.String(100))
    # Status
    is_active    = db.Column(db.Boolean, default=True)
    notify_days  = db.Column(db.Integer, default=30)
    added_by     = db.Column(db.String(80))
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    # CSR lifecycle (same as CertDomain)
    private_key_pem  = db.Column(db.Text)
    csr_pem          = db.Column(db.Text)
    csr_cn           = db.Column(db.String(255))
    csr_org          = db.Column(db.String(255))
    csr_ou           = db.Column(db.String(255))
    csr_country      = db.Column(db.String(5))
    csr_state        = db.Column(db.String(100))
    csr_locality     = db.Column(db.String(100))
    csr_sans         = db.Column(db.Text)
    csr_generated_at = db.Column(db.DateTime)
    cert_chain_pem   = db.Column(db.Text)
    cert_uploaded_at = db.Column(db.DateTime)
    results = db.relationship("CertResult", backref="device",
                              lazy=True, cascade="all, delete-orphan",
                              primaryjoin="CertDevice.id == foreign(CertResult.device_id)",
                              order_by="CertResult.checked_at.desc()")

    @property
    def password(self):
        return self._password or ""

    @password.setter
    def password(self, v):
        if v: self._password = v

    @property
    def latest(self):
        return self.results[0] if self.results else None

    @property
    def product_label(self):
        return CERT_PRODUCT_MAP.get(self.product_type, (self.product_type, "", "#888"))[0]

    @property
    def product_colour(self):
        return CERT_PRODUCT_MAP.get(self.product_type, ("", "", "#888"))[2]


# ═══════════════════════════════════════════════════════════════
#  UNIFIED PHONE NUMBER INVENTORY
# ═══════════════════════════════════════════════════════════════
class PhoneNumber(db.Model):
    """
    Cross-platform phone number inventory.
    Populated by syncing Teams Graph API, Webex Calling API, and CUCM AXL.
    Used for DID block scan so overlaps across platforms are detected.
    """
    __tablename__ = "phone_numbers"
    id            = db.Column(db.Integer, primary_key=True)
    number        = db.Column(db.String(50), nullable=False)        # raw value from API
    number_norm   = db.Column(db.String(50), nullable=False,        # digits only, no +
                              index=True)
    platform      = db.Column(db.String(20), nullable=False,        # teams|webex|cucm
                              index=True)
    status        = db.Column(db.String(20), default="assigned")    # assigned|unassigned|reserved
    assigned_to   = db.Column(db.String(255))                       # display name / UPN / userid
    assigned_type = db.Column(db.String(50))                        # user|autoAttendant|service|…
    number_type   = db.Column(db.String(50))                        # directRouting|callingPlan|…
    location      = db.Column(db.String(255))                       # site / location name
    synced_at     = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        db.UniqueConstraint("number_norm", "platform", name="uq_number_platform"),
    )

    @staticmethod
    def normalize(number: str) -> str:
        """Strip everything except digits. '+31205550100' → '31205550100'."""
        import re
        return re.sub(r"\D", "", number or "")


class InventorySyncLog(db.Model):
    """One row per sync run, per platform."""
    __tablename__ = "inventory_sync_logs"
    id          = db.Column(db.Integer, primary_key=True)
    platform    = db.Column(db.String(20), nullable=False)
    started_at  = db.Column(db.DateTime, default=datetime.utcnow)
    finished_at = db.Column(db.DateTime)
    total       = db.Column(db.Integer, default=0)
    status      = db.Column(db.String(20), default="running")   # running|ok|error
    error       = db.Column(db.String(500))

    @classmethod
    def latest(cls, platform):
        return (cls.query.filter_by(platform=platform)
                .order_by(cls.started_at.desc()).first())


# ═══════════════════════════════════════════════════════════════
#  DID MANAGEMENT
# ═══════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════
#  DID GEOGRAPHIC HIERARCHY
#  Country → Region/State/Province → DIDBlock
#  Blocks can be attached at country level OR region level.
# ═══════════════════════════════════════════════════════════════
class DIDCountry(db.Model):
    """Top-level geographic container. Example: Belgium, UK, USA."""
    __tablename__ = "did_countries"
    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(120), nullable=False, unique=True)
    iso_code   = db.Column(db.String(5))   # ISO 3166-1 alpha-2, e.g. BE, GB, US
    notes      = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.String(80))
    regions    = db.relationship("DIDRegion", backref="country", lazy=True,
                                 cascade="all, delete-orphan",
                                 order_by="DIDRegion.name")
    # Blocks defined directly at country level (no specific region)
    blocks     = db.relationship("DIDBlock",
                                 primaryjoin="and_(DIDBlock.country_id==DIDCountry.id, "
                                             "DIDBlock.region_id==None)",
                                 backref="country_obj", lazy=True,
                                 foreign_keys="DIDBlock.country_id")


class DIDRegion(db.Model):
    """State / Province / Region within a country. Example: Wallonia, California."""
    __tablename__ = "did_regions"
    id         = db.Column(db.Integer, primary_key=True)
    country_id = db.Column(db.Integer, db.ForeignKey("did_countries.id"), nullable=False)
    name       = db.Column(db.String(120), nullable=False)
    notes      = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.String(80))
    blocks     = db.relationship("DIDBlock", backref="region", lazy=True,
                                 cascade="all, delete-orphan",
                                 foreign_keys="DIDBlock.region_id",
                                 order_by="DIDBlock.start_number")
    __table_args__ = (
        db.UniqueConstraint("country_id", "name", name="uq_region_country_name"),
    )


class DIDBlock(db.Model):
    """
    A contiguous range of telephone numbers.
    Attached at country OR region level (region_id may be NULL for country-level blocks).
    """
    __tablename__ = "did_blocks"
    id           = db.Column(db.Integer, primary_key=True)
    country_id   = db.Column(db.Integer, db.ForeignKey("did_countries.id"), nullable=False)
    region_id    = db.Column(db.Integer, db.ForeignKey("did_regions.id"),  nullable=True)
    label        = db.Column(db.String(100))
    start_number = db.Column(db.String(30), nullable=False)  # E.164 or bare extension
    end_number   = db.Column(db.String(30), nullable=False)
    number_type  = db.Column(db.String(30), default="mixed")
    # mixed | directRouting | callingPlan | operatorConnect | webex | cucm | unassigned
    notes        = db.Column(db.String(255))
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    created_by   = db.Column(db.String(80))

    @property
    def scope_label(self):
        if self.region:
            return f"{self.region.name}, {self.region.country.iso_code or self.region.country.name}"
        from app.models import DIDCountry as _C
        c = _C.query.get(self.country_id)
        return c.name if c else "—"

    @property
    def range_size(self):
        try:
            s = int("".join(ch for ch in self.start_number if ch.isdigit()))
            e = int("".join(ch for ch in self.end_number   if ch.isdigit()))
            return max(0, e - s + 1)
        except Exception:
            return None


# Keep Site as a legacy alias so old code doesn't break immediately
class Site(db.Model):
    """Legacy — kept so existing data and foreign-key references survive migration."""
    __tablename__ = "sites"
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.String(255))
    country     = db.Column(db.String(50))
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)


# ═══════════════════════════════════════════════════════════════
#  SCHEDULES
# ═══════════════════════════════════════════════════════════════
class Schedule(db.Model):
    __tablename__ = "schedules"
    id            = db.Column(db.Integer, primary_key=True)
    name          = db.Column(db.String(100))
    platform      = db.Column(db.String(20), nullable=False, default="teams")
    # teams: use teams_upn + user_object_id
    # webex: use user_object_id (personId)
    # cucm:  use teams_upn (userid)
    user_id       = db.Column(db.String(255))   # generic: personId (webex) or userid (cucm)
    user_upn      = db.Column(db.String(255))   # UPN/email/userid for display
    display_name  = db.Column(db.String(255))   # friendly name shown in UI
    # Legacy Teams columns kept for backwards compat
    teams_upn     = db.Column(db.String(255))
    user_object_id= db.Column(db.String(255))
    forward_to    = db.Column(db.String(50),  nullable=False)
    activate_at   = db.Column(db.DateTime,    nullable=False)
    deactivate_at = db.Column(db.DateTime)
    is_active     = db.Column(db.Boolean, default=True)
    activated     = db.Column(db.Boolean, default=False)
    deactivated   = db.Column(db.Boolean, default=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    created_by    = db.Column(db.String(80))
    note          = db.Column(db.String(200))


class TimeWindowSchedule(db.Model):
    __tablename__ = "time_window_schedules"
    id             = db.Column(db.Integer, primary_key=True)
    name           = db.Column(db.String(100))
    platform       = db.Column(db.String(20), nullable=False, default="teams")
    user_id        = db.Column(db.String(255))   # generic ID for the platform API
    user_upn       = db.Column(db.String(255))   # UPN/email/userid
    display_name   = db.Column(db.String(255))
    # Legacy Teams columns kept for backwards compat
    teams_upn      = db.Column(db.String(255))
    user_object_id = db.Column(db.String(255))
    forward_to     = db.Column(db.String(50), nullable=False)
    days           = db.Column(db.String(100), nullable=False)
    start_time     = db.Column(db.String(10),  nullable=False)
    end_time       = db.Column(db.String(10),  nullable=False)
    note           = db.Column(db.String(200))
    is_enabled     = db.Column(db.Boolean, default=True)
    cf_active      = db.Column(db.Boolean, default=False)
    last_checked   = db.Column(db.DateTime)
    last_action    = db.Column(db.String(200))
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    created_by     = db.Column(db.String(80))

    def day_numbers(self):
        MAP = {"Mon":0,"Tue":1,"Wed":2,"Thu":3,"Fri":4,"Sat":5,"Sun":6}
        return [MAP[d.strip()] for d in self.days.split(",") if d.strip() in MAP]

    def is_window_active(self, now):
        if not self.is_enabled:
            return False
        if now.weekday() not in self.day_numbers():
            return False
        from datetime import time as dtime
        sh, sm = map(int, self.start_time.split(":"))
        eh, em = map(int, self.end_time.split(":"))
        s = dtime(sh, sm); e = dtime(eh, em); c = now.time()
        if s < e:
            return s <= c < e
        return c >= s or c < e


# ═══════════════════════════════════════════════════════════════
#  AUDIT LOG
# ═══════════════════════════════════════════════════════════════
class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id          = db.Column(db.Integer, primary_key=True)
    timestamp   = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    username    = db.Column(db.String(80),  nullable=False, index=True)
    user_role   = db.Column(db.String(20))
    action      = db.Column(db.String(50),  nullable=False)
    resource    = db.Column(db.String(50))
    resource_id = db.Column(db.String(100))
    detail      = db.Column(db.String(500))
    ip_address  = db.Column(db.String(45))
    status      = db.Column(db.String(10), default="OK")


def log_audit(action, resource=None, resource_id=None,
              detail=None, status="OK", ip=None):
    from flask_login import current_user
    from flask import request
    username = getattr(current_user, "username", "system")
    role     = getattr(current_user, "role",     "system")
    ip       = ip or (request.remote_addr if request else None)
    row = AuditLog(username=username, user_role=role, action=action,
                   resource=resource,
                   resource_id=str(resource_id) if resource_id else None,
                   detail=detail, ip_address=ip, status=status)
    db.session.add(row)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()


# ═══════════════════════════════════════════════════════════════
#  LDAP SERVER
# ═══════════════════════════════════════════════════════════════
class LdapServer(db.Model):
    __tablename__ = "ldap_servers"
    id              = db.Column(db.Integer, primary_key=True)
    name            = db.Column(db.String(100), nullable=False, unique=True)
    host            = db.Column(db.String(255), nullable=False)
    port            = db.Column(db.Integer, default=389)
    bind_dn         = db.Column(db.String(300))
    _bind_password  = db.Column("bind_password", db.String(255))
    base_dn         = db.Column(db.String(300))
    user_filter     = db.Column(db.String(200), default="(objectClass=person)")
    attr_name       = db.Column(db.String(80),  default="displayName")
    attr_email      = db.Column(db.String(80),  default="mail")
    attr_uid        = db.Column(db.String(80),  default="sAMAccountName")
    attr_phone      = db.Column(db.String(80),  default="telephoneNumber")
    use_ssl         = db.Column(db.Boolean, default=False)
    use_tls         = db.Column(db.Boolean, default=True)
    is_active       = db.Column(db.Boolean, default=True)
    last_sync_at    = db.Column(db.DateTime)
    last_sync_ok    = db.Column(db.Boolean)
    last_sync_msg   = db.Column(db.String(300), default="Never synced")
    last_sync_count = db.Column(db.Integer, default=0)
    added_by        = db.Column(db.String(80))
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
    users           = db.relationship("User", backref="ldap_server", lazy=True,
                                      foreign_keys="User.ldap_server_id")

    @property
    def bind_password(self):
        return self._bind_password or ""

    @bind_password.setter
    def bind_password(self, v):
        if v:
            self._bind_password = v

    def is_configured(self):
        return bool(self.host and self.bind_dn and self._bind_password and self.base_dn)


# ═══════════════════════════════════════════════════════════════
#  CERT MONITOR
# ═══════════════════════════════════════════════════════════════
class CertDomain(db.Model):
    __tablename__ = "cert_domains"
    id          = db.Column(db.Integer, primary_key=True)
    hostname    = db.Column(db.String(255), nullable=False)
    port        = db.Column(db.Integer, default=443)
    label       = db.Column(db.String(120))
    notify_days = db.Column(db.Integer, default=30)
    is_active   = db.Column(db.Boolean, default=True)
    added_by    = db.Column(db.String(80))
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    # CSR / certificate lifecycle
    private_key_pem  = db.Column(db.Text)          # RSA private key (PEM)
    csr_pem          = db.Column(db.Text)          # Certificate Signing Request (PEM)
    csr_cn           = db.Column(db.String(255))   # CN used when generating CSR
    csr_org          = db.Column(db.String(255))
    csr_ou           = db.Column(db.String(255))
    csr_country      = db.Column(db.String(5))
    csr_state        = db.Column(db.String(100))
    csr_locality     = db.Column(db.String(100))
    csr_sans         = db.Column(db.Text)          # comma-separated SANs
    csr_generated_at = db.Column(db.DateTime)
    cert_chain_pem   = db.Column(db.Text)          # uploaded signed cert + chain
    cert_uploaded_at = db.Column(db.DateTime)
    results     = db.relationship("CertResult", backref="domain", lazy=True,
                                  cascade="all, delete-orphan",
                                  order_by="CertResult.checked_at.desc()")

    @property
    def latest(self):
        return self.results[0] if self.results else None


class CertResult(db.Model):
    __tablename__ = "cert_results"
    id          = db.Column(db.Integer, primary_key=True)
    domain_id   = db.Column(db.Integer, db.ForeignKey("cert_domains.id"), nullable=True)
    device_id   = db.Column(db.Integer, db.ForeignKey("cert_devices.id"), nullable=True)
    risk        = db.Column(db.String(20))
    days_left   = db.Column(db.Integer)
    not_before  = db.Column(db.String(20))
    not_after   = db.Column(db.String(20))
    issuer_org  = db.Column(db.String(200))
    issuer_cn   = db.Column(db.String(200))
    subject_cn  = db.Column(db.String(200))
    san_count   = db.Column(db.Integer)
    error       = db.Column(db.String(500))
    checked_at  = db.Column(db.DateTime, default=datetime.utcnow, index=True)
