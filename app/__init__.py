import os
from flask import Flask, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
migrate = Migrate()


def create_app(env="production"):
    app = Flask(__name__)
    app.config.from_object(__import__("config").config[env])

    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)

    from app.routes.auth import auth_bp
    from app.routes.admin import admin_bp
    from app.routes.extension import extension_bp
    from app.routes.schedule import schedule_bp
    from app.routes.schedule_csv import schedule_csv_bp
    from app.routes.cert_monitor import cert_bp
    from app.routes.ldap_routes import ldap_bp
    from app.routes.webex_extension import webex_ext_bp
    from app.routes.cucm import cucm_bp

    app.register_blueprint(auth_bp,         url_prefix="/auth")
    app.register_blueprint(admin_bp,         url_prefix="/admin")
    app.register_blueprint(extension_bp,     url_prefix="/extension")
    app.register_blueprint(schedule_bp,      url_prefix="/schedule")
    app.register_blueprint(schedule_csv_bp,  url_prefix="/schedule-csv")
    app.register_blueprint(cert_bp,          url_prefix="/admin/certs")
    app.register_blueprint(ldap_bp,          url_prefix="/admin/ldap")
    app.register_blueprint(webex_ext_bp,     url_prefix="/webex")
    app.register_blueprint(cucm_bp,          url_prefix="/cucm")

    @app.context_processor
    def inject_platform():
        from app.models import PlatformSettings
        try:
            ps = PlatformSettings.get()
            return dict(
                has_teams        = ps.has_teams,
                has_webex        = ps.has_webex,
                has_cucm         = ps.has_cucm,
                has_cert_monitor = ps.has_cert_monitor,
                has_did          = ps.has_did,
                has_ldap         = ps.has_ldap,
                has_audit        = ps.has_audit,
                client_name      = ps.client_name or "",
            )
        except Exception:
            return dict(has_teams=True, has_webex=False, has_cucm=False,
                        has_cert_monitor=False, has_did=True, has_ldap=False,
                        has_audit=False, client_name="")

    @app.route("/")
    def index():
        return redirect(url_for("schedule_csv.index"))

    with app.app_context():
        _bootstrap_admin()

    from app.utils.scheduler import start_scheduler
    start_scheduler(app)

    return app


def _bootstrap_admin():
    """
    Create the first admin account from environment variables.
    Only runs if NO admin user exists (first boot / fresh DB).
    Never overwrites an existing admin — safe to call on every restart.

    Set these in .env to control the bootstrap account:
        RELAY_ADMIN_USER=admin
        RELAY_ADMIN_PASS=yourpassword
        RELAY_ADMIN_EMAIL=admin@example.com

    If RELAY_ADMIN_PASS is not set, defaults to 'Relay@Setup1' and
    logs a clear warning so it is never silently lost.
    """
    from app.models import User
    import logging
    log = logging.getLogger(__name__)

    # Guard: if the users table doesn't exist yet (pre-migration), exit silently.
    # flask db upgrade will create the schema; _bootstrap_admin runs on next restart.
    try:
        if User.query.filter_by(role="admin").first():
            return
    except Exception:
        return

    username = os.getenv("RELAY_ADMIN_USER", "admin").strip() or "admin"
    password = os.getenv("RELAY_ADMIN_PASS", "").strip()
    email    = os.getenv("RELAY_ADMIN_EMAIL", f"{username}@relay.local").strip()

    if not password:
        password = "Relay@Setup1"
        log.warning(
            "RELAY_ADMIN_PASS not set in .env — admin account created with "
            "default password 'Relay@Setup1'. Change it immediately via GUI."
        )
    else:
        log.info("Bootstrap admin account created: user=%s", username)

    u = User(username=username, email=email, role="admin")
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
