"""LDAP / AD sync utility.  Requires: pip install ldap3"""
from datetime import datetime


def _make_connection(srv):
    from ldap3 import Server, Connection, ALL, SIMPLE, AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND, SAFE_SYNC, Tls
    import ssl
    tls = Tls(validate=ssl.CERT_NONE) if srv.use_tls else None
    server    = Server(srv.host, port=srv.port, use_ssl=srv.use_ssl, tls=tls, get_info=ALL)
    auto_bind = AUTO_BIND_TLS_BEFORE_BIND if srv.use_tls else AUTO_BIND_NO_TLS
    return Connection(server, user=srv.bind_dn, password=srv.bind_password,
                      authentication=SIMPLE, auto_bind=auto_bind,
                      client_strategy=SAFE_SYNC, raise_exceptions=True)


def test_connection(srv):
    try:
        conn = _make_connection(srv)
        info = str(conn.server.info.vendor_name or "LDAP") if conn.server.info else "Connected"
        conn.unbind()
        return {"ok": True, "message": f"Bind successful — {info}"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def sync_users(srv, app_context):
    from app import db
    from app.models import User
    attrs = [srv.attr_name, srv.attr_email, srv.attr_uid, srv.attr_phone]
    try:
        conn = _make_connection(srv)
        conn.search(search_base=srv.base_dn, search_filter=srv.user_filter, attributes=attrs)
        entries = list(conn.entries)
        conn.unbind()
    except Exception as e:
        return {"ok": False, "created": 0, "updated": 0, "skipped": 0,
                "message": f"LDAP search failed: {e}"}

    created = updated = skipped = 0
    for entry in entries:
        uid   = _attr(entry, srv.attr_uid)
        email = _attr(entry, srv.attr_email)
        name  = _attr(entry, srv.attr_name)
        phone = _attr(entry, srv.attr_phone)
        dn    = entry.entry_dn
        if not uid or not email:
            skipped += 1
            continue
        with app_context:
            user = User.query.filter_by(username=uid).first()
            if user:
                user.email = email; user.ldap_dn = dn; user.ldap_server_id = srv.id
                if name:  user.display_name = name
                if phone and not user.teams_extension: user.teams_extension = phone
                updated += 1
            else:
                import secrets
                user = User(username=uid, email=email, role="user", is_active=True,
                            display_name=name, ldap_dn=dn, ldap_server_id=srv.id)
                if phone: user.teams_extension = phone
                user.set_password(secrets.token_hex(24))
                db.session.add(user)
                created += 1
        db.session.commit()
    return {"ok": True, "created": created, "updated": updated, "skipped": skipped,
            "message": f"Sync complete: {created} created, {updated} updated, {skipped} skipped."}


def _attr(entry, attr_name):
    try:
        val = getattr(entry, attr_name).value
        return str(val[0] if isinstance(val, list) else val) if val else ""
    except Exception:
        return ""
