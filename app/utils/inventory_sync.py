"""
RELAY — Unified Phone Number Inventory Sync

Pulls number assignments from every enabled platform (Teams, Webex, CUCM)
into the shared `phone_numbers` table so that DID block scans can detect
cross-platform overlap without hitting multiple APIs at scan time.

Usage (called from admin routes):
    from app.utils.inventory_sync import sync_platform, sync_all
    result = sync_platform("teams")   # {"ok": True, "total": 245, "platform": "teams"}
    result = sync_all()               # {"teams": {...}, "webex": {...}, "cucm": {...}}
"""
from datetime import datetime, timezone
from app import db
from app.models import PhoneNumber, InventorySyncLog, PlatformSettings


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _upsert_numbers(rows: list[dict], platform: str) -> int:
    """
    Upsert a list of normalised number dicts into phone_numbers for one platform.
    Deletes rows for this platform that are no longer present in the live data.
    Returns count of rows written.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    # Build lookup of what we currently have in DB for this platform
    existing: dict[str, PhoneNumber] = {
        pn.number_norm: pn
        for pn in PhoneNumber.query.filter_by(platform=platform).all()
    }

    live_norms: set[str] = set()

    for row in rows:
        norm = row["number_norm"]
        if not norm:
            continue
        live_norms.add(norm)

        if norm in existing:
            pn = existing[norm]
        else:
            pn = PhoneNumber(number_norm=norm, platform=platform)
            db.session.add(pn)

        pn.number        = row.get("number",        norm)
        pn.status        = row.get("status",        "assigned")
        pn.assigned_to   = row.get("assigned_to",   None)
        pn.assigned_type = row.get("assigned_type", None)
        pn.number_type   = row.get("number_type",   None)
        pn.location      = row.get("location",      None)
        pn.synced_at     = now

    # Remove stale rows (numbers no longer in the live system)
    stale = [existing[n] for n in existing if n not in live_norms]
    for pn in stale:
        db.session.delete(pn)

    db.session.commit()
    return len(live_norms)


# ─────────────────────────────────────────────────────────────────────────────
# Teams sync
# ─────────────────────────────────────────────────────────────────────────────

def _sync_teams() -> list:
    """
    Pull all Teams phone numbers with display names into the unified inventory.
    Uses get_all_assigned_numbers_for_inventory() for the base data (new + legacy API).
    Then enriches assigned_to with display names by calling get_all_user_configurations()
    to build an objectId → name map, falling back to the local User table.
    """
    from app.utils.graph_api import (get_all_assigned_numbers_for_inventory,
                                     get_all_user_configurations)
    base_rows = get_all_assigned_numbers_for_inventory()

    # Build id → display_name map from userConfigurations (new API)
    id_to_name: dict[str, str] = {}
    try:
        configs = get_all_user_configurations()
        for cfg in configs:
            uid = cfg.get("id", "")
            upn = cfg.get("userPrincipalName", "")
            # Use UPN as display name if no better field
            if uid and upn:
                id_to_name[uid.lower()] = upn
    except Exception as e:
        import logging
        logging.getLogger(__name__).debug("userConfigurations enrichment failed: %s", e)

    # Also try local User table as fallback
    try:
        from app.models import User
        for u in User.query.filter(User.teams_upn.isnot(None)).all():
            upn = (u.teams_upn or "").lower()
            if upn:
                id_to_name[upn] = u.display_name or u.username or upn
            ext = (u.teams_extension or "").lower()
            if ext:
                id_to_name[ext] = u.display_name or u.username or ext
    except Exception:
        pass

    # Enrich rows: if assigned_to looks like an objectId (no @, no +), try to resolve
    for row in base_rows:
        raw = (row.get("assigned_to") or "").strip()
        if raw and "@" not in raw and not raw.startswith("+"):
            # Looks like an objectId — try to resolve to a name
            name = id_to_name.get(raw.lower())
            if name:
                row["assigned_to"] = name
    return base_rows


# ─────────────────────────────────────────────────────────────────────────────
# Webex sync
# ─────────────────────────────────────────────────────────────────────────────

def _sync_webex() -> list:
    from app.utils.webex_api import get_webex_numbers

    all_numbers = get_webex_numbers(max_results=1000)

    # Build personId → name from local User table as enrichment
    local_name: dict[str, str] = {}
    try:
        from app.models import User
        for u in User.query.filter(User.webex_extension.isnot(None)).all():
            ext = (u.webex_extension or "").lower()
            if ext:
                local_name[ext] = u.display_name or u.username or ext
    except Exception:
        pass

    rows = []
    for n in all_numbers:
        number    = n.get("phoneNumber", "")
        extension = n.get("extension", "")
        raw = number or extension
        if not raw:
            continue
        norm  = PhoneNumber.normalize(raw)
        owner = n.get("owner", {})

        # Build the best available display name
        # Webex API may return: displayName, firstName+lastName, id
        disp = (owner.get("displayName") or
                " ".join(filter(None, [owner.get("firstName",""), owner.get("lastName","")])).strip() or
                local_name.get((owner.get("id") or "").lower()) or
                owner.get("id") or
                None)

        owner_id   = (owner.get("id")   or "").strip()
        owner_type = (owner.get("type") or "").strip()

        # Valid Webex entity types that confirm a real assignment.
        # An owner.id without a recognised type is a stale/phantom reference.
        VALID_WEBEX_TYPES = {
            "PEOPLE", "PLACE", "VIRTUAL_LINE",
            "CALL_QUEUE", "AUTO_ATTENDANT", "HUNT_GROUP",
            "PAGING_GROUP", "GROUP_PAGING",
        }
        is_assigned = bool(owner_id) and (
            owner_type.upper() in VALID_WEBEX_TYPES or bool(disp)
        )

        base = {
            "assigned_to":   disp,
            "assigned_type": owner_type or None,
            "number_type":   n.get("numberType", "webex"),
            "location":      n.get("location", {}).get("name"),
            "status":        "assigned" if is_assigned else "available",
        }
        rows.append({"number": raw, "number_norm": norm, **base})
        # Also index bare extension when both E.164 and extension exist
        if number and extension:
            ext_norm = PhoneNumber.normalize(extension)
            if ext_norm != norm:
                rows.append({"number": extension, "number_norm": ext_norm,
                              "number_type": "webex-extension", **{k:v for k,v in base.items() if k!="number_type"}})
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# CUCM sync
# ─────────────────────────────────────────────────────────────────────────────

def _sync_cucm() -> list:
    """
    Pull DN inventory from ALL enabled CUCM clusters and merge into one list.
    Clusters that fail are skipped with a warning — remaining clusters still sync.
    """
    from app.utils.cucm_api import list_all_cucm_lines
    from app.models import CUCMCluster

    ACTIVE_CUCM_USAGES = {
        "Device", "Translation Pattern", "CTI Route Point",
        "Hunt List", "Hunt Pilot", "Call Park", "Call Pickup",
        "Meet-Me Conference", "Voice Mail Port", "Route Point", "Auto Attendant",
    }

    rows = []
    clusters = CUCMCluster.query.filter_by(is_enabled=True).all()
    if not clusters:
        return rows

    for cluster in clusters:
        if not cluster.is_configured():
            continue
        try:
            raw = list_all_cucm_lines(cluster=cluster)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(
                "CUCM cluster '%s' sync failed: %s", cluster.label, e)
            continue

        for line in raw:
            pattern = line.get("pattern", "")
            if not pattern:
                continue
            norm = PhoneNumber.normalize(pattern)
            if not norm:
                continue

            description = (line.get("description") or "").strip()
            usage       = (line.get("usage")       or "").strip()
            partition   = (line.get("partition")   or "").strip()

            is_assigned = bool(description) or (usage in ACTIVE_CUCM_USAGES)
            location = f"[{cluster.label}] {partition}" if partition else f"[{cluster.label}]"

            rows.append({
                "number":        pattern,
                "number_norm":   norm,
                "status":        "assigned" if is_assigned else "available",
                "assigned_to":   description or (f"[{usage}]" if usage else None),
                "assigned_type": usage or "DN",
                "number_type":   "cucm",
                "location":      location,
            })
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def sync_platform(platform: str) -> dict:
    """
    Sync a single platform into the unified inventory.
    Returns {"ok": bool, "platform": str, "total": int, "error": str|None}
    """
    log = InventorySyncLog(platform=platform, status="running")
    db.session.add(log)
    db.session.commit()

    try:
        if platform == "teams":
            rows = _sync_teams()
        elif platform == "webex":
            rows = _sync_webex()
        elif platform == "cucm":
            rows = _sync_cucm()
        else:
            raise ValueError(f"Unknown platform: {platform}")

        total = _upsert_numbers(rows, platform)
        log.finished_at = datetime.now(timezone.utc).replace(tzinfo=None)
        log.total       = total
        log.status      = "ok"
        db.session.commit()
        return {"ok": True, "platform": platform, "total": total, "error": None}

    except Exception as e:
        db.session.rollback()
        log.finished_at = datetime.now(timezone.utc).replace(tzinfo=None)
        log.status      = "error"
        log.error       = str(e)[:490]
        db.session.commit()
        return {"ok": False, "platform": platform, "total": 0, "error": str(e)}


def sync_all() -> dict:
    """Sync all enabled platforms. Returns per-platform result dicts."""
    ps = PlatformSettings.get()
    results = {}
    if ps.has_teams:
        results["teams"] = sync_platform("teams")
    if ps.has_webex:
        results["webex"] = sync_platform("webex")
    if ps.has_cucm:
        results["cucm"] = sync_platform("cucm")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Block scan — cross-platform
# ─────────────────────────────────────────────────────────────────────────────

def scan_block_unified(start: str, end: str) -> dict:
    """
    Scan a DID block against the unified inventory (all platforms combined).

    A number is reported as available only if it appears on NONE of the
    synced platforms. If a platform has never been synced, a warning is
    included so the admin knows the result may be incomplete.

    start/end: E.164 ('+3227780000') or bare extension ('1001').
    """
    from app.models import PlatformSettings

    start_norm = PhoneNumber.normalize(start)
    end_norm   = PhoneNumber.normalize(end)

    if not start_norm.isdigit() or not end_norm.isdigit():
        return {"ok": False, "error": "Block boundaries must be numeric (E.164 or extension)"}

    start_i = int(start_norm)
    end_i   = int(end_norm)

    if end_i < start_i:
        return {"ok": False, "error": "End number must be >= start number"}

    block_size = end_i - start_i + 1

    # Warn if any enabled platform has never been synced
    ps = PlatformSettings.get()
    warnings = []
    for plat, enabled in [("teams", ps.has_teams), ("webex", ps.has_webex), ("cucm", ps.has_cucm)]:
        if enabled:
            if not PhoneNumber.query.filter_by(platform=plat).first():
                warnings.append(
                    f"{plat} inventory is empty — sync it first for accurate results"
                )

    # Fetch candidate rows by digit-length
    len_s = len(start_norm)
    len_e = len(end_norm)
    candidates = PhoneNumber.query.filter(
        db.func.length(PhoneNumber.number_norm).in_([len_s, len_e])
    ).all()

    # Build fast lookup: number_norm -> [PhoneNumber, ...]
    inventory = {}
    for pn in candidates:
        n = pn.number_norm
        if start_norm <= n <= end_norm:
            inventory.setdefault(n, []).append(pn)

    numbers = []
    assigned_count = 0
    platform_counts = {}

    for i in range(start_i, end_i + 1):
        norm = str(i).zfill(len_s)
        matches = inventory.get(norm, [])

        if matches:
            # A number is only "assigned" if at least one platform row has
            # status="assigned". Rows with status="available" mean the platform
            # knows about the number but nothing is attached to it.
            assigned_matches = [m for m in matches if m.status == "assigned"]

            if assigned_matches:
                platforms = [m.platform for m in assigned_matches]
                for p in platforms:
                    platform_counts[p] = platform_counts.get(p, 0) + 1
                assigned_count += 1
                numbers.append({
                    "number":    norm,
                    "status":    "assigned",
                    "platforms": platforms,
                    "details": [
                        {
                            "platform":    m.platform,
                            "assigned_to": m.assigned_to,
                            "type":        m.assigned_type,
                            "number_type": m.number_type,
                            "location":    m.location,
                        }
                        for m in assigned_matches
                    ],
                })
            else:
                # Number exists in inventory but status is "available" on
                # all platforms that know about it — treat as available
                numbers.append({
                    "number":    norm,
                    "status":    "available",
                    "platforms": [],
                    "details":   [],
                })
        else:
            numbers.append({
                "number":    norm,
                "status":    "available",
                "platforms": [],
                "details":   [],
            })

    return {
        "ok":              True,
        "total":           block_size,
        "assigned":        assigned_count,
        "available":       block_size - assigned_count,
        "platform_counts": platform_counts,
        "warnings":        warnings,
        "numbers":         numbers,
    }

