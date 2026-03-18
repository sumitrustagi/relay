"""
RELAY — Upload Manager

Handles saving uploaded CSV files to persistent storage on disk,
with automatic rotation to prevent unbounded disk growth.

Storage layout:
  /opt/relay/uploads/
      csv/          ← schedule CSVs, DID import CSVs, user CSVs
      certs/        ← uploaded certificate chains (PEM)
      temp/         ← short-lived working files (purged > 24h old)

Files are named:  <timestamp>_<username>_<original_filename>
"""
import os
import time
import logging
from pathlib import Path
from datetime import datetime, timezone
from werkzeug.utils import secure_filename

log = logging.getLogger(__name__)

# Base upload directory — installer creates this during setup
_BASE_CANDIDATES = [
    "/opt/relay/uploads",
    "/opt/relay/instance/uploads",
]

MAX_CSV_BYTES   = 10 * 1024 * 1024   # 10 MB per upload
MAX_CERT_BYTES  = 256 * 1024          # 256 KB per cert file
ROTATE_CSV_DAYS = 90                  # keep CSV files for 90 days
ROTATE_CERT_DAYS= 365                 # keep cert files for 1 year
ROTATE_TEMP_HOURS = 24                # temp files purged after 24 h


def _base_dir() -> Path:
    """Return the upload base directory, creating it if needed."""
    explicit = os.environ.get("RELAY_UPLOAD_DIR")
    if explicit:
        p = Path(explicit)
        p.mkdir(parents=True, exist_ok=True)
        return p
    for candidate in _BASE_CANDIDATES:
        p = Path(candidate)
        if p.exists():
            return p
    # Fallback: inside instance directory
    from flask import current_app
    try:
        p = Path(current_app.instance_path) / "uploads"
        p.mkdir(parents=True, exist_ok=True)
        return p
    except RuntimeError:
        p = Path("/tmp/relay_uploads")
        p.mkdir(parents=True, exist_ok=True)
        return p


def _subdir(name: str) -> Path:
    d = _base_dir() / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def _make_filename(original: str, username: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe = secure_filename(original) or "upload"
    return f"{ts}_{secure_filename(username or 'anon')}_{safe}"


# ── Save functions ─────────────────────────────────────────────

def save_csv(file_storage, username: str) -> dict:
    """
    Save a Werkzeug FileStorage CSV to disk.
    Returns {"ok": bool, "path": str, "filename": str, "error": str}
    """
    data = file_storage.read()
    if len(data) > MAX_CSV_BYTES:
        return {"ok": False, "error": f"File exceeds {MAX_CSV_BYTES//1024//1024} MB limit"}

    filename = _make_filename(file_storage.filename or "upload.csv", username)
    dest     = _subdir("csv") / filename
    try:
        dest.write_bytes(data)
        os.chmod(dest, 0o640)
        log.info("upload_manager: CSV saved %s (%d bytes)", dest, len(data))
        return {"ok": True, "path": str(dest), "filename": filename, "size": len(data)}
    except OSError as e:
        return {"ok": False, "error": str(e)}


def save_cert(pem_text: str, hostname: str, username: str) -> dict:
    """Save a PEM certificate chain to the certs subdir."""
    data = pem_text.encode()
    if len(data) > MAX_CERT_BYTES:
        return {"ok": False, "error": "Certificate data exceeds 256 KB"}
    safe_host = hostname.replace(".", "_").replace("*", "wildcard")
    filename  = _make_filename(f"{safe_host}_chain.pem", username)
    dest      = _subdir("certs") / filename
    try:
        dest.write_bytes(data)
        os.chmod(dest, 0o640)
        return {"ok": True, "path": str(dest), "filename": filename}
    except OSError as e:
        return {"ok": False, "error": str(e)}


# ── Rotation / cleanup ─────────────────────────────────────────

def rotate_uploads(dry_run: bool = False) -> dict:
    """
    Delete old uploaded files according to retention policy.
    Returns counts of files removed per category.
    """
    now = time.time()
    removed: dict[str, int] = {"csv": 0, "certs": 0, "temp": 0}

    def _clean(subdir_name: str, max_age_seconds: float):
        subdir = _base_dir() / subdir_name
        if not subdir.exists():
            return
        for f in subdir.iterdir():
            if not f.is_file():
                continue
            age = now - f.stat().st_mtime
            if age > max_age_seconds:
                log.info("upload_manager: rotating %s (%.0f days old)", f.name, age/86400)
                if not dry_run:
                    try:
                        f.unlink()
                        removed[subdir_name] = removed.get(subdir_name, 0) + 1
                    except OSError as e:
                        log.warning("upload_manager: could not delete %s: %s", f, e)
                else:
                    removed[subdir_name] = removed.get(subdir_name, 0) + 1

    _clean("csv",   ROTATE_CSV_DAYS  * 86400)
    _clean("certs", ROTATE_CERT_DAYS * 86400)
    _clean("temp",  ROTATE_TEMP_HOURS * 3600)

    total = sum(removed.values())
    log.info("upload_manager: rotation complete — %d file(s) removed", total)
    return {"ok": True, "removed": removed, "total": total, "dry_run": dry_run}


def get_upload_stats() -> dict:
    """Return disk usage stats for the uploads directory."""
    base = _base_dir()
    stats: dict[str, dict] = {}
    total_size = 0
    total_count = 0
    for sub in ["csv", "certs", "temp"]:
        d = base / sub
        if not d.exists():
            stats[sub] = {"count": 0, "size_kb": 0}
            continue
        files = list(d.iterdir())
        size  = sum(f.stat().st_size for f in files if f.is_file())
        stats[sub] = {"count": len(files), "size_kb": round(size / 1024, 1)}
        total_size  += size
        total_count += len(files)
    return {
        "base_dir": str(base),
        "subdirs":  stats,
        "total_files": total_count,
        "total_size_kb": round(total_size / 1024, 1),
    }
