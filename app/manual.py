"""Manual evidence: an assessment by a named person, optionally with a file, valid until a date.

Uploaded files are stored under a random name in DATA_DIR/attachments and are only
ever served back as downloads (never rendered in the browser), so a malicious file
cannot run scripts in the app. A SHA-256 hash is kept for integrity in the report.
"""
import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from app import config
from app.db import get_conn

MAX_FILE_BYTES = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".txt": "text/plain",
    ".csv": "text/csv",
    ".md": "text/markdown",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".odt": "application/vnd.oasis.opendocument.text",
    ".ods": "application/vnd.oasis.opendocument.spreadsheet",
}


class EvidenceError(ValueError):
    pass


@dataclass
class Upload:
    filename: str
    data: bytes


def attachments_dir() -> Path:
    d = Path(config.DATA_DIR) / "attachments"
    d.mkdir(parents=True, exist_ok=True)
    return d


def safe_filename(name: str) -> str:
    name = Path(name or "file").name
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip(" .") or "file"
    return name[:120]


def add_manual_evidence(control_id: str, status: str, note: str, reviewer: str,
                        valid_until: str | None, upload: Upload | None = None) -> int:
    note, reviewer = (note or "").strip(), (reviewer or "").strip()
    if status not in ("pass", "fail"):
        raise EvidenceError("Status must be pass or fail.")
    if not note:
        raise EvidenceError("A note describing the evidence is required.")
    if not reviewer:
        raise EvidenceError("The reviewer's name is required.")
    if valid_until:
        try:
            if date.fromisoformat(valid_until) < date.today():
                raise EvidenceError("'Valid until' cannot be in the past.")
        except ValueError as exc:
            if isinstance(exc, EvidenceError):
                raise
            raise EvidenceError("'Valid until' must be a date (YYYY-MM-DD).") from exc

    stored = None
    if upload and upload.data:
        filename = safe_filename(upload.filename)
        ext = Path(filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise EvidenceError(f"File type '{ext or 'none'}' is not allowed. Allowed: "
                                + ", ".join(sorted(ALLOWED_EXTENSIONS)))
        if len(upload.data) > MAX_FILE_BYTES:
            raise EvidenceError("File is larger than 10 MB.")
        stored = (filename, secrets.token_hex(16) + ext, ALLOWED_EXTENSIONS[ext],
                  len(upload.data), hashlib.sha256(upload.data).hexdigest())

    with get_conn() as conn:
        row = conn.execute("SELECT check_type FROM controls WHERE id = ?", (control_id,)).fetchone()
        if not row:
            raise EvidenceError(f"Unknown control {control_id}.")
        if row["check_type"] != "manual":
            raise EvidenceError("This control is verified automatically; manual evidence is not accepted.")
        ev_id = conn.execute(
            """INSERT INTO evidence (control_id, source, status, summary, raw_json, reviewer, valid_until)
               VALUES (?, 'manual', ?, ?, '{}', ?, ?)""",
            (control_id, status, note, reviewer, valid_until or None)).lastrowid
        if stored:
            (attachments_dir() / stored[1]).write_bytes(upload.data)
            conn.execute(
                """INSERT INTO attachments (evidence_id, filename, stored_name, content_type, size, sha256)
                   VALUES (?, ?, ?, ?, ?, ?)""", (ev_id, *stored))
    return ev_id


def get_attachment(attachment_id: int) -> tuple[dict, Path] | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM attachments WHERE id = ?", (attachment_id,)).fetchone()
    if not row:
        return None
    path = attachments_dir() / row["stored_name"]
    return (dict(row), path) if path.is_file() else None
