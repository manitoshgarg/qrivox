"""Local SQLite storage for scan history; this is not threat intelligence."""

from __future__ import annotations

import hashlib
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


SCHEMA_VERSION = 1
BUSY_TIMEOUT_SECONDS = 5.0
DATABASE_ENV_VAR = "QR_SAFE_DATABASE_PATH"


class StorageError(RuntimeError):
    """The database schema cannot be used by this version of the app."""


def default_database_path() -> Path:
    configured = os.environ.get(DATABASE_ENV_VAR)
    if configured:
        return Path(configured).expanduser()
    return Path(__file__).with_name("qr_safe_history.sqlite3")


@contextmanager
def connect_database(database_path: str | Path | None = None) -> Iterator[sqlite3.Connection]:
    """Yield a configured SQLite connection and always close it on exit."""
    path = Path(database_path) if database_path is not None else default_database_path()
    connection = sqlite3.connect(str(path), timeout=BUSY_TIMEOUT_SECONDS)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {int(BUSY_TIMEOUT_SECONDS * 1000)}")
        yield connection
    finally:
        connection.close()


def initialize_storage(database_path: str | Path | None = None) -> None:
    """Apply all pending schema migrations transactionally and idempotently."""
    with connect_database(database_path) as connection:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version > SCHEMA_VERSION:
            raise StorageError(
                f"Database schema version {version} is newer than supported version {SCHEMA_VERSION}."
            )
        if version == SCHEMA_VERSION:
            return

        try:
            connection.execute("BEGIN IMMEDIATE")
            if version < 1:
                _migration_1(connection)
                connection.execute("PRAGMA user_version = 1")
            connection.commit()
        except Exception:
            connection.rollback()
            raise


def _migration_1(connection: sqlite3.Connection) -> None:
    connection.execute(
        """CREATE TABLE scans (
            scan_id INTEGER PRIMARY KEY,
            scanned_at_utc TEXT NOT NULL,
            fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64),
            risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
            verdict TEXT NOT NULL,
            payee_vpa TEXT NOT NULL DEFAULT '',
            payee_name TEXT NOT NULL DEFAULT '',
            amount TEXT,
            currency TEXT NOT NULL DEFAULT 'INR',
            merchant_category_code TEXT NOT NULL DEFAULT '',
            mode TEXT NOT NULL DEFAULT ''
        )"""
    )
    connection.execute(
        """CREATE TABLE scan_findings (
            finding_id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
            position INTEGER NOT NULL,
            rule TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            reason TEXT NOT NULL,
            score_impact INTEGER NOT NULL,
            UNIQUE (scan_id, position)
        )"""
    )
    connection.execute("CREATE INDEX scans_by_time ON scans(scanned_at_utc DESC, scan_id DESC)")
    connection.execute("CREATE INDEX scans_by_fingerprint ON scans(fingerprint)")
    connection.execute("CREATE INDEX findings_by_scan_order ON scan_findings(scan_id, position)")


def _validated_scan(report: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(report, dict):
        raise ValueError("A scan report must be a dictionary.")
    score = report.get("trust_score")
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError("Risk score must be an integer between 0 and 100.")
    payload = report.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("Scan report is missing parsed payment metadata.")
    raw = payload.get("raw")
    if not isinstance(raw, str):
        raise ValueError("Scan report is missing the raw input needed to calculate its fingerprint.")
    verdict = report.get("verdict")
    if not isinstance(verdict, str) or not verdict:
        raise ValueError("Scan report is missing a verdict.")
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("Scan report findings must be a list.")

    scan = {
        "fingerprint": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "risk_score": score,
        "verdict": verdict,
        "payee_vpa": _text(payload.get("vpa")),
        "payee_name": _text(payload.get("name")),
        "amount": _optional_text(payload.get("amount")),
        "currency": _text(payload.get("currency")) or "INR",
        "merchant_category_code": _text(payload.get("mc")),
        "mode": _text(payload.get("mode")),
    }
    clean_findings = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("Each scan finding must be a dictionary.")
        impact = finding.get("impact")
        if isinstance(impact, bool) or not isinstance(impact, int):
            raise ValueError("Finding score impact must be an integer.")
        required_text = ("rule", "category", "severity")
        if any(not isinstance(finding.get(key), str) for key in required_text):
            raise ValueError("Each finding must include text rule, category, and severity values.")
        reason = finding.get("reason", finding.get("detail"))
        if not isinstance(reason, str):
            raise ValueError("Each finding must include a text explanation.")
        clean_findings.append({
            "rule": finding["rule"],
            "category": finding["category"],
            "severity": finding["severity"],
            "reason": reason,
            "score_impact": impact,
        })
    return scan, clean_findings


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    return value if isinstance(value, str) else str(value)


def save_scan(report: dict[str, Any], database_path: str | Path | None = None) -> int:
    """Atomically save one scan event and its findings; repeated scans are retained."""
    scan, findings = _validated_scan(report)
    scanned_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    with connect_database(database_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            """INSERT INTO scans (
                scanned_at_utc, fingerprint, risk_score, verdict, payee_vpa,
                payee_name, amount, currency, merchant_category_code, mode
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scanned_at, scan["fingerprint"], scan["risk_score"], scan["verdict"],
                scan["payee_vpa"], scan["payee_name"], scan["amount"], scan["currency"],
                scan["merchant_category_code"], scan["mode"],
            ),
        )
        scan_id = int(cursor.lastrowid)
        connection.executemany(
            """INSERT INTO scan_findings (
                scan_id, position, rule, category, severity, reason, score_impact
            ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [
                (scan_id, position, item["rule"], item["category"], item["severity"],
                 item["reason"], item["score_impact"])
                for position, item in enumerate(findings)
            ],
        )
        connection.commit()
        return scan_id


def get_recent_scans(
    limit: int = 10, database_path: str | Path | None = None
) -> list[dict[str, Any]]:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("History limit must be a positive integer.")
    with connect_database(database_path) as connection:
        rows = connection.execute(
            """SELECT scan_id, scanned_at_utc, fingerprint, risk_score, verdict,
                      payee_vpa, payee_name, amount, currency,
                      merchant_category_code, mode
               FROM scans ORDER BY scanned_at_utc DESC, scan_id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_scan_findings(scan_id: int, database_path: str | Path | None = None) -> list[dict[str, Any]]:
    if isinstance(scan_id, bool) or not isinstance(scan_id, int) or scan_id < 1:
        raise ValueError("Scan ID must be a positive integer.")
    with connect_database(database_path) as connection:
        rows = connection.execute(
            """SELECT finding_id, scan_id, position, rule, category, severity, reason, score_impact
               FROM scan_findings WHERE scan_id = ? ORDER BY position""",
            (scan_id,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_analytics_summary(database_path: str | Path | None = None) -> dict[str, Any]:
    """Return read-only aggregates from persisted scan events and findings."""
    with connect_database(database_path) as connection:
        totals = connection.execute(
            """SELECT COUNT(*) AS total_scans,
                      COUNT(DISTINCT fingerprint) AS unique_fingerprints,
                      COUNT(*) - COUNT(DISTINCT fingerprint) AS repeat_scan_events,
                      (SELECT COUNT(*) FROM (
                           SELECT fingerprint FROM scans GROUP BY fingerprint HAVING COUNT(*) > 1
                       )) AS repeated_fingerprints
               FROM scans"""
        ).fetchone()
        verdicts = connection.execute(
            "SELECT verdict, COUNT(*) AS count FROM scans GROUP BY verdict ORDER BY verdict"
        ).fetchall()
        activity = connection.execute(
            """SELECT substr(scanned_at_utc, 1, 10) AS day_utc, COUNT(*) AS count
               FROM scans GROUP BY day_utc ORDER BY day_utc"""
        ).fetchall()
        severities = connection.execute(
            """SELECT severity, COUNT(*) AS count FROM scan_findings
               GROUP BY severity ORDER BY severity"""
        ).fetchall()
        rules = connection.execute(
            """SELECT rule, COUNT(*) AS count FROM scan_findings
               GROUP BY rule ORDER BY count DESC, rule LIMIT 10"""
        ).fetchall()
        return {
            **dict(totals),
            "verdict_distribution": [dict(row) for row in verdicts],
            "scan_activity": [dict(row) for row in activity],
            "finding_severity": [dict(row) for row in severities],
            "frequent_rules": [dict(row) for row in rules],
        }


def search_scan_history(
    search: str = "", verdict: str | None = None, severity: str | None = None,
    limit: int = 200, database_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Search/filter history while returning only non-payload scan fields."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("History limit must be a positive integer.")
    conditions: list[str] = []
    parameters: list[Any] = []
    if search.strip():
        conditions.append("lower(fingerprint) LIKE ?")
        parameters.append(f"%{search.strip().lower()}%")
    if verdict:
        conditions.append("verdict = ?")
        parameters.append(verdict)
    if severity:
        conditions.append(
            "EXISTS (SELECT 1 FROM scan_findings f WHERE f.scan_id = scans.scan_id AND f.severity = ?)"
        )
        parameters.append(severity)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    parameters.append(limit)
    with connect_database(database_path) as connection:
        rows = connection.execute(
            f"""SELECT scan_id, scanned_at_utc, fingerprint, risk_score, verdict
                FROM scans {where}
                ORDER BY scanned_at_utc DESC, scan_id DESC LIMIT ?""",
            parameters,
        ).fetchall()
        return [dict(row) for row in rows]


def get_scan_summary(scan_id: int, database_path: str | Path | None = None) -> dict[str, Any] | None:
    """Fetch an individual event without returning payment metadata or raw input."""
    if isinstance(scan_id, bool) or not isinstance(scan_id, int) or scan_id < 1:
        raise ValueError("Scan ID must be a positive integer.")
    with connect_database(database_path) as connection:
        row = connection.execute(
            """SELECT scan_id, scanned_at_utc, fingerprint, risk_score, verdict
               FROM scans WHERE scan_id = ?""",
            (scan_id,),
        ).fetchone()
        return dict(row) if row else None


def get_scan_report_data(
    scan_id: int, database_path: str | Path | None = None
) -> dict[str, Any] | None:
    """Read a stored scan and its original ordered findings for a forensic report."""
    if isinstance(scan_id, bool) or not isinstance(scan_id, int) or scan_id < 1:
        raise ValueError("Scan ID must be a positive integer.")
    with connect_database(database_path) as connection:
        row = connection.execute(
            """SELECT scan_id, scanned_at_utc, fingerprint, risk_score, verdict,
                      payee_vpa, payee_name, amount, currency,
                      merchant_category_code, mode
               FROM scans WHERE scan_id = ?""",
            (scan_id,),
        ).fetchone()
        if row is None:
            return None
        report = dict(row)
        findings = connection.execute(
            """SELECT rule, category, severity, reason, score_impact
               FROM scan_findings WHERE scan_id = ? ORDER BY position""",
            (scan_id,),
        ).fetchall()
        report["findings"] = [dict(finding) for finding in findings]
        return report


# ---------------------------------------------------------------------------
# Investigation Workspace queries: read-only, parameterized, no schema change.
# ---------------------------------------------------------------------------

_HEX_DIGITS = frozenset("0123456789abcdef")
_SCAN_COLUMNS = (
    "scan_id, scanned_at_utc, fingerprint, risk_score, verdict, payee_vpa, "
    "payee_name, amount, currency, merchant_category_code, mode"
)


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be a positive integer.")
    return value


def _hex_text(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("Fingerprint text must be a string.")
    cleaned = value.strip().lower()
    if not set(cleaned) <= _HEX_DIGITS:
        raise ValueError("Fingerprints contain only hexadecimal characters (0-9, a-f).")
    return cleaned


def get_fingerprint_summaries(
    search: str = "", limit: int = 200, database_path: str | Path | None = None
) -> list[dict[str, Any]]:
    """One row per distinct fingerprint: scan count and first/last scan time."""
    _positive_int(limit, "History limit")
    cleaned = _hex_text(search)
    where = "WHERE fingerprint LIKE ?" if cleaned else ""
    parameters: list[Any] = [f"%{cleaned}%"] if cleaned else []
    parameters.append(limit)
    with connect_database(database_path) as connection:
        rows = connection.execute(
            f"""SELECT fingerprint, COUNT(*) AS scan_count,
                      MIN(scanned_at_utc) AS first_seen_utc,
                      MAX(scanned_at_utc) AS last_seen_utc
               FROM scans {where}
               GROUP BY fingerprint
               ORDER BY last_seen_utc DESC, fingerprint LIMIT ?""",
            parameters,
        ).fetchall()
        return [dict(row) for row in rows]


def get_scans_for_fingerprint(
    fingerprint: str, limit: int = 200, database_path: str | Path | None = None
) -> list[dict[str, Any]]:
    """Scan events for one full fingerprint, oldest first (the newest `limit` events)."""
    _positive_int(limit, "History limit")
    cleaned = _hex_text(fingerprint)
    if len(cleaned) != 64:
        raise ValueError("A full 64-character SHA-256 fingerprint is required.")
    with connect_database(database_path) as connection:
        rows = connection.execute(
            f"""SELECT {_SCAN_COLUMNS} FROM scans WHERE fingerprint = ?
               ORDER BY scanned_at_utc DESC, scan_id DESC LIMIT ?""",
            (cleaned, limit),
        ).fetchall()
        return [dict(row) for row in reversed(rows)]


def get_payee_groups(
    min_fingerprints: int = 2, limit: int = 50, database_path: str | Path | None = None
) -> list[dict[str, Any]]:
    """Payee addresses (compared case-insensitively) seen under several QR fingerprints."""
    _positive_int(min_fingerprints, "Minimum fingerprint count")
    _positive_int(limit, "Group limit")
    with connect_database(database_path) as connection:
        rows = connection.execute(
            """SELECT lower(payee_vpa) AS payee_key,
                     COUNT(*) AS scan_count,
                     COUNT(DISTINCT fingerprint) AS distinct_fingerprints,
                     COUNT(DISTINCT payee_name) AS distinct_names,
                     COUNT(DISTINCT amount) AS distinct_amounts,
                     MIN(scanned_at_utc) AS first_seen_utc,
                     MAX(scanned_at_utc) AS last_seen_utc
              FROM scans WHERE trim(payee_vpa) <> ''
              GROUP BY lower(payee_vpa)
              HAVING COUNT(DISTINCT fingerprint) >= ?
              ORDER BY distinct_fingerprints DESC, last_seen_utc DESC, payee_key
              LIMIT ?""",
            (min_fingerprints, limit),
        ).fetchall()
        return [dict(row) for row in rows]


def get_scans_for_payee(
    payee_key: str, limit: int = 500, database_path: str | Path | None = None
) -> list[dict[str, Any]]:
    """Scan events whose payee address matches `payee_key` case-insensitively, newest first."""
    _positive_int(limit, "History limit")
    if not isinstance(payee_key, str) or not payee_key.strip():
        raise ValueError("A payee address is required.")
    with connect_database(database_path) as connection:
        rows = connection.execute(
            f"""SELECT {_SCAN_COLUMNS} FROM scans WHERE lower(payee_vpa) = ?
               ORDER BY scanned_at_utc DESC, scan_id DESC LIMIT ?""",
            (payee_key.lower(), limit),
        ).fetchall()
        return [dict(row) for row in rows]
