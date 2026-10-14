"""SQLite persistence and failure handling tests using isolated temp files."""

import sqlite3
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import pytest

import app1
import storage


@pytest.fixture
def database_path():
    path = Path(__file__).with_name(f".storage-test-{uuid4().hex}.sqlite3")
    try:
        yield path
    finally:
        for candidate in (
            path,
            Path(str(path) + "-journal"),
            Path(str(path) + "-wal"),
            Path(str(path) + "-shm"),
            Path(str(path) + ".directory"),
            Path(str(path) + ".invalid"),
        ):
            if candidate.is_dir():
                candidate.rmdir()
            else:
                candidate.unlink(missing_ok=True)


@pytest.fixture
def sample_report():
    raw = (
        "upi://pay?pa=shop%40demo.test&pn=Sample%20Shop&am=12.50&cu=INR"
        "&mc=5411&mode=00&tn=private-note&tr=ref-secret&sign=sig-secret"
    )
    return app1.run_risk_engine(app1.parse_upi_payload(raw))


def test_schema_creation_and_repeated_initialization(database_path):
    storage.initialize_storage(database_path)
    storage.initialize_storage(database_path)

    with storage.connect_database(database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == storage.SCHEMA_VERSION
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert {"scans", "scan_findings"} <= tables
        indexes = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }
        assert {"scans_by_time", "scans_by_fingerprint", "findings_by_scan_order"} <= indexes


def test_version_zero_database_migrates_and_future_version_is_rejected(database_path):
    with storage.connect_database(database_path) as connection:
        connection.execute("PRAGMA user_version = 0")
    storage.initialize_storage(database_path)
    with storage.connect_database(database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        connection.execute("PRAGMA user_version = 99")

    with pytest.raises(storage.StorageError, match="newer than supported"):
        storage.initialize_storage(database_path)


def test_saves_scan_and_ordered_findings_and_reads_from_new_connection(
    database_path, sample_report
):
    storage.initialize_storage(database_path)
    scan_id = storage.save_scan(sample_report, database_path)

    # Each public read opens a separate connection.
    saved_scan = storage.get_recent_scans(database_path=database_path)[0]
    findings = storage.get_scan_findings(scan_id, database_path)
    assert saved_scan["scan_id"] == scan_id
    assert saved_scan["risk_score"] == sample_report["trust_score"]
    assert saved_scan["verdict"] == sample_report["verdict"]
    assert saved_scan["payee_vpa"] == "shop@demo.test"
    assert saved_scan["payee_name"] == "Sample Shop"
    assert saved_scan["amount"] == "12.50"
    assert saved_scan["currency"] == "INR"
    assert saved_scan["merchant_category_code"] == "5411"
    assert [item["position"] for item in findings] == list(range(len(findings)))
    assert [item["rule"] for item in findings] == [item["rule"] for item in sample_report["findings"]]
    info_findings = [item for item in findings if item["severity"] == "INFO"]
    assert info_findings
    assert all(item["score_impact"] == 0 for item in info_findings)
    timestamp = datetime.fromisoformat(saved_scan["scanned_at_utc"].replace("Z", "+00:00"))
    assert timestamp.utcoffset().total_seconds() == 0


def test_same_fingerprint_is_kept_as_separate_scan_events(database_path, sample_report):
    storage.initialize_storage(database_path)
    first_id = storage.save_scan(sample_report, database_path)
    second_id = storage.save_scan(sample_report, database_path)

    rows = storage.get_recent_scans(limit=10, database_path=database_path)
    assert first_id != second_id
    assert len(rows) == 2
    assert rows[0]["fingerprint"] == rows[1]["fingerprint"]


def test_invalid_scores_are_rejected_before_write(database_path, sample_report):
    storage.initialize_storage(database_path)
    for score in (-1, 101, 50.5, True):
        report = {**sample_report, "trust_score": score}
        with pytest.raises(ValueError, match="between 0 and 100"):
            storage.save_scan(report, database_path)
    assert storage.get_recent_scans(database_path=database_path) == []


def test_findings_write_rolls_back_scan_atomically(database_path, sample_report):
    storage.initialize_storage(database_path)
    with storage.connect_database(database_path) as connection:
        connection.execute(
            """CREATE TRIGGER fail_findings BEFORE INSERT ON scan_findings
               BEGIN SELECT RAISE(ABORT, 'simulated finding write failure'); END"""
        )

    with pytest.raises(sqlite3.IntegrityError, match="simulated finding write failure"):
        storage.save_scan(sample_report, database_path)
    assert storage.get_recent_scans(database_path=database_path) == []


def test_foreign_keys_are_enforced(database_path):
    storage.initialize_storage(database_path)
    with storage.connect_database(database_path) as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO scan_findings
                   (scan_id, position, rule, category, severity, reason, score_impact)
                   VALUES (999, 0, 'test', 'info', 'INFO', 'test', 0)"""
            )


def test_initialization_read_and_write_failures_are_reported(database_path):
    path_is_directory = Path(str(database_path) + ".directory")
    path_is_directory.mkdir()
    with pytest.raises(sqlite3.OperationalError):
        storage.initialize_storage(path_is_directory)

    malformed_database = Path(str(database_path) + ".invalid")
    malformed_database.write_text("not sqlite", encoding="utf-8")
    with pytest.raises(sqlite3.DatabaseError):
        storage.get_recent_scans(database_path=malformed_database)
    with pytest.raises(sqlite3.DatabaseError):
        storage.save_scan(sample_report_for_failure(), malformed_database)


def sample_report_for_failure():
    return app1.run_risk_engine(
        app1.parse_upi_payload("upi://pay?pa=shop%40demo.test")
    )


def test_prohibited_raw_and_sensitive_fields_are_not_stored(database_path, sample_report):
    storage.initialize_storage(database_path)
    storage.save_scan(sample_report, database_path)
    stored = storage.get_recent_scans(database_path=database_path)
    findings = storage.get_scan_findings(stored[0]["scan_id"], database_path)

    assert "private-note" not in repr(stored) + repr(findings)
    assert "ref-secret" not in repr(stored) + repr(findings)
    assert "sig-secret" not in repr(stored) + repr(findings)
    assert "upi://pay?" not in repr(stored) + repr(findings)
    assert "transaction_note" not in stored[0]
    assert "transaction_reference" not in stored[0]
