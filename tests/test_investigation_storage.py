"""Storage-level tests for Investigation Workspace queries (temporary SQLite files only)."""

import hashlib
import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest

import storage


def make_report(raw, *, vpa="shop@example.test", name="Shop", amount=None, score=100,
                verdict="NO HIGH-RISK INDICATORS", findings=None):
    return {
        "trust_score": score, "verdict": verdict, "findings": findings or [],
        "payload": {"raw": raw, "vpa": vpa, "name": name, "amount": amount,
                    "currency": "INR", "mc": "", "mode": ""},
    }


def fp(raw):
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@pytest.fixture
def db():
    path = Path(__file__).with_name(f".investigation-storage-{uuid4().hex}.sqlite3")
    storage.initialize_storage(path)
    try:
        yield path
    finally:
        for suffix in ("", "-journal", "-wal", "-shm"):
            Path(str(path) + suffix).unlink(missing_ok=True)


def test_empty_database_returns_empty_results(db):
    assert storage.get_fingerprint_summaries(database_path=db) == []
    assert storage.get_scans_for_fingerprint("a" * 64, database_path=db) == []
    assert storage.get_payee_groups(database_path=db) == []
    assert storage.get_scans_for_payee("x@y", database_path=db) == []


def test_fingerprint_summaries_count_repeats(db):
    storage.save_scan(make_report("raw-one"), db)
    storage.save_scan(make_report("raw-one"), db)
    storage.save_scan(make_report("raw-two"), db)
    counts = {
        row["fingerprint"]: row["scan_count"]
        for row in storage.get_fingerprint_summaries(database_path=db)
    }
    assert counts == {fp("raw-one"): 2, fp("raw-two"): 1}


def test_workspace_storage_api_shapes_and_missing_optional_payee_fields(db):
    """Keep the database result contract aligned with the Investigation UI."""
    required = (
        "get_fingerprint_summaries", "get_scans_for_fingerprint", "get_scan_findings",
        "get_recent_scans", "get_scan_report_data", "get_payee_groups", "get_scans_for_payee",
    )
    assert all(callable(getattr(storage, name, None)) for name in required)

    first_id = storage.save_scan(make_report("raw-one", vpa="", name=None), db)
    storage.save_scan(make_report("raw-one", vpa="", name=None), db)
    summaries = storage.get_fingerprint_summaries(database_path=db)
    assert set(summaries[0]) == {"fingerprint", "scan_count", "first_seen_utc", "last_seen_utc"}
    assert summaries[0]["scan_count"] == 2

    scans = storage.get_scans_for_fingerprint(fp("raw-one"), database_path=db)
    expected_scan_fields = {
        "scan_id", "scanned_at_utc", "fingerprint", "risk_score", "verdict", "payee_vpa",
        "payee_name", "amount", "currency", "merchant_category_code", "mode",
    }
    assert len(scans) == 2
    assert set(scans[0]) == expected_scan_fields
    assert scans[0]["payee_vpa"] == "" and scans[0]["payee_name"] in (None, "")
    assert storage.get_payee_groups(database_path=db) == []
    assert storage.get_scans_for_payee("shop@example.test", database_path=db) == []
    assert storage.get_scan_report_data(first_id, database_path=db)["findings"] == []


def test_fingerprint_search_filters_and_validates(db):
    storage.save_scan(make_report("raw-one"), db)
    storage.save_scan(make_report("raw-two"), db)
    target = fp("raw-one")
    found = storage.get_fingerprint_summaries(search=target[:8].upper(), database_path=db)
    assert [row["fingerprint"] for row in found] == [target]
    for bad in ("%", "zz", "' OR 1=1 --"):
        with pytest.raises(ValueError):
            storage.get_fingerprint_summaries(search=bad, database_path=db)


def test_scans_for_fingerprint_are_chronological_and_validated(db):
    ids = [storage.save_scan(make_report("raw-one"), db) for _ in range(3)]
    storage.save_scan(make_report("raw-two"), db)
    scans = storage.get_scans_for_fingerprint(fp("raw-one").upper(), database_path=db)
    assert [scan["scan_id"] for scan in scans] == ids
    with pytest.raises(ValueError):
        storage.get_scans_for_fingerprint("abc123", database_path=db)
    with pytest.raises(ValueError):
        storage.get_scans_for_fingerprint(fp("raw-one"), limit=0, database_path=db)


def test_payee_groups_use_distinct_fingerprints_case_insensitively(db):
    storage.save_scan(make_report("p1", vpa="Shop@Example.test", amount="10"), db)
    storage.save_scan(make_report("p2", vpa="shop@example.test", amount="20", name="Other"), db)
    storage.save_scan(make_report("p2", vpa="shop@example.test", amount="20"), db)
    storage.save_scan(make_report("solo", vpa="solo@example.test"), db)
    storage.save_scan(make_report("blank", vpa=""), db)
    groups = storage.get_payee_groups(database_path=db)
    assert len(groups) == 1
    group = groups[0]
    assert group["payee_key"] == "shop@example.test"
    assert (group["scan_count"], group["distinct_fingerprints"], group["distinct_amounts"]) == (3, 2, 2)
    assert group["distinct_names"] == 2
    assert len(storage.get_scans_for_payee("SHOP@example.test", database_path=db)) == 3
    with pytest.raises(ValueError):
        storage.get_scans_for_payee("   ", database_path=db)


def test_user_text_is_treated_as_data(db):
    storage.save_scan(make_report("raw-one"), db)
    assert storage.get_scans_for_payee("x' OR '1'='1", database_path=db) == []
    assert len(storage.get_fingerprint_summaries(database_path=db)) == 1


def test_queries_are_read_only_and_schema_is_unchanged(db):
    storage.save_scan(make_report("raw-one"), db)
    storage.get_fingerprint_summaries(database_path=db)
    storage.get_scans_for_fingerprint(fp("raw-one"), database_path=db)
    storage.get_payee_groups(database_path=db)
    storage.get_scans_for_payee("shop@example.test", database_path=db)
    connection = sqlite3.connect(db)
    try:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    finally:
        connection.close()
    assert {"scans", "scan_findings"} <= tables
    assert not any("investig" in name for name in tables)
