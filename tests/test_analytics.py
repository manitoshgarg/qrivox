"""Read-only analytics query and dashboard behavior tests."""

import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest
from streamlit.testing.v1 import AppTest

import app1
import storage


@pytest.fixture
def database_path(monkeypatch):
    path = Path(__file__).with_name(f".analytics-test-{uuid4().hex}.sqlite3")
    monkeypatch.setenv(storage.DATABASE_ENV_VAR, str(path))
    try:
        storage.initialize_storage(path)
        yield path
    finally:
        for suffix in ("", "-journal", "-wal", "-shm"):
            Path(str(path) + suffix).unlink(missing_ok=True)


def report(raw):
    return app1.run_risk_engine(app1.parse_upi_payload(raw))


def test_aggregates_count_events_unique_and_repeated_fingerprints(database_path):
    ordinary = report("upi://pay?pa=shop%40demo.test&pn=Shop")
    suspicious = report("upi://pay?pa=helpdesk%40demo.test&pn=Urgent")
    storage.save_scan(ordinary, database_path)
    storage.save_scan(ordinary, database_path)
    storage.save_scan(suspicious, database_path)

    summary = storage.get_analytics_summary(database_path)
    assert summary["total_scans"] == 3
    assert summary["unique_fingerprints"] == 2
    assert summary["repeat_scan_events"] == 1
    assert summary["repeated_fingerprints"] == 1
    assert sum(item["count"] for item in summary["verdict_distribution"]) == 3
    assert sum(item["count"] for item in summary["scan_activity"]) == 3
    assert sum(item["count"] for item in summary["finding_severity"]) > 0
    assert summary["frequent_rules"]


def test_empty_history_returns_zero_metrics_and_empty_chart_data(database_path):
    summary = storage.get_analytics_summary(database_path)
    assert summary["total_scans"] == 0
    assert summary["unique_fingerprints"] == 0
    assert summary["repeat_scan_events"] == 0
    assert summary["repeated_fingerprints"] == 0
    for key in ("verdict_distribution", "scan_activity", "finding_severity", "frequent_rules"):
        assert summary[key] == []


def test_analytics_api_contract_matches_dashboard_expectations(database_path):
    summary = storage.get_analytics_summary(database_path)
    assert set(summary) == {
        "total_scans", "unique_fingerprints", "repeat_scan_events", "repeated_fingerprints",
        "verdict_distribution", "scan_activity", "finding_severity", "frequent_rules",
    }
    assert all(callable(getattr(storage, name, None)) for name in (
        "get_analytics_summary", "search_scan_history", "get_scan_summary", "get_scan_findings"
    ))


def test_history_search_verdict_and_severity_filters(database_path):
    ordinary = report("upi://pay?pa=shop%40demo.test")
    suspicious = report("upi://pay?pa=urgent%40demo.test&pn=Urgent")
    ordinary_id = storage.save_scan(ordinary, database_path)
    suspicious_id = storage.save_scan(suspicious, database_path)

    matched = storage.search_scan_history(
        search=next(row["fingerprint"][:10] for row in storage.get_recent_scans(database_path=database_path)
                    if row["scan_id"] == suspicious_id),
        verdict=suspicious["verdict"], severity="LOW", database_path=database_path,
    )
    assert [row["scan_id"] for row in matched] == [suspicious_id]
    assert storage.search_scan_history(search="not-a-fingerprint", database_path=database_path) == []
    assert storage.get_scan_summary(ordinary_id, database_path)["scan_id"] == ordinary_id
    assert set(storage.get_scan_summary(ordinary_id, database_path)) == {
        "scan_id", "scanned_at_utc", "fingerprint", "risk_score", "verdict"
    }


def test_malformed_database_read_failure_is_reported(database_path):
    broken = Path(str(database_path) + ".broken")
    try:
        broken.write_text("not a sqlite database", encoding="utf-8")
        with pytest.raises(sqlite3.DatabaseError):
            storage.get_analytics_summary(broken)
        with pytest.raises(sqlite3.DatabaseError):
            storage.search_scan_history(database_path=broken)
    finally:
        broken.unlink(missing_ok=True)


def test_dashboard_shows_empty_state_and_handles_database_read_failure(monkeypatch, database_path):
    empty_app = AppTest.from_file("app1.py").run()
    assert not empty_app.exception
    assert any("No persisted scans yet" in item.value for item in empty_app.info)

    def fail_read(*args, **kwargs):
        raise sqlite3.OperationalError("simulated read failure")

    monkeypatch.setattr(storage, "get_analytics_summary", fail_read)
    failed_app = AppTest.from_file("app1.py").run()
    assert not failed_app.exception
    assert any("Security analytics is unavailable" in item.value for item in failed_app.warning)


def test_dashboard_renders_persisted_analytics_and_scan_findings(database_path):
    scan_id = storage.save_scan(
        report("upi://pay?pa=review%40demo.test&pn=Urgent"), database_path
    )
    app = AppTest.from_file("app1.py").run(timeout=10)

    assert not app.exception
    assert any("Scan events" == metric.label and metric.value == "1" for metric in app.metric)
    assert any("Inspect a scan" in item.label for item in app.selectbox)
    assert any(f"Scan #{scan_id}" in item.value for item in app.markdown)
    assert len(app.dataframe) >= 2
    assert any(
        item["rule"] == "Recipient identity not verified"
        for item in storage.get_scan_findings(scan_id, database_path)
    )


def test_dashboard_recovers_when_streamlit_has_a_stale_storage_module(monkeypatch, database_path):
    monkeypatch.delattr(storage, "get_analytics_summary")
    app = AppTest.from_file("app1.py").run(timeout=10)

    assert not app.exception
    assert any("No persisted scans yet" in item.value for item in app.info)
    assert callable(storage.get_analytics_summary)
