"""Pure-logic tests for the Investigation Workspace plus one real-engine round trip."""

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

import investigation
import storage


@pytest.fixture
def investigation_db():
    path = Path(__file__).with_name(f".investigation-engine-{uuid4().hex}.sqlite3")
    try:
        yield path
    finally:
        for suffix in ("", "-journal", "-wal", "-shm"):
            Path(str(path) + suffix).unlink(missing_ok=True)


def scan(sid, ts, score, verdict, fp="a" * 64, **overrides):
    base = {"scan_id": sid, "scanned_at_utc": ts, "fingerprint": fp, "risk_score": score,
            "verdict": verdict, "payee_vpa": "shop@example.test", "payee_name": "Shop",
            "amount": None, "currency": "INR", "merchant_category_code": "", "mode": ""}
    base.update(overrides)
    return base


def finding(rule, category="indicator", severity="LOW", impact=-8, reason="because"):
    return {"rule": rule, "category": category, "severity": severity, "score_impact": impact, "reason": reason}


def test_mask_vpa():
    assert investigation.mask_vpa("shop@example.test") == "sh***@example.test"
    assert investigation.mask_vpa("a@bank") == "a***@bank"
    assert investigation.mask_vpa("nohandle") == "no***"
    assert investigation.mask_vpa("") == investigation.NOT_PROVIDED
    assert investigation.mask_vpa(None) == investigation.NOT_PROVIDED


def test_evidence_basis_categories():
    assert investigation.evidence_basis({"category": "format"})["label"].startswith("Heuristic")
    assert investigation.evidence_basis({"category": "cannot_verify"})["label"] == "Not verifiable by this app"
    assert investigation.evidence_basis({"category": "observation"})["label"].startswith("Observation")
    assert "unclassified" in investigation.evidence_basis({"category": "something-new"})["label"]
    assert "unclassified" in investigation.evidence_basis({})["label"]


def test_time_helpers():
    assert investigation.format_utc("2026-10-11T10:00:00.123Z") == "2026-10-11 10:00:00 UTC"
    assert investigation.format_utc("garbage") == "garbage"
    assert investigation.format_utc(None) == investigation.NOT_PROVIDED
    assert investigation.format_gap(None) == "—"
    assert investigation.format_gap(0) == "0s"
    assert investigation.format_gap(90) == "1m 30s"
    assert investigation.format_gap(3700) == "1h 1m"
    assert investigation.format_gap(90000) == "1d 1h"


def test_diff_findings_handles_both_shapes():
    engine_shape = {"rule": "R1", "severity": "LOW", "impact": -8, "reason": "x"}
    stored_shape = {"rule": "R1", "severity": "LOW", "score_impact": -8, "reason": "x"}
    diff = investigation.diff_findings([engine_shape], [stored_shape])
    assert len(diff["unchanged"]) == 1 and not diff["changed"]
    diff = investigation.diff_findings(
        [finding("A"), finding("B", reason="old")], [finding("B", reason="new"), finding("C")]
    )
    assert [f["rule"] for f in diff["only_in_a"]] == ["A"]
    assert [f["rule"] for f in diff["only_in_b"]] == ["C"]
    assert [c["rule"] for c in diff["changed"]] == ["B"]


def test_timeline_tracks_changes_between_scans():
    scans = [scan(1, "2026-10-11T10:00:00.000Z", 100, "NO HIGH-RISK INDICATORS"),
             scan(2, "2026-10-11T10:01:30.000Z", 92, "NO HIGH-RISK INDICATORS"),
             scan(3, "2026-10-11T10:02:00.000Z", 100, "NO HIGH-RISK INDICATORS")]
    timeline = investigation.build_timeline(scans, {1: [], 2: [finding("W")], 3: []})
    assert timeline[0]["is_first"] and not timeline[0]["has_changes"]
    assert timeline[1]["added_rules"] == ["W"] and timeline[1]["score_change"] == -8
    assert timeline[1]["seconds_since_previous"] == 90.0
    assert timeline[2]["removed_rules"] == ["W"]
    assert investigation.timeline_overview(scans, timeline)["findings_changed"] is True
    assert investigation.describe_changes(timeline[0]).startswith("First")


def test_timeline_for_identical_scans_reports_no_change():
    scans = [scan(i, f"2026-10-11T10:0{i}:00.000Z", 100, "V") for i in (1, 2)]
    timeline = investigation.build_timeline(scans, {1: [], 2: []})
    assert investigation.describe_changes(timeline[1]) == "No change"
    assert investigation.timeline_overview(scans, timeline)["findings_changed"] is False
    with pytest.raises(ValueError):
        investigation.timeline_overview([], [])


def test_compare_scans_differences_and_masking():
    a = scan(1, "t", 100, "V", fp="a" * 64, amount="125.00", findings=[finding("Pre", "observation", "INFO", 0)])
    b = scan(2, "t", 92, "V", fp="b" * 64, amount="900.00", findings=[finding("Word")])
    result = investigation.compare_scans(a, b)
    by_field = {f["field"]: f for f in result["fields"]}
    assert by_field["amount"]["differs"] and not by_field["payee_vpa"]["differs"]
    assert by_field["payee_vpa"]["scan_a"] == "sh***@example.test"
    assert investigation.compare_scans(a, b, mask_payee=False)["fields"][0]["scan_a"] == "shop@example.test"
    assert result["score_delta"] == -8 and not result["same_fingerprint"]
    assert [f["rule"] for f in result["findings"]["only_in_b"]] == ["Word"]
    assert any("not evidence of tampering" in note for note in result["notes"])


def test_compare_treats_none_and_empty_as_equal_and_flags_same_fingerprint():
    a = scan(1, "t", 100, "V", amount=None, findings=[])
    b = scan(2, "t", 100, "V", amount="", findings=[finding("Late")])
    result = investigation.compare_scans(a, b)
    assert result["differing_field_count"] == 0 and result["same_fingerprint"]
    assert "rules or stored records" in result["notes"][0]


def test_payee_variants():
    scans = [scan(1, "2026-10-11T10:00:00Z", 100, "V", fp="a" * 64, amount="10"),
             scan(2, "2026-10-11T10:05:00Z", 92, "W", fp="b" * 64, amount="20"),
             scan(3, "2026-10-11T10:06:00Z", 92, "W", fp="b" * 64, amount="20")]
    variants = investigation.group_payee_variants(scans)
    assert [v["fingerprint"][0] for v in variants] == ["b", "a"]
    assert variants[0]["scan_count"] == 2 and variants[0]["latest_score"] == 92
    assert investigation.varying_fields(variants) == ["Amount"]


def test_summaries_escape_text_and_respect_privacy():
    scans = [scan(1, "2026-10-11T10:00:00Z", 92, "V")]
    findings = {1: [finding("Rule | one", reason="line1\nline2 | pipe")]}
    when = datetime(2026, 10, 11, tzinfo=timezone.utc)
    text = investigation.build_investigation_summary("a" * 64, scans, findings, generated_at=when)
    assert "sh***@example.test" in text and "shop@example.test" not in text
    assert "line1 line2 \\| pipe" in text and "Rule \\| one" in text
    assert "upi://" not in text and "not calibrated fraud probabilities" in text
    revealed = investigation.build_investigation_summary(
        "a" * 64, scans, findings, reveal_payee=True, generated_at=when)
    assert "shop@example.test" in revealed
    with pytest.raises(ValueError):
        investigation.build_investigation_summary("a" * 64, [], {})


def test_comparison_summary_contents():
    a = scan(1, "2026-10-11T10:00:00Z", 100, "V", fp="a" * 64, findings=[])
    b = scan(2, "2026-10-11T10:01:00Z", 92, "V", fp="b" * 64, findings=[finding("Word")])
    text = investigation.build_comparison_summary(a, b, investigation.compare_scans(a, b))
    assert "# QR Scan Comparison" in text and "Word" in text and "Score change A→B: -8" in text


def test_real_engine_reports_round_trip(investigation_db):
    app1 = pytest.importorskip("app1")
    db = investigation_db
    storage.initialize_storage(db)
    raw = "upi://pay?pa=corner-shop%40example.test&pn=Corner%20Shop&tn=urgent"
    for _ in range(2):
        storage.save_scan(app1.run_risk_engine(app1.parse_upi_payload(raw)), db)
    fingerprint = storage.get_fingerprint_summaries(database_path=db)[0]["fingerprint"]
    scans = storage.get_scans_for_fingerprint(fingerprint, database_path=db)
    findings = {s["scan_id"]: storage.get_scan_findings(s["scan_id"], database_path=db) for s in scans}
    timeline = investigation.build_timeline(scans, findings)
    assert len(scans) == 2 and not timeline[1]["has_changes"]
    assert "Potentially concerning wording" in [f["rule"] for f in findings[scans[0]["scan_id"]]]
    assert "# QR Investigation Summary" in investigation.build_investigation_summary(fingerprint, scans, findings)
