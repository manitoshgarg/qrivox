"""Tests for PDF reports generated from current and persisted scan results."""

from io import BytesIO
from pathlib import Path
from uuid import uuid4

import pytest
from pypdf import PdfReader
from streamlit.testing.v1 import AppTest

import app1
import forensic_report
import storage


@pytest.fixture
def database_path(monkeypatch):
    path = Path(__file__).with_name(f".report-test-{uuid4().hex}.sqlite3")
    monkeypatch.setenv(storage.DATABASE_ENV_VAR, str(path))
    try:
        storage.initialize_storage(path)
        yield path
    finally:
        for suffix in ("", "-journal", "-wal", "-shm"):
            Path(str(path) + suffix).unlink(missing_ok=True)


def make_report(raw):
    return app1.run_risk_engine(app1.parse_upi_payload(raw))


def pdf_text(pdf_bytes):
    return "\n".join(page.extract_text() or "" for page in PdfReader(BytesIO(pdf_bytes)).pages)


def test_persisted_report_has_scan_metadata_findings_and_does_not_mutate_history(database_path):
    report = make_report(
        "upi://pay?pa=merchant%40demo.test&pn=Caf%C3%A9&am=42.50&cu=INR&mc=5411"
        "&tn=private-report-note&tr=private-reference&sign=private-signature"
    )
    scan_id = storage.save_scan(report, database_path)
    before = storage.get_recent_scans(database_path=database_path)
    record = storage.get_scan_report_data(scan_id, database_path)
    pdf_bytes, report_id = forensic_report.generate_pdf_report(record)
    after = storage.get_recent_scans(database_path=database_path)

    content = " ".join(pdf_text(pdf_bytes).split())
    assert pdf_bytes.startswith(b"%PDF-")
    assert "QRivox" in content
    assert len(PdfReader(BytesIO(pdf_bytes)).pages[0].images) == 1
    assert report_id in content
    assert record["fingerprint"] in content
    assert "Café" in content
    assert "42.50" in content
    assert report["verdict"] in content
    assert "Recipient identity not verified" in content
    assert "Informational observation" in content
    assert "not a calibrated probability of fraud" in content
    assert "does not independently verify the recipient" in content
    assert "private-report-note" not in content
    assert "private-reference" not in content
    assert "private-signature" not in content
    assert len(after) == len(before) == 1
    assert [item["rule"] for item in record["findings"]] == [
        item["rule"] for item in report["findings"]
    ]


def test_current_report_handles_unicode_long_findings_and_page_breaks():
    current = make_report("upi://pay?pa=shop%40demo.test&pn=na%C3%AFve")
    current["findings"] = [
        {
            "rule": "Unicode review — café",
            "category": "indicator",
            "severity": "LOW",
            "impact": -8,
            "reason": "नमस्ते café " + ("A long explanation. " * 800),
        }
    ]
    projected = forensic_report.current_scan_data(current)
    pdf_bytes, _ = forensic_report.generate_pdf_report(projected)
    reader = PdfReader(BytesIO(pdf_bytes))
    content = "\n".join(page.extract_text() or "" for page in reader.pages)

    assert len(reader.pages) > 1
    assert "naïve" in content
    assert "café" in content
    assert "नमस्ते" in content
    assert "Suspicious indicator; not a verified match" in content


def test_report_handles_missing_metadata_and_empty_findings():
    pdf_bytes, _ = forensic_report.generate_pdf_report({
        "risk_score": 100,
        "verdict": "NO HIGH-RISK INDICATORS",
        "findings": [],
    })
    content = pdf_text(pdf_bytes)
    assert "Not available" in content
    assert "No findings were recorded for this scan" in content


def test_report_generation_errors_are_explicit():
    with pytest.raises(forensic_report.ReportGenerationError, match="could not be generated"):
        forensic_report.generate_pdf_report({"risk_score": 101, "findings": []})


def test_unicode_without_a_local_unicode_font_is_preserved_as_codepoint_text(monkeypatch):
    monkeypatch.setattr(forensic_report, "_font_name", lambda: "Helvetica")
    pdf_bytes, _ = forensic_report.generate_pdf_report({
        "risk_score": 100,
        "verdict": "REVIEW",
        "payee_name": "नमस्ते",
        "findings": [],
    })
    assert r"\u0928\u092e\u0938" in pdf_text(pdf_bytes)


def test_scan_results_and_persisted_history_show_download_buttons(database_path):
    app = AppTest.from_file("app1.py").run(timeout=10)
    app.text_area[0].set_value("upi://pay?pa=merchant%40demo.test&pn=Shop").run()
    next(button for button in app.button if button.key == "scan_manual").click().run(timeout=10)
    assert not app.exception
    download_buttons = [element for element in app if element.type == "download_button"]
    assert any("Digital Forensic Report" in button.label for button in download_buttons)
    assert len(storage.get_recent_scans(database_path=database_path)) == 1

    # The history tab renders its report selector and the same download action.
    assert any("Choose a persisted scan" in item.label for item in app.selectbox)
    assert len(download_buttons) >= 2
    assert len(storage.get_recent_scans(database_path=database_path)) == 1
