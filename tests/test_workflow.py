"""Regression tests for the Streamlit scan workflow."""

from io import BytesIO
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from PIL import Image
from streamlit.testing.v1 import AppTest
import pytest

import app1
import storage


@pytest.fixture(autouse=True)
def isolated_database(monkeypatch):
    database_path = Path(__file__).with_name(f".workflow-test-{uuid4().hex}.sqlite3")
    monkeypatch.setenv(storage.DATABASE_ENV_VAR, str(database_path))
    try:
        yield database_path
    finally:
        for suffix in ("", "-journal", "-wal", "-shm"):
            Path(str(database_path) + suffix).unlink(missing_ok=True)


def png_bytes() -> bytes:
    image = Image.new("RGB", (2, 2), "white")
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def test_scan_button_gates_manual_analysis_and_reruns_do_not_duplicate_history() -> None:
    app = AppTest.from_file("app1.py").run()
    assert not app.exception
    app.text_area[0].set_value("upi://pay?pa=shop%40oksbi&sign=s").run()

    assert "scan_report" not in app.session_state
    assert len(app.session_state["scan_history"]) == 0

    manual_button = next(button for button in app.button if button.key == "scan_manual")
    manual_button.click().run()
    assert not app.exception
    assert app.session_state["scan_report"]["payload"]["vpa"] == "shop@oksbi"
    assert len(app.session_state["scan_history"]) == 1

    app.run()
    assert not app.exception
    assert len(app.session_state["scan_history"]) == 1
    assert len(storage.get_recent_scans(database_path=storage.default_database_path())) == 1

    app.text_area[0].set_value("upi://pay?pa=another%40oksbi").run()
    assert "scan_report" not in app.session_state
    assert len(app.session_state["scan_history"]) == 1


def test_manual_button_validation_is_live_and_keeps_malformed_inputs_reviewable() -> None:
    app = AppTest.from_file("app1.py").run()
    assert not app.exception
    button = next(button for button in app.button if button.key == "scan_manual")
    assert button.disabled

    app.text_area[0].set_value("   \n\t").run()
    button = next(button for button in app.button if button.key == "scan_manual")
    assert button.disabled
    assert app.session_state["manual_input_valid"] is False

    # The scanner intentionally accepts non-UPI text and reports its format;
    # UI eligibility therefore checks non-empty text, not URI validity.
    app.text_area[0].set_value("not a UPI URI").run()
    button = next(button for button in app.button if button.key == "scan_manual")
    assert not button.disabled
    assert app.session_state["manual_input_valid"] is True

    button.click().run()
    assert not app.exception
    assert app.session_state["scan_report"]["payload"]["raw"] == "not a UPI URI"
    assert len(app.session_state["scan_history"]) == 1


def test_uploaded_payload_is_independent_and_scan_is_button_gated() -> None:
    app = AppTest.from_file("app1.py").run()
    upload = app.get("file_uploader")[0]
    with patch("pyzbar.pyzbar.decode", return_value=[SimpleNamespace(data=b"upi://pay?pa=qr%40oksbi")]):
        upload.set_value(("code.png", png_bytes(), "image/png")).run()

        assert not app.exception
        assert "scan_report" not in app.session_state
        assert app.text_area[0].value == ""

        image_button = next(button for button in app.button if button.key == "scan_uploaded")
        image_button.click().run()

    assert not app.exception
    assert app.session_state["scan_report"]["payload"]["vpa"] == "qr@oksbi"
    assert len(app.session_state["scan_history"]) == 1


def test_camera_control_renders_without_capturing_or_saving_a_scan() -> None:
    app = AppTest.from_file("app1.py").run()

    assert not app.exception
    assert "scan_report" not in app.session_state
    assert len(app.session_state["scan_history"]) == 0
    assert any(button.key == "scan_camera" for button in app.button)


def test_repeated_button_clicks_are_distinct_database_events() -> None:
    app = AppTest.from_file("app1.py").run()
    app.text_area[0].set_value("upi://pay?pa=repeat%40demo.test").run()
    button = next(button for button in app.button if button.key == "scan_manual")
    button.click().run()
    next(button for button in app.button if button.key == "scan_manual").click().run()

    rows = storage.get_recent_scans(database_path=storage.default_database_path())
    assert len(rows) == 2
    assert rows[0]["fingerprint"] == rows[1]["fingerprint"]
    assert len(app.session_state["scan_history"]) == 2

    restarted_app = AppTest.from_file("app1.py").run()
    assert not restarted_app.exception
    assert len(restarted_app.session_state["scan_history"]) == 2
    assert restarted_app.session_state["scan_history"][0]["hash"] == rows[0]["fingerprint"][:12].upper()


def test_current_result_remains_available_when_database_initialization_fails(monkeypatch):
    def fail_initialization(*args, **kwargs):
        raise sqlite3.OperationalError("simulated unavailable database")

    monkeypatch.setattr(storage, "initialize_storage", fail_initialization)
    app = AppTest.from_file("app1.py").run()
    app.text_area[0].set_value("upi://pay?pa=memory%40demo.test").run()
    next(button for button in app.button if button.key == "scan_manual").click().run()

    assert not app.exception
    assert app.session_state["scan_report"]["payload"]["vpa"] == "memory@demo.test"
    assert "not saved to persistent history" in app.session_state["storage_warning"]


def test_malformed_amount_renders_report_without_app_exception() -> None:
    app = AppTest.from_file("app1.py").run()
    app.text_area[0].set_value("upi://pay?pa=shop%40oksbi&am=not-a-number").run()
    next(button for button in app.button if button.key == "scan_manual").click().run()

    assert not app.exception
    assert any(
        finding["rule"] == "Malformed amount field"
        for finding in app.session_state["scan_report"]["findings"]
    )
    assert app1._format_report_amount("not-a-number") == "Invalid amount: not-a-number"


def test_low_severity_wording_finding_is_not_hidden_by_verdict_advice() -> None:
    app = AppTest.from_file("app1.py").run()
    app.text_area[0].set_value("upi://pay?pa=shop%40demo.test&tn=urgent").run()
    next(button for button in app.button if button.key == "scan_manual").click().run()

    report = app.session_state["scan_report"]
    assert report["verdict"] == "NO HIGH-RISK INDICATORS"
    assert any(finding["category"] == "indicator" for finding in report["findings"])
    assert any("Review any listed findings" in item.value for item in app.info)


def test_explanation_displays_warning_severity_impact_and_reason_for_result() -> None:
    app = AppTest.from_file("app1.py").run()
    app.text_area[0].set_value("upi://pay?pa=shop%40demo.test&tn=urgent").run()
    next(button for button in app.button if button.key == "scan_manual").click().run()

    report = app.session_state["scan_report"]
    finding = next(item for item in report["findings"] if item["category"] == "indicator")
    rendered = "\n".join(item.value for item in app.markdown)
    assert finding["severity"] == "LOW"
    assert finding["impact"] == -8
    assert "Warnings and review indicators" in rendered
    assert "What was detected:" in rendered
    assert "Why it matters:" in rendered
    assert "Severity: LOW" in rendered
    assert "Score impact:" in rendered and "−8 points" in rendered
    assert "What to verify or do next:" in rendered
    assert "Potentially concerning wording" in rendered
    assert "Why this result?" in rendered
    assert "largest listed score impacts came from: Potentially concerning wording" in rendered


def test_missing_optional_fields_are_presented_as_information_without_score_penalty() -> None:
    app = AppTest.from_file("app1.py").run()
    app.text_area[0].set_value("upi://pay?pa=shop%40demo.test").run()
    next(button for button in app.button if button.key == "scan_manual").click().run()

    report = app.session_state["scan_report"]
    rendered = "\n".join(item.value for item in app.markdown)
    assert report["trust_score"] == 100
    assert all(item["impact"] == 0 for item in report["info"])
    assert "Informational observations and limitations" in rendered
    assert "Not specified in QR" in rendered
    assert "No finding reduced this rule-based score" in rendered
    assert any("Verify the recipient and amount in your official payment app" in item.value for item in app.info)


def test_untrusted_qr_text_is_escaped_in_html_markdown() -> None:
    hostile_text = "<img src=x onerror=alert(1)>"
    payload = (
        "upi://pay?pa=%3Cimg%20src=x%20onerror=alert%281%29%3E%40example.test"
        "&am=%3Cimg%20src=x%20onerror=alert%281%29%3E"
    )
    app = AppTest.from_file("app1.py").run()
    app.text_area[0].set_value(payload).run()
    next(button for button in app.button if button.key == "scan_manual").click().run()

    assert not app.exception
    unsafe_html_blocks = [
        item.value for item in app.markdown
        if "<span style='font-size:11px" in item.value or '<div style="background:' in item.value
    ]
    assert unsafe_html_blocks
    assert all(hostile_text not in block for block in unsafe_html_blocks)
    assert any("&lt;img" in block for block in unsafe_html_blocks)


def test_unreadable_image_returns_clear_error() -> None:
    image, payload, error = app1.decode_uploaded_qr(BytesIO(b"not an image"))

    assert image is None
    assert payload is None
    assert "not a readable image" in error


def test_image_without_qr_returns_clear_error() -> None:
    with patch("app1.decode", return_value=[]):
        image, payload, error = app1.decode_uploaded_qr(BytesIO(png_bytes()))

    assert image is not None
    assert payload is None
    assert "No QR code detected" in error


def test_camera_capture_uses_shared_decoder_for_valid_image() -> None:
    with patch("app1.decode", return_value=[SimpleNamespace(data=b"upi://pay?pa=cam%40oksbi")]):
        image, payload, error = app1.decode_camera_capture(BytesIO(png_bytes()))

    assert image is not None
    assert payload == "upi://pay?pa=cam%40oksbi"
    assert error is None


def test_camera_capture_reports_invalid_image_and_missing_qr() -> None:
    image, payload, error = app1.decode_camera_capture(BytesIO(b"not an image"))
    assert image is None
    assert payload is None
    assert "not a readable image" in error

    with patch("app1.decode", return_value=[]):
        image, payload, error = app1.decode_camera_capture(BytesIO(png_bytes()))
    assert image is not None
    assert payload is None
    assert "No QR code detected" in error


def test_empty_camera_capture_waits_without_an_error() -> None:
    assert app1.decode_camera_capture(None) == (None, None, None)


def test_non_utf8_qr_returns_clear_error() -> None:
    with patch("app1.decode", return_value=[SimpleNamespace(data=b"\xff")]):
        image, payload, error = app1.decode_uploaded_qr(BytesIO(png_bytes()))

    assert image is not None
    assert payload is None
    assert "cannot be read as UTF-8" in error
