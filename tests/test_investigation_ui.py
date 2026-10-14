"""Integration checks for Investigation Workspace rendering against temporary history."""

from pathlib import Path
from uuid import uuid4

from streamlit.testing.v1 import AppTest

import investigation_ui
import storage


def _report(raw: str, amount: str) -> dict:
    return {
        "trust_score": 100,
        "verdict": "NO HIGH-RISK INDICATORS",
        "findings": [],
        "payload": {
            "raw": raw,
            "vpa": "shop@example.test",
            "name": "Example Shop",
            "amount": amount,
            "currency": "INR",
            "mc": "",
            "mode": "",
        },
    }


def test_workspace_renders_all_views_and_refreshes_a_stale_storage_import(monkeypatch):
    database = Path(__file__).with_name(f".investigation-ui-{uuid4().hex}.sqlite3")
    monkeypatch.setenv(storage.DATABASE_ENV_VAR, str(database))
    storage.initialize_storage(database)
    storage.save_scan(_report("upi://pay?pa=shop%40example.test&am=10", "10"), database)
    storage.save_scan(_report("upi://pay?pa=shop%40example.test&am=20", "20"), database)

    try:
        # Simulate a long-lived Streamlit process whose imported module predates
        # the new workspace queries. The UI should refresh the same module object.
        monkeypatch.delattr(storage, "get_fingerprint_summaries")
        app = AppTest.from_file("app1.py").run()
        assert not app.exception
        assert callable(storage.get_fingerprint_summaries)
        assert any("QR timeline" in str(radio.options) for radio in app.radio)

        for view in investigation_ui._VIEWS:
            view_radio = next(radio for radio in app.radio if "QR timeline" in str(radio.options))
            view_radio.set_value(view)
            app.run()
            assert not app.exception, f"Investigation view failed to render: {view}"
            assert not any("could not read persistent history" in warning.value for warning in app.warning)
    finally:
        for suffix in ("", "-journal", "-wal", "-shm"):
            Path(str(database) + suffix).unlink(missing_ok=True)
