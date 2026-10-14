# QRivox — Final Exhibition Rehearsal

Use synthetic examples only. The score is a deterministic rule score, not a fraud probability. “NO HIGH-RISK INDICATORS” does not mean the recipient is verified or the payment is safe.

## Start the app

In PowerShell, from the project folder:

```powershell
Set-Location D:\QR-Safe
python -m streamlit run app1.py
```

Wait for Streamlit's **Local URL** in the terminal and open it in a browser. The usual local address is `http://localhost:8501`. Keep the terminal running during the demo. By default, scan history is stored in `D:\QR-Safe\qr_safe_history.sqlite3`; a configured `QR_SAFE_DATABASE_PATH` changes that location.

## Rehearsal checklist

- [ ] **Manual input:** Open **Manual / Paste**, enter the normal example below, and click **Run Forensic Scan**. Show parsed recipient/amount, findings, score, verdict, and recommendations.
- [ ] **Malformed input:** Replace it with the malformed example below and submit. Confirm a readable finding appears and the app stays open.
- [ ] **Upload:** Open **Scan QR Image**, upload a PNG/JPG containing a QR for the synthetic normal payload, then click **Run Forensic Scan**. Confirm it decodes and shows a report. Try an image without a QR only if time permits; it should show a no-QR message.
- [ ] **Webcam:** In **Scan QR Image**, allow browser camera access, capture a QR, then click **Analyze Captured QR**. The camera feature is implemented, but real webcam/browser permission operation still requires verification on the exhibition laptop. Use manual input or upload as fallback.
- [ ] **Findings:** Show the “Why this result?” summary, warning and information groups, severity, score impact, next step, and the reminder to verify recipient and amount in the official payment app.
- [ ] **History after restart:** Submit a synthetic scan and confirm the persistence notice does not report a write failure. Stop Streamlit with `Ctrl+C`, start it again using the command above, then open **Scan History** and find the event. If a storage warning appeared, that event was not persisted.
- [ ] **Analytics:** Open **Security Analytics** after at least one persisted scan. Confirm it displays saved-event aggregates. Existing database history can affect totals; do not describe counts as fraud rates or accuracy.
- [ ] **PDFs:** Download the current scan PDF below its result. In **Scan History**, select a saved scan and download its historical PDF. Confirm each opens and corresponds to the selected scan. Historical reports use saved findings rather than rescoring them.

## Synthetic test inputs and expected behavior

### Normal-looking payload

```text
upi://pay?pa=shop%40demo.test&pn=Model%20Shop&am=150.00&cu=INR
```

Expected from the current parser and rules: payee address `shop@demo.test`, name `Model Shop`, amount `150.00`, and currency `INR` are available. The valid pre-filled amount is an INFO observation with zero impact. Verification-limit observations are also informational. With no other indicators, the score is 100 and the verdict is **NO HIGH-RISK INDICATORS**. This is not a safety guarantee.

### Malformed amount payload

```text
upi://pay?pa=shop%40demo.test&am=abc
```

Expected from the current rules: the app parses the recipient and reports **Malformed amount field** as a MEDIUM format finding with a −25 impact. With no other negative findings, the resulting score is 75 and the verdict is **REVIEW DETAILS**. The malformed amount is not a verified fraud match; verify the amount before authorizing a payment.

## Equipment and offline readiness

- [ ] Laptop plugged in or charged; presentation screen/projector and display cable tested.
- [ ] Browser installed; Streamlit, Python packages, and QR decoder dependencies already installed before going offline.
- [ ] Sample QR image for the synthetic normal payload available locally; keep the text payload above as a fallback.
- [ ] If demonstrating webcam, camera is available and browser permission is granted. Do not rely on Wi-Fi for the local scan workflow; verify the app starts offline on the actual laptop.
- [ ] Use no real payment account details and do not authorize a payment during the demo.

## What the evidence supports

**Implemented in the source:** manual entry, image upload, browser camera capture path, shared QR image decoder, parser and heuristic findings, scan history in SQLite, analytics, and current/historical PDF report generation. The evaluation script and synthetic dataset are also present.

**Covered by automated tests:** parser and risk behavior; malformed and missing fields; score bounds and informational impacts; manual scan workflow and persistence behavior; image decoder outcomes and camera adapter using mocked QR-decoder results; SQLite storage; analytics; PDF generation/report controls; and synthetic evaluation. The documented latest run in the project report is 64 passed on 2026-10-10. It was not rerun for this documentation task.

**Still needs physical-device verification:** webcam availability and browser permission/capture on the exhibition laptop, scanning a real displayed or printed sample QR through the browser, and confirming browser PDF downloads and persistence after restart on that laptop. Automated camera tests do not establish hardware camera operation.

## 60-second explanation

“QRivox is a local educational prototype for reviewing UPI QR payment details. It accepts pasted payment text or decodes a QR image from an upload or camera capture. It shows fields such as the recipient and amount, then applies simple, explainable rules to flag format problems and a few wording patterns. Each finding includes its severity, score impact, and a suggested next step. The app can save limited scan details and findings in a local SQLite database, summarize saved scans, and create a PDF report for a current or historical scan. The original QR image and raw payload are not stored in scan history. This tool does not verify who owns an account, validate signatures, or guarantee that a payment is safe. Its score is a heuristic, not a probability of fraud. Users must verify the recipient and amount in their official payment app before authorizing payment.”

## Documentation comparison notes

The four existing exhibition documents describe the current source and the previously recorded test/evaluation results consistently. The important qualification is already present: image/camera automated tests use mocked decoding, so they do not prove a physical webcam works. No application or test files were changed, and the test suite was not rerun for this rehearsal document.
