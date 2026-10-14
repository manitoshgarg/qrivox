# QRivox — Likely Judge Questions

### 1. What problem does the project address?

Payment QR codes can contain recipient and amount information that a payer should review. This prototype makes selected QR contents visible and explains a few format or wording signals before a user proceeds to a payment app.

### 2. What does the application actually do?

It accepts pasted UPI text or decodes an image supplied by upload or the Streamlit camera control, parses fields, runs deterministic checks, displays findings and recommendations, and can store limited scan metadata in SQLite. It also includes analytics, PDF reports, and a synthetic evaluation script.

### 3. What is novel about the project?

It is an educational integration of QR decoding, explainable rule output, local persistence, analytics, and historical reporting. It is not a new QR standard or a novel fraud-detection algorithm, and I do not claim scientific novelty or measured fraud reduction.

### 4. How is the QR code decoded?

Pillow opens the image and `pyzbar` calls the ZBar QR decoder. Camera captures and uploaded images use the same image-decoding function. The resulting text is passed to the same parser used by manual input.

### 5. What information is extracted?

The parser reads fields such as payee address (`pa`), payee name (`pn`), amount (`am`), currency (`cu`), transaction reference, note, merchant category code, mode, and signature text when present. Some fields are displayed only in the full metadata view; not all are stored.

### 6. What rules does the risk engine use?

It checks UPI URI structure, whether a payee address has an `@` separator, duplicate parameters, amount validity, exact whole-word matches from a configured keyword list, and HTTP/HTTPS text in payment metadata. It also reports verification limitations as zero-impact informational findings.

### 7. How is the score calculated?

The engine starts at 100, subtracts configured negative finding impacts, and clamps the score to 0–100. A single wording match currently deducts 8 points; valid pre-filled amounts and informational observations deduct zero. The score is deterministic but is not a calibrated probability of fraud.

### 8. Does a “suspicious” finding mean the recipient is fraudulent?

No. Wording and URL checks are review signals, not evidence of account ownership or verified fraud. Format errors identify payload problems, not necessarily malicious intent. There is no sourced malicious-account database.

### 9. Are missing optional fields treated as fraud?

No. A minimal payload with a payee address and no optional name, amount, or reference does not receive a score penalty. The result still reminds the user to check the recipient and amount in the payment app.

### 10. Does the application verify a recipient, bank account, or QR signature?

No. A familiar VPA, MCC, or signature field is just QR-provided text here. The app does not connect to a bank, payment network, identity service, or signature-validation service. It does not claim NPCI certification.

### 11. What is stored in SQLite?

Each scan event stores its UTC timestamp, full SHA-256 fingerprint, score, verdict, VPA, payee name, amount, currency, MCC, and mode. Its findings are stored in order with rule, category, severity, explanation, and score impact. Repeated scans remain separate events.

### 12. What privacy protections and limitations exist?

Raw QR payload text, image bytes, notes, transaction references, and signature values are not stored in SQLite. The VPA and name are stored and can identify a recipient. The local database is unencrypted; the active session keeps the report and raw input available for current processing/display. The fingerprint is not encryption.

### 13. What does the analytics dashboard show?

It aggregates persisted scan events, distinct and repeated fingerprints, verdict distribution, activity by date, finding severity, and frequently triggered rules. Users can search/filter history and inspect a scan. These aggregates do not establish fraud rates or detection accuracy.

### 14. What testing and evaluation have been completed?

The latest test run on 2026-10-10 reported 64 passed. It covers parser/risk behavior, workflow, storage, analytics, PDF generation, and evaluator output. The separate synthetic evaluator classified 7 of 7 scenario categories as expected, with 5 true-positive and 2 true-negative review-signal counts and zero false-positive/false-negative counts. The dataset is small and synthetic; these numbers are not real-world fraud metrics. Camera decoding tests use a mocked QR decoder.

### 15. Is it ready for real-world use, and what would you improve next?

It is a local exhibition prototype, not a production payment-security service. Before any real deployment, I would need a representative, independently verified dataset, measured error rates, broader URI and image testing, a responsibly sourced threat-data process if one were appropriate, privacy/security review, and manual tests on supported devices. I would also verify the webcam permission flow on the actual exhibition laptop. No bank verification, guaranteed detection, or official certification is claimed.

