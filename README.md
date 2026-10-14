# QRivox

![QRivox logo](assets/qrivox_logo.png)

QRivox is a local Streamlit prototype for reviewing UPI QR payloads with deterministic, rule-based indicators. Its score is not a fraud probability and does not verify recipient identity.

## Local scan-history database

The app stores persistent scan history in `qr_safe_history.sqlite3` beside `app1.py`. Set `QR_SAFE_DATABASE_PATH` to use a different local SQLite file. The database is created and migrated automatically when the app starts.

Stored scan fields include a UTC timestamp, full SHA-256 fingerprint, rule-based score, verdict, payee VPA and name, amount, currency, MCC, and mode. Findings are stored separately with their rule, category, severity, explanation, and score impact. Each scan-button click is a separate event, including repeated scans of the same QR.

The app does not store raw QR payloads, QR images, transaction notes, signatures, or transaction references. The VPA and payee name can still identify a recipient. The SQLite file is local and unencrypted, so anyone who can read that file can see its stored fields. A deterministic fingerprint is not encryption and may be guessable for predictable QR payloads. Scan history is not threat-intelligence data and does not establish that any account is malicious.

If SQLite cannot be opened or written, the app continues the scan and keeps its result in the current Streamlit session. It displays a warning when that scan was not persisted; session-only results do not survive an app restart.

## Run tests

From the project directory, run:

```powershell
python -m pytest -q tests
```

Storage tests use temporary SQLite files and do not read or modify the app's persistent history database.

## Security Analytics

The **Security Analytics** tab reads the same local SQLite scan history used by Scan History; it does not create a separate database or add records. It summarizes scan events, distinct QR fingerprints, repeated events, verdicts, UTC daily activity, finding severities, and frequently recorded rules. Search uses a full or partial SHA-256 fingerprint, and history can be filtered by verdict and finding severity. Selecting a row shows that scan's stored timestamp, fingerprint, score, verdict, and ordered findings.

Analytics displays only aggregate results and the limited scan details needed for review. It does not display raw QR payloads, transaction notes, signature values, transaction references, payee names, or payee addresses. These are counts of this app's recorded outcomes, not evidence of fraud rates, detection accuracy, or recipient legitimacy. An empty database has an informational state; a database read failure disables analytics with a warning while leaving scan controls available.

## Digital Forensic Reports

After a scan, use **Download Digital Forensic Report (PDF)** below the result. The Scan History section also lets you select a persisted scan and download a report. Historical reports use the scan metadata and original ordered findings already saved in SQLite; they do not rerun the current risk engine or add/update scan records. Reports are generated in memory with a unique report ID and download filename.

Reports include the full QR fingerprint and stored payment fields, but omit raw QR payloads, images, transaction notes, signatures, and transaction references. The analysis is automated, its score is not a calibrated fraud probability, and it does not independently verify the recipient or guarantee transaction safety. Suspicious indicators are not presented as verified malicious-account matches. Install the listed `reportlab` dependency with the rest of `requirements.txt` to enable PDF downloads.

## Synthetic detection evaluation

Run `python evaluate_engine.py` to evaluate the current parser and heuristic findings against `evaluation_dataset.json`. The dataset contains only synthetic example payloads and scenario labels. Labels describe expected format or review-indicator behavior; they are not confirmed fraud labels or evidence about real recipients. The summary shows each expected/predicted category, the engine verdict, correct/incorrect scenario classifications, grouped scenario results, and false-positive/false-negative counts for the explicitly labeled **review signal** only. These results do not measure real-world fraud detection accuracy. The evaluator is read-only and does not use or alter SQLite scan history.

Run the complete test suite with `python -m pytest -q -p no:cacheprovider tests`.
