# QRivox — 3-Minute Demo Script

## Before the audience arrives

1. From `D:\QR-Safe`, start the application:

   ```powershell
   python -m streamlit run app1.py
   ```

2. Open the local URL printed by Streamlit (normally `http://localhost:8501`).
3. Confirm the page loads and the manual input tab is available. Do not use real payment details in the demo.
4. If you plan to demonstrate the camera, test webcam permission and a QR image on this laptop and browser in advance. The automated tests do not prove physical camera operation.
5. If you plan to download a PDF, test the browser download button and confirm the PDF opens before the event.

## Timed demonstration

| Time | Exact action | What to say and show |
|---|---|---|
| 0:00–0:20 | Show the app title and tabs. | “QRivox is a local educational prototype. It reads UPI QR payment text and explains a small set of review rules. It does not verify recipients or guarantee safety.” |
| 0:20–0:55 | Open **Manual / Paste**. Paste `upi://pay?pa=shop%40demo.test&pn=Model%20Shop&am=150.00&cu=INR`, then click **Run Forensic Scan**. | Point to the recipient identifier, payee name, amount, score, and verdict. “This synthetic example has a fixed amount. The engine treats that as an informational observation with zero score impact. I still need to verify the displayed recipient and amount in the official payment app.” |
| 0:55–1:35 | Replace the manual text with `upi://pay?pa=shop%40demo.test&pn=Model%20Shop&tn=urgent`, then click **Run Forensic Scan**. | Point to **Warnings and review indicators**, the LOW severity, the −8 point impact, “Why this result?”, and the next step. “The exact word is a weak wording signal. It is not a known malicious-account match or proof of fraud. This is why you should read the finding rather than treating the score as a probability.” |
| 1:35–2:05 | Open **Scan History**, then **Security Analytics**. | Show the recent event and that analytics are based on persisted scans from the same SQLite database. “These are counts of this app’s saved scan events, not fraud rates or accuracy measurements.” Existing history may contain earlier scans, so do not promise exact totals. |
| 2:05–2:35 | Return to the current result and click **Download Digital Forensic Report (PDF)**. If time permits, show the historical report selector in Scan History. | Show the generated report’s scan timestamp, fingerprint, score, verdict, and ordered findings. “Historical reports use the saved scan result; they do not silently rerun today’s rules on an older scan.” |
| 2:35–3:00 | End on the report and summarize limitations. | “The system uses deterministic heuristics and synthetic tests. It has no sourced malicious-account database, does not validate signatures, and does not confirm account ownership. Before payment, verify the recipient and amount in your official payment app.” |

## Optional camera substitution (only after manual verification)

If the webcam works on the presentation laptop, replace the first scan with this camera path:

1. Open **Scan QR Image**.
2. Allow camera permission when the browser prompts.
3. Capture a QR image that encodes a synthetic UPI payload.
4. Click **Analyze Captured QR** and show the same result sections.

The source includes `st.camera_input` and tests cover the camera image adapter and decoder outcomes. The tests do not exercise a physical webcam or browser permission prompt. Keep manual paste as the fallback; do not claim the camera was tested on this device until you perform that check.

## Demo inputs and expected behavior

Normal-looking synthetic payload:

```text
upi://pay?pa=shop%40demo.test&pn=Model%20Shop&am=150.00&cu=INR
```

Expected by the existing rules: score 100; pre-filled amount and verification limitations are INFO findings with zero impact; verdict **NO HIGH-RISK INDICATORS**. This does not mean the recipient is safe or verified.

Wording-indicator synthetic payload:

```text
upi://pay?pa=shop%40demo.test&pn=Model%20Shop&tn=urgent
```

Expected by the existing rules: one LOW wording indicator with −8 impact; score 92; verdict **NO HIGH-RISK INDICATORS**. Explain that the verdict threshold and individual finding are different pieces of information, and the wording may be benign.

