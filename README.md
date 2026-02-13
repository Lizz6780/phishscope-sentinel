# PhishScope Sentinel
Autonomous phishing triage command center for SOC-style email incident analysis.

## Overview
PhishScope Sentinel is a practical phishing detection and case management project that:
- Parses `.eml` emails
- Extracts URLs and attachment signals
- Applies risk scoring and verdicting
- Maps incidents to MITRE ATT&CK techniques
- Persists incidents to JSON + SQLite
- Provides a polished Streamlit dashboard for analysts

This repository is designed as a portfolio-grade, client-demo-ready project.

## Key Features
- End-to-end phishing pipeline (`main.py`, batch and single-email modes)
- MITRE ATT&CK mapping (`T1566.001`, `T1566.002`)
- Case workflow fields: `New`, `Investigating`, `Old`, `Closed`
- Incident Explorer with owner/notes updates
- CSV export (filtered incidents)
- PDF export (selected incident)
- Upload `.eml` from dashboard and process instantly
- Demo data burst generator for presentations
- Branded UI with customizable logo styles and analyst identity

## Tech Stack
- Python 3.12+
- Streamlit
- Pandas
- Requests
- ReportLab (for PDF export)
- SQLite (built-in `sqlite3`)

## Project Structure
```text
phishing-detection/
├─ dashboard/
│  └─ app.py
├─ detector/
│  ├─ phishing_logic.py
│  └─ pipeline.py
├─ emails/
│  ├─ sample.eml
│  └─ liji_inbox/
├─ intel/
│  ├─ virustotal.py
│  └─ abuseipdb.py
├─ mitre/
│  └─ mapping.py
├─ parsing/
│  ├─ email_parser.py
│  ├─ header_checks.py
│  ├─ url_extractor.py
│  └─ attachment_analysis.py
├─ reports/
│  ├─ incident_writer.py
│  ├─ incident_db.py
│  ├─ exporter.py
│  └─ incidents.db
├─ scoring/
│  └─ risk_engine.py
└─ main.py
```

## Installation
```bash
# from project root
python -m venv venv
source venv/bin/activate   # Linux/WSL/macOS
# venv\Scripts\activate    # Windows PowerShell

pip install streamlit pandas requests reportlab
```

Optional:
```bash
pip install streamlit-autorefresh
```

## Usage
### 1. Process one email
```bash
python main.py --email-path emails/sample.eml
```

### 2. Process a folder in batch mode
```bash
python main.py --batch --email-dir emails/liji_inbox
```

### 3. Launch dashboard
```bash
streamlit run dashboard/app.py
```
Open: `http://localhost:8501`

## Dashboard Highlights
- **Threat Theater** cards for critical workload snapshots
- **Export Center** for one-click CSV download
- **Case Export** for one-click PDF incident report
- **Incident Explorer** for deep triage (URLs, attachments, MITRE, notes)
- **Branding panel** for product name, analyst name, and logo style

## API Key Notes
Threat intel modules use placeholders:
- `intel/virustotal.py`
- `intel/abuseipdb.py`

Without valid keys/network, the app degrades gracefully and continues analysis with safe defaults.

## LinkedIn Showcase Checklist
1. Start dashboard with demo data loaded.
2. Use `Demo Burst` button to generate live incidents.
3. Set branding:
   - Product: `PhishScope Sentinel`
   - Analyst: `Liji Varghese`
   - Logo Style: `LinkedIn Minimal White` or `Neo Monogram`
4. Capture screenshots:
   - Hero + Threat Theater
   - Incident Explorer + Case Management
   - Export buttons (CSV/PDF)

## Roadmap
- Alerting (Telegram/email) for high-severity incidents
- SLA/Aging analytics for case operations
- Tenant mode / multi-client separation
- Docker packaging for one-command deployment

## License
MIT (recommended). Add a `LICENSE` file if you plan to open-source publicly.
