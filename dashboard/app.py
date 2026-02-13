from pathlib import Path
import json
import sys
from datetime import UTC, datetime
import random
from urllib.parse import quote

import pandas as pd
import streamlit as st

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from reports.incident_db import (
    bootstrap_from_json_reports,
    list_incidents,
    update_incident_workflow,
)
from reports.exporter import incident_to_pdf_bytes, incidents_to_csv_bytes
from detector.pipeline import process_email
from reports.incident_writer import write_incident


st.set_page_config(
    page_title="Phishing SOC Dashboard",
    page_icon="shield",
    layout="wide",
)

st.markdown(
    """
    <style>
    :root {
        --bg: #f8fbff;
        --card: #ffffff;
        --ink: #1f2937;
        --muted: #64748b;
        --accent: #4f46e5;
        --ok: #15803d;
        --warn: #b45309;
        --bad: #b91c1c;
        --lavender: #ecebff;
        --mint: #e8f8ef;
        --peach: #fff1e8;
        --sky: #eaf4ff;
    }

    .stApp {
        background:
            radial-gradient(circle at 10% 10%, #eaf4ff 0%, transparent 34%),
            radial-gradient(circle at 90% 5%, #fff1e8 0%, transparent 28%),
            linear-gradient(180deg, #fcfdff 0%, #f4f8ff 100%);
        color: var(--ink);
        font-family: "Times New Roman", Times, serif !important;
    }

    .stApp * {
        font-family: "Times New Roman", Times, serif !important;
    }

    @keyframes drift {
        0% { transform: translateY(0px); }
        50% { transform: translateY(-6px); }
        100% { transform: translateY(0px); }
    }

    .block-container {
        padding-top: 1.2rem;
        padding-bottom: 2rem;
    }

    .hero {
        background: linear-gradient(135deg, #c7d2fe 0%, #dbeafe 45%, #fde7f3 100%);
        color: #1e293b;
        border-radius: 16px;
        padding: 1.2rem 1.4rem;
        margin-bottom: 1rem;
        border: 1px solid #dbe4ff;
        box-shadow: 0 8px 20px rgba(148, 163, 184, 0.16);
    }
    .hero-top {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 1rem;
    }
    .hero-brand {
        display: flex;
        align-items: center;
        gap: 0.7rem;
    }
    .hero-logo {
        width: 44px;
        height: 44px;
        border-radius: 10px;
        border: 1px solid #c7d2fe;
        object-fit: cover;
        background: #ffffff;
    }
    .hero-product {
        font-size: 0.88rem;
        color: #4338ca;
        letter-spacing: 0.03em;
        margin: 0;
    }
    .hero-analyst {
        font-size: 0.83rem;
        color: #475569;
        margin: 0;
    }

    .hero h1 {
        margin: 0;
        font-size: 1.6rem;
        font-weight: 700;
    }

    .hero p {
        margin: 0.3rem 0 0;
        color: #475569;
        font-size: 0.95rem;
    }

    .hero-strip {
        margin-top: 0.8rem;
        display: inline-block;
        font-size: 0.78rem;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: #4338ca;
        background: #eef2ff;
        border: 1px solid #c7d2fe;
        border-radius: 999px;
        padding: 0.22rem 0.62rem;
    }

    .badge {
        display: inline-block;
        border-radius: 999px;
        padding: 0.2rem 0.65rem;
        font-size: 0.78rem;
        font-weight: 700;
        margin-right: 0.4rem;
        margin-bottom: 0.35rem;
    }

    .badge-high { background: #ffe8ec; color: #9f1239; border: 1px solid #fecdd3; }
    .badge-critical { background: #ffe4f0; color: #831843; border: 1px solid #f9a8d4; }
    .badge-medium { background: #fff4e6; color: #9a3412; border: 1px solid #fed7aa; }
    .badge-low { background: #eaf9f0; color: #166534; border: 1px solid #bbf7d0; }
    .badge-phishing { background: #ffe8ec; color: #9f1239; border: 1px solid #fecdd3; }
    .badge-suspicious { background: #fff4e6; color: #9a3412; border: 1px solid #fed7aa; }
    .badge-legit { background: #eaf9f0; color: #166534; border: 1px solid #bbf7d0; }

    .url-card {
        background: #fdfdff;
        border: 1px solid #e3e9f8;
        border-radius: 12px;
        padding: 0.65rem 0.8rem;
        margin-bottom: 0.5rem;
    }
    .url-card a {
        text-decoration: none;
        color: #4338ca;
        font-weight: 600;
        word-break: break-all;
    }
    .url-card:hover {
        border-color: #c7d2fe;
        box-shadow: 0 6px 14px rgba(99, 102, 241, 0.12);
        transform: translateY(-1px);
        transition: all 0.2s ease;
    }

    .insight {
        background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
        border: 1px solid #e3e9f8;
        border-radius: 12px;
        padding: 0.7rem 0.9rem;
        box-shadow: 0 4px 12px rgba(148, 163, 184, 0.12);
        animation: drift 6s ease-in-out infinite;
    }
    .insight .label {
        color: #64748b;
        font-size: 0.82rem;
        margin-bottom: 0.2rem;
    }
    .insight .value {
        color: #1e293b;
        font-size: 1.02rem;
        font-weight: 700;
    }

    div[data-testid="stMetric"] {
        background: linear-gradient(180deg, #ffffff 0%, #f7faff 100%);
        border: 1px solid #e2e8f6;
        border-radius: 12px;
        padding: 0.35rem 0.5rem;
        box-shadow: 0 3px 10px rgba(148, 163, 184, 0.12);
    }

    div[data-testid="stDataFrame"] {
        border: 1px solid #e3e9f8;
        border-radius: 12px;
        overflow: hidden;
    }

    .ops-card {
        background: linear-gradient(140deg, #ffffff 0%, #f6f9ff 100%);
        border: 1px solid #dae5ff;
        border-radius: 14px;
        padding: 0.9rem 1rem;
        box-shadow: 0 10px 18px rgba(99, 102, 241, 0.08);
    }
    .ops-card .kicker {
        color: #4f46e5;
        font-size: 0.75rem;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        margin-bottom: 0.2rem;
    }
    .ops-card .big {
        color: #0f172a;
        font-size: 1.15rem;
        font-weight: 700;
    }
    .section-title {
        margin-top: 0.2rem;
        margin-bottom: 0.35rem;
        color: #1e293b;
        font-size: 1.28rem;
        font-weight: 700;
        letter-spacing: 0.01em;
    }
    .footer-signature {
        margin-top: 1.2rem;
        padding: 0.7rem 0.9rem;
        border: 1px solid #dbe5ff;
        background: linear-gradient(180deg, #ffffff 0%, #f6f9ff 100%);
        border-radius: 12px;
        color: #475569;
        text-align: center;
        font-size: 0.88rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def load_incidents() -> pd.DataFrame:
    reports_dir = Path(__file__).resolve().parents[1] / "reports"
    bootstrap_from_json_reports(reports_dir)
    rows = list_incidents()

    # Backward compatibility: if DB is empty, load legacy JSON reports.
    if not rows:
        files = sorted(reports_dir.glob("incident_*.json"))
        for file_path in files:
            with file_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
                data["id"] = None
                data["file"] = file_path.name
                data["status"] = data.get("status", "New")
                data["owner"] = data.get("owner", "")
                data["notes"] = data.get("notes", "")
                rows.append(data)

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    else:
        df["timestamp"] = pd.NaT

    if "urls" not in df.columns:
        df["urls"] = [[] for _ in range(len(df))]
    if "attachments" not in df.columns:
        df["attachments"] = [[] for _ in range(len(df))]
    if "mitre" not in df.columns:
        df["mitre"] = [[] for _ in range(len(df))]
    if "status" not in df.columns:
        df["status"] = "New"
    if "owner" not in df.columns:
        df["owner"] = ""
    if "notes" not in df.columns:
        df["notes"] = ""

    df["urls"] = df["urls"].apply(lambda value: value if isinstance(value, list) else [])
    df["attachments"] = df["attachments"].apply(
        lambda value: value if isinstance(value, list) else []
    )
    df["mitre"] = df["mitre"].apply(lambda value: value if isinstance(value, list) else [])
    df = df.sort_values(by="timestamp", ascending=False).reset_index(drop=True)
    return df


def render_badge(label: str, kind: str) -> None:
    st.markdown(
        f'<span class="badge badge-{kind}">{label}</span>',
        unsafe_allow_html=True,
    )


def refresh_controls() -> None:
    st.sidebar.subheader("Live")
    auto_refresh = st.sidebar.toggle("Auto-refresh", value=True)
    interval_sec = st.sidebar.slider("Refresh interval (sec)", 5, 120, 20, 5)

    if not auto_refresh:
        return

    try:
        from streamlit_autorefresh import st_autorefresh

        st_autorefresh(interval=interval_sec * 1000, key="soc_autorefresh")
        st.sidebar.caption("Auto-refresh is active.")
    except Exception:
        st.sidebar.warning(
            "Install `streamlit-autorefresh` to enable timed refresh:\n"
            "`pip install streamlit-autorefresh`"
        )


def generate_demo_burst(count: int, target_email: str, product_name: str):
    sample_urls = [
        "https://secure-mail-auth-check.example/reset",
        "https://payroll-verify-now.example/confirm",
        "https://sharepoint-login-check.example/session",
        "https://invoice-review-portal.example/validate",
    ]
    sample_techniques = [
        {"tactic": "Initial Access", "technique": "T1566.002", "name": "Spearphishing Link"},
        {"tactic": "Initial Access", "technique": "T1566.001", "name": "Spearphishing Attachment"},
    ]

    generated = []
    for i in range(count):
        risk = random.randint(25, 96)
        if risk >= 81:
            severity = "CRITICAL"
            verdict = "PHISHING"
        elif risk >= 61:
            severity = "HIGH"
            verdict = "PHISHING"
        elif risk >= 31:
            severity = "MEDIUM"
            verdict = "SUSPICIOUS"
        else:
            severity = "LOW"
            verdict = "LEGIT"

        status = random.choice(["New", "Investigating", "Old", "Closed"])
        urls = random.sample(sample_urls, k=random.randint(1, min(2, len(sample_urls))))
        has_attachment = random.choice([True, False])
        attachments = []
        if has_attachment:
            attachments.append(
                {
                    "filename": random.choice(["invoice_copy.pdf.exe", "salary_patch.xlsm", "doc_view.js"]),
                    "content_type": "application/octet-stream",
                    "size_bytes": random.randint(1024, 24576),
                    "suspicious": True,
                    "reasons": ["suspicious_extension"],
                }
            )

        incident = {
            "verdict": verdict,
            "risk_score": risk,
            "severity": severity,
            "status": status,
            "owner": "",
            "notes": f"Auto-generated showcase incident #{i + 1} for {product_name}",
            "source_email": f"demo_mail_{i + 1}@{target_email.split('@')[-1]}",
            "urls": urls,
            "attachments": attachments,
            "mitre": sample_techniques[: 2 if has_attachment else 1],
            "timestamp": datetime.now(UTC).isoformat(),
        }
        generated.append(write_incident(incident))

    return generated


def monogram_logo_data_uri(full_name: str, style: str = "Neo Monogram") -> str:
    parts = [p for p in full_name.strip().split() if p]
    if not parts:
        initials = "LV"
    elif len(parts) == 1:
        initials = parts[0][:2].upper()
    else:
        initials = f"{parts[0][0]}{parts[-1][0]}".upper()

    if style == "LinkedIn Minimal White":
        svg = f"""
        <svg xmlns='http://www.w3.org/2000/svg' width='64' height='64' viewBox='0 0 64 64'>
          <rect x='2' y='2' width='60' height='60' rx='16' fill='#0a2540'/>
          <rect x='4' y='4' width='56' height='56' rx='14' fill='none' stroke='#ffffff' stroke-opacity='0.2'/>
          <path d='M20 20 L20 44 L32 44' fill='none' stroke='#ffffff' stroke-width='3.1' stroke-linecap='round' stroke-linejoin='round'/>
          <path d='M32 20 L44 44 L44 20' fill='none' stroke='#ffffff' stroke-width='3.1' stroke-linecap='round' stroke-linejoin='round'/>
        </svg>
        """
    elif style == "Neo Monogram":
        svg = f"""
        <svg xmlns='http://www.w3.org/2000/svg' width='64' height='64' viewBox='0 0 64 64'>
          <defs>
            <linearGradient id='bg' x1='0' y1='0' x2='1' y2='1'>
              <stop offset='0%' stop-color='#0b1f3a'/>
              <stop offset='100%' stop-color='#0b5cab'/>
            </linearGradient>
            <linearGradient id='line' x1='0' y1='0' x2='1' y2='1'>
              <stop offset='0%' stop-color='#93c5fd'/>
              <stop offset='100%' stop-color='#60a5fa'/>
            </linearGradient>
          </defs>
          <rect x='2' y='2' width='60' height='60' rx='16' fill='url(#bg)'/>
          <rect x='4' y='4' width='56' height='56' rx='14' fill='none' stroke='#60a5fa' stroke-opacity='0.38'/>
          <path d='M19 21 L19 44 L30 44' fill='none' stroke='url(#line)' stroke-width='3.2' stroke-linecap='round' stroke-linejoin='round'/>
          <path d='M31 21 L43 44 L45 44 L45 21' fill='none' stroke='url(#line)' stroke-width='3.2' stroke-linecap='round' stroke-linejoin='round'/>
          <circle cx='50' cy='15' r='2' fill='#67e8f9' fill-opacity='0.9'/>
        </svg>
        """
    elif style == "Sentinel Emblem":
        svg = f"""
        <svg xmlns='http://www.w3.org/2000/svg' width='64' height='64' viewBox='0 0 64 64'>
          <defs>
            <linearGradient id='g1' x1='0' y1='0' x2='1' y2='1'>
              <stop offset='0%' stop-color='#0b1f3a'/>
              <stop offset='100%' stop-color='#0b5cab'/>
            </linearGradient>
            <linearGradient id='g2' x1='0' y1='0' x2='1' y2='1'>
              <stop offset='0%' stop-color='#22d3ee'/>
              <stop offset='100%' stop-color='#60a5fa'/>
            </linearGradient>
          </defs>
          <rect x='2' y='2' width='60' height='60' rx='14' fill='url(#g1)'/>
          <path d='M32 9 L49 15 L49 30 C49 41 41 50 32 54 C23 50 15 41 15 30 L15 15 Z' fill='none' stroke='url(#g2)' stroke-width='1.8'/>
          <circle cx='32' cy='31' r='8' fill='none' stroke='white' stroke-opacity='0.85' stroke-width='1.4'/>
          <path d='M22 31 A10 10 0 0 1 42 31' fill='none' stroke='#c7d2fe' stroke-opacity='0.75' stroke-width='1.2'/>
          <text x='32' y='38.5' text-anchor='middle' font-family='Times New Roman, serif' font-size='15.5' font-weight='700' fill='white'>{initials}</text>
        </svg>
        """
    elif style == "Classic Crest":
        svg = f"""
        <svg xmlns='http://www.w3.org/2000/svg' width='64' height='64' viewBox='0 0 64 64'>
          <defs>
            <linearGradient id='g' x1='0' y1='0' x2='1' y2='1'>
              <stop offset='0%' stop-color='#1d4ed8'/>
              <stop offset='100%' stop-color='#1d4ed8'/>
            </linearGradient>
          </defs>
          <path d='M32 4 L54 12 L54 31 C54 45 44 55 32 60 C20 55 10 45 10 31 L10 12 Z' fill='url(#g)'/>
          <path d='M32 9 L50 15 L50 31 C50 42 42 50 32 55 C22 50 14 42 14 31 L14 15 Z' fill='none' stroke='#c7d2fe' stroke-width='1.5'/>
          <text x='32' y='39' text-anchor='middle' font-family='Times New Roman, serif' font-size='23' font-weight='700' fill='white'>{initials}</text>
        </svg>
        """
    elif style == "Outline":
        svg = f"""
        <svg xmlns='http://www.w3.org/2000/svg' width='64' height='64' viewBox='0 0 64 64'>
          <rect x='4' y='4' width='56' height='56' rx='14' fill='#ffffff'/>
          <rect x='5.5' y='5.5' width='53' height='53' rx='13' fill='none' stroke='#1d4ed8' stroke-width='2'/>
          <circle cx='32' cy='32' r='21' fill='none' stroke='#c7d2fe' stroke-width='1.4'/>
          <text x='32' y='39' text-anchor='middle' font-family='Times New Roman, serif' font-size='23' font-weight='700' fill='#1d4ed8'>{initials}</text>
        </svg>
        """
    elif style == "Minimal":
        svg = f"""
        <svg xmlns='http://www.w3.org/2000/svg' width='64' height='64' viewBox='0 0 64 64'>
          <defs>
            <linearGradient id='g' x1='0' y1='0' x2='1' y2='1'>
              <stop offset='0%' stop-color='#2563eb'/>
              <stop offset='100%' stop-color='#0ea5e9'/>
            </linearGradient>
          </defs>
          <rect x='2' y='2' width='60' height='60' rx='14' fill='url(#g)'/>
          <rect x='3' y='3' width='58' height='58' rx='13' fill='none' stroke='#c7d2fe' stroke-opacity='0.55'/>
          <text x='32' y='40' text-anchor='middle' font-family='Times New Roman, serif' font-size='24' font-weight='700' fill='white'>{initials}</text>
        </svg>
        """
    else:
        svg = f"""
        <svg xmlns='http://www.w3.org/2000/svg' width='64' height='64' viewBox='0 0 64 64'>
          <rect x='4' y='4' width='56' height='56' rx='12' fill='#312e81'/>
          <text x='32' y='39' text-anchor='middle' font-family='Times New Roman, serif' font-size='24' font-weight='700' fill='white'>{initials}</text>
        </svg>
        """
    return "data:image/svg+xml;utf8," + quote(" ".join(svg.split()))


df = load_incidents()

if df.empty:
    st.markdown(
        """
        <div class="hero">
            <h1>PhishScope Sentinel Command Center</h1>
            <p>No incident reports found yet. Run <code>python main.py</code> to generate incidents.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.stop()


st.markdown(
    """
    <div class="hero">
        <div class="hero-top">
            <div class="hero-brand">
                {logo_html}
                <div>
                    <p class="hero-product">{product_name}</p>
                    <h1>Autonomous Phishing Triage Command Center</h1>
                    <p>Case-centric email threat detection, ATT&amp;CK mapping, and analyst workflow orchestration.</p>
                </div>
            </div>
            <div style="text-align:right;">
                <p class="hero-analyst">Prepared by: <b>{analyst_name}</b></p>
                <div class="hero-strip">LinkedIn Showcase • SOC Engineering</div>
            </div>
        </div>
    </div>
    """.format(
        logo_html=(
            f'<img class="hero-logo" src="{st.session_state.get("brand_logo_url", "")}" alt="logo" />'
            if st.session_state.get("brand_logo_url", "")
            else f'<img class="hero-logo" src="{monogram_logo_data_uri(st.session_state.get("brand_analyst_name", "Liji Varghese"), st.session_state.get("brand_logo_style", "Neo Monogram"))}" alt="logo" />'
        ),
        product_name=st.session_state.get("brand_product_name", "PhishScope Sentinel"),
        analyst_name=st.session_state.get("brand_analyst_name", "Liji Varghese"),
    ),
    unsafe_allow_html=True,
)

st.sidebar.header("Filters")
refresh_controls()
st.sidebar.subheader("Branding")
st.session_state["brand_product_name"] = st.sidebar.text_input(
    "Product Name",
    value=st.session_state.get("brand_product_name", "PhishScope Sentinel"),
)
st.session_state["brand_analyst_name"] = st.sidebar.text_input(
    "Analyst Name",
    value=st.session_state.get("brand_analyst_name", "Liji Varghese"),
)
st.session_state["brand_logo_url"] = st.sidebar.text_input(
    "Logo URL (optional)",
    value=st.session_state.get("brand_logo_url", ""),
)
st.session_state["brand_logo_style"] = st.sidebar.selectbox(
    "Logo Style",
    ["Neo Monogram", "LinkedIn Minimal White", "Sentinel Emblem", "Classic Crest", "Outline", "Minimal"],
    index=["Neo Monogram", "LinkedIn Minimal White", "Sentinel Emblem", "Classic Crest", "Outline", "Minimal"].index(
        st.session_state.get("brand_logo_style", "Neo Monogram")
        if st.session_state.get("brand_logo_style", "Neo Monogram")
        in ["Neo Monogram", "LinkedIn Minimal White", "Sentinel Emblem", "Classic Crest", "Outline", "Minimal"]
        else "Neo Monogram"
    ),
)

st.sidebar.subheader("Ingest Email")
uploaded = st.sidebar.file_uploader("Upload .eml", type=["eml"])
if uploaded is not None:
    uploads_dir = ROOT_DIR / "emails" / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)

    upload_name = (
        f"upload_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S_%f')}_{uploaded.name}"
    )
    upload_path = uploads_dir / upload_name

    with upload_path.open("wb") as handle:
        handle.write(uploaded.getvalue())

    incident_path = process_email(str(upload_path))
    st.sidebar.success(f"Processed and saved: {Path(incident_path).name}")
    st.rerun()

st.sidebar.subheader("Demo Burst")
demo_target = st.sidebar.text_input(
    "Victim Email ID",
    value="liji@liiji.local",
)
demo_count = st.sidebar.slider("Incident Count", 3, 30, 8, 1)
if st.sidebar.button("Generate Demo Data Burst", use_container_width=True):
    burst = generate_demo_burst(
        demo_count,
        demo_target,
        st.session_state.get("brand_product_name", "PhishScope Sentinel"),
    )
    st.sidebar.success(f"Generated {len(burst)} demo incidents.")
    st.rerun()

base_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
seen_severities = [str(s).upper() for s in df["severity"].dropna().unique().tolist()]
all_severities = base_severities + [s for s in seen_severities if s not in base_severities]
all_verdicts = sorted(df["verdict"].dropna().unique().tolist())
base_statuses = ["New", "Investigating", "Old", "Closed"]
seen_statuses = [str(s) for s in df["status"].dropna().unique().tolist()]
all_statuses = base_statuses + [s for s in seen_statuses if s not in base_statuses]

severity_filter = st.sidebar.multiselect("Severity", all_severities, default=all_severities)
verdict_filter = st.sidebar.multiselect("Verdict", all_verdicts, default=all_verdicts)
status_filter = st.sidebar.multiselect("Status", all_statuses, default=all_statuses)

date_min = df["timestamp"].dropna().min()
date_max = df["timestamp"].dropna().max()

if pd.isna(date_min) or pd.isna(date_max):
    filtered = df[
        (df["severity"].isin(severity_filter))
        & (df["verdict"].isin(verdict_filter))
        & (df["status"].isin(status_filter))
    ].copy()
else:
    date_range = st.sidebar.date_input(
        "Date range",
        value=(date_min.date(), date_max.date()),
        min_value=date_min.date(),
        max_value=date_max.date(),
    )

    if isinstance(date_range, tuple) and len(date_range) == 2:
        start_date, end_date = date_range
    else:
        start_date = date_range
        end_date = date_range

    filtered = df[
        (df["timestamp"].dt.date >= start_date)
        & (df["timestamp"].dt.date <= end_date)
        & (df["severity"].isin(severity_filter))
        & (df["verdict"].isin(verdict_filter))
        & (df["status"].isin(status_filter))
    ].copy()

if filtered.empty:
    st.warning("No incidents match the active filters.")
    st.stop()

critical_count = int((filtered["severity"] == "CRITICAL").sum())
old_count = int((filtered["status"] == "Old").sum())
suspicious_attachment_count = 0
for attachments in filtered["attachments"]:
    for item in attachments:
        if isinstance(item, dict) and item.get("suspicious", False):
            suspicious_attachment_count += 1

theater1, theater2, theater3 = st.columns(3)
with theater1:
    st.markdown(
        f"""
        <div class="ops-card">
            <div class="kicker">Threat Theater</div>
            <div class="big">{critical_count} Critical Incidents</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
with theater2:
    st.markdown(
        f"""
        <div class="ops-card">
            <div class="kicker">Workflow Pressure</div>
            <div class="big">{old_count} Cases marked Old</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
with theater3:
    st.markdown(
        f"""
        <div class="ops-card">
            <div class="kicker">Attachment Risk</div>
            <div class="big">{suspicious_attachment_count} Suspicious Files</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.write("")

top_severity = filtered["severity"].value_counts().idxmax()
top_verdict = filtered["verdict"].value_counts().idxmax()
top_technique = "None"
techniques_flat = []
for entries in filtered["mitre"]:
    for item in entries:
        if isinstance(item, dict):
            techniques_flat.append(item.get("technique", "Unknown"))
if techniques_flat:
    top_technique = pd.Series(techniques_flat).value_counts().idxmax()

ins1, ins2, ins3 = st.columns(3)
with ins1:
    st.markdown(
        f'<div class="insight"><div class="label">Dominant Severity</div><div class="value">{top_severity}</div></div>',
        unsafe_allow_html=True,
    )
with ins2:
    st.markdown(
        f'<div class="insight"><div class="label">Most Common Verdict</div><div class="value">{top_verdict}</div></div>',
        unsafe_allow_html=True,
    )
with ins3:
    st.markdown(
        f'<div class="insight"><div class="label">Top MITRE Technique</div><div class="value">{top_technique}</div></div>',
        unsafe_allow_html=True,
    )

st.write("")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Incidents", int(len(filtered)))
col2.metric("Open Cases", int((filtered["status"] != "Closed").sum()))
col3.metric("Phishing Verdicts", int((filtered["verdict"] == "PHISHING").sum()))
col4.metric("Average Risk", round(float(filtered["risk_score"].mean()), 1))

export_csv = incidents_to_csv_bytes(filtered)
st.markdown('<div class="section-title">Export Center</div>', unsafe_allow_html=True)
exp_col1, exp_col2 = st.columns([1.2, 1])
with exp_col1:
    st.download_button(
        "Download Filtered Incidents (CSV)",
        data=export_csv,
        file_name=f"incidents_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
        use_container_width=True,
    )
with exp_col2:
    st.info(
        "PDF export is available in Incident Explorer for the selected case."
    )

st.divider()

trend_col, severity_col = st.columns([2, 1])

with trend_col:
    st.subheader("Incident Trend")
    trend = (
        filtered.dropna(subset=["timestamp"])
        .assign(day=lambda frame: frame["timestamp"].dt.date)
        .groupby("day")
        .size()
        .rename("incidents")
    )
    if trend.empty:
        st.info("No timestamp data available for trend chart.")
    else:
        st.line_chart(trend)

with severity_col:
    st.subheader("Severity Mix")
    sev = (
        filtered["severity"]
        .value_counts()
        .reindex(["LOW", "MEDIUM", "HIGH", "CRITICAL"], fill_value=0)
        .rename_axis("severity")
        .to_frame("count")
    )
    st.bar_chart(sev)

st.divider()

left, right = st.columns([1, 1])

with left:
    st.subheader("MITRE Technique Coverage")
    techniques = []
    for entries in filtered["mitre"]:
        for item in entries:
            if isinstance(item, dict):
                techniques.append(item.get("technique", "Unknown"))

    if techniques:
        mitre_df = (
            pd.Series(techniques, name="technique")
            .value_counts()
            .rename_axis("technique")
            .to_frame("count")
        )
        st.bar_chart(mitre_df)
    else:
        st.info("No MITRE techniques mapped in selected incidents.")

with right:
    st.subheader("Recent Incidents")
    table_df = filtered[
        ["file", "timestamp", "severity", "verdict", "status", "owner", "risk_score"]
    ].copy()
    table_df["timestamp"] = table_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S UTC")

    def color_row(row):
        sev = str(row.get("severity", "")).upper()
        if sev == "CRITICAL":
            color = "#ffeaf4"
        elif sev == "HIGH":
            color = "#fff0f3"
        elif sev == "MEDIUM":
            color = "#fff8ee"
        else:
            color = "#effcf4"
        return [f"background-color: {color}"] * len(row)

    styled = (
        table_df.style.apply(color_row, axis=1)
        .set_properties(**{"border": "1px solid #e7ecf8"})
    )
    st.dataframe(styled, use_container_width=True, hide_index=True)

st.divider()

st.subheader("Incident Explorer")
choices = filtered["id"].tolist() if filtered["id"].notna().any() else filtered["file"].tolist()
selected_key = st.selectbox(
    "Select incident",
    choices,
    format_func=(
        lambda key: filtered[filtered["id"] == key].iloc[0]["file"]
        if filtered["id"].notna().any()
        else str(key)
    ),
)

if filtered["id"].notna().any():
    incident = filtered[filtered["id"] == selected_key].iloc[0].to_dict()
else:
    incident = filtered[filtered["file"] == selected_key].iloc[0].to_dict()

detail_a, detail_b = st.columns([1, 1])
with detail_a:
    verdict_value = str(incident.get("verdict", "Unknown")).upper()
    severity_value = str(incident.get("severity", "Unknown")).upper()

    verdict_kind_map = {
        "PHISHING": "phishing",
        "SUSPICIOUS": "suspicious",
        "LEGIT": "legit",
    }
    severity_kind_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    severity_kind_map["CRITICAL"] = "critical"

    render_badge(
        f"Verdict: {verdict_value}",
        verdict_kind_map.get(verdict_value, "suspicious"),
    )
    render_badge(
        f"Severity: {severity_value}",
        severity_kind_map.get(severity_value, "medium"),
    )
    st.write(f"Status: **{incident.get('status', 'New')}**")
    st.write(f"Owner: **{incident.get('owner', '-') or '-'}**")
    st.write(f"Risk score: **{incident.get('risk_score', 0)}**")
with detail_b:
    st.write(f"Timestamp: **{incident.get('timestamp', 'Unknown')}**")
    st.write(f"URL count: **{len(incident.get('urls', []))}**")
    st.write(f"Attachment count: **{len(incident.get('attachments', []))}**")
    st.write(f"MITRE entries: **{len(incident.get('mitre', []))}**")
    if incident.get("source_email"):
        st.write(f"Source: **{incident.get('source_email')}**")

st.markdown("#### Case Management")
if incident.get("id") is not None:
    workflow_col1, workflow_col2 = st.columns([1, 1])
    with workflow_col1:
        status_options = ["New", "Investigating", "Old", "Closed"]
        new_status = st.selectbox(
            "Status",
            status_options,
            index=status_options.index(
                incident.get("status", "New")
                if incident.get("status", "New") in status_options
                else "New"
            ),
            key=f"status_{incident['id']}",
        )
        new_owner = st.text_input(
            "Owner",
            value=incident.get("owner", ""),
            key=f"owner_{incident['id']}",
        )
    with workflow_col2:
        new_notes = st.text_area(
            "Analyst Notes",
            value=incident.get("notes", ""),
            height=120,
            key=f"notes_{incident['id']}",
        )

    if st.button("Save Case Update", use_container_width=True):
        update_incident_workflow(int(incident["id"]), new_status, new_owner, new_notes)
        st.success("Case updated.")
        st.rerun()
else:
    st.caption("Case management is available for incidents stored in SQLite.")

st.markdown('<div class="section-title">Case Export</div>', unsafe_allow_html=True)
try:
    pdf_bytes = incident_to_pdf_bytes(incident)
    st.download_button(
        "Download Selected Incident (PDF)",
        data=pdf_bytes,
        file_name=f"{incident.get('file', 'incident')}.pdf",
        mime="application/pdf",
        use_container_width=True,
    )
except RuntimeError as exc:
    st.info(str(exc))

st.markdown(
    """
    <div class="footer-signature">
        Crafted for executive-ready phishing triage demonstrations • Times New Roman Edition
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown("#### URLs")
urls = incident.get("urls", [])
if urls:
    for url in urls:
        safe_url = str(url)
        st.markdown(
            f'<div class="url-card"><a href="{safe_url}" target="_blank">{safe_url}</a></div>',
            unsafe_allow_html=True,
        )
else:
    st.caption("No URLs found in this incident.")

st.markdown("#### Attachments")
attachments = incident.get("attachments", [])
if attachments:
    attachment_rows = []
    for item in attachments:
        filename = item.get("filename", "unknown")
        suspicious = bool(item.get("suspicious", False))
        reasons = item.get("reasons", [])
        attachment_rows.append(
            {
                "filename": filename,
                "content_type": item.get("content_type", "unknown"),
                "size_bytes": item.get("size_bytes", 0),
                "suspicious": "Yes" if suspicious else "No",
                "reasons": ", ".join(reasons) if reasons else "-",
            }
        )
    st.dataframe(
        pd.DataFrame(attachment_rows),
        use_container_width=True,
        hide_index=True,
    )
else:
    st.caption("No attachments found in this incident.")

st.markdown("#### MITRE Mappings")
mitre_entries = incident.get("mitre", [])
if mitre_entries:
    mitre_rows = []
    for m in mitre_entries:
        if isinstance(m, dict):
            mitre_rows.append(
                {
                    "tactic": m.get("tactic", "Unknown"),
                    "technique": m.get("technique", "Unknown"),
                    "name": m.get("name", "Unknown"),
                }
            )
    st.dataframe(pd.DataFrame(mitre_rows), use_container_width=True, hide_index=True)
else:
    st.caption("No MITRE mappings for this incident.")

with st.expander("Raw Incident JSON"):
    st.json(incident)
