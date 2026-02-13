import io
import json

import pandas as pd


def incidents_to_csv_bytes(df: pd.DataFrame) -> bytes:
    export_df = df.copy()
    for col in ["urls", "attachments", "mitre"]:
        if col in export_df.columns:
            export_df[col] = export_df[col].apply(
                lambda value: json.dumps(value) if isinstance(value, list) else str(value)
            )

    return export_df.to_csv(index=False).encode("utf-8")


def incident_to_pdf_bytes(incident: dict) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.utils import simpleSplit
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise RuntimeError("PDF export requires reportlab. Install with: pip install reportlab") from exc

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    x = 50
    y = height - 50
    line_height = 14

    def write_line(text: str, bold: bool = False):
        nonlocal y
        if y < 60:
            c.showPage()
            y = height - 50
        c.setFont("Helvetica-Bold" if bold else "Helvetica", 10)
        wrapped = simpleSplit(text, "Helvetica", 10, width - 100)
        for row in wrapped:
            c.drawString(x, y, row)
            y -= line_height

    write_line("Phishing Incident Report", bold=True)
    y -= 6
    write_line(f"File: {incident.get('file', 'N/A')}")
    write_line(f"Timestamp: {incident.get('timestamp', 'N/A')}")
    write_line(f"Verdict: {incident.get('verdict', 'N/A')}")
    write_line(f"Severity: {incident.get('severity', 'N/A')}")
    write_line(f"Risk Score: {incident.get('risk_score', 'N/A')}")
    write_line(f"Status: {incident.get('status', 'N/A')}")
    write_line(f"Owner: {incident.get('owner', 'N/A')}")
    write_line(f"Source Email: {incident.get('source_email', 'N/A')}")
    y -= 8

    write_line("URLs", bold=True)
    urls = incident.get("urls", [])
    if urls:
        for u in urls:
            write_line(f"- {u}")
    else:
        write_line("- None")
    y -= 6

    write_line("Attachments", bold=True)
    attachments = incident.get("attachments", [])
    if attachments:
        for a in attachments:
            reasons = ", ".join(a.get("reasons", [])) if isinstance(a, dict) else ""
            if isinstance(a, dict):
                write_line(
                    f"- {a.get('filename', 'unknown')} | suspicious={a.get('suspicious', False)} | {reasons}"
                )
            else:
                write_line(f"- {a}")
    else:
        write_line("- None")
    y -= 6

    write_line("MITRE Mappings", bold=True)
    mitre = incident.get("mitre", [])
    if mitre:
        for m in mitre:
            if isinstance(m, dict):
                write_line(
                    f"- {m.get('technique', 'Unknown')} | {m.get('name', 'Unknown')} ({m.get('tactic', 'Unknown')})"
                )
            else:
                write_line(f"- {m}")
    else:
        write_line("- None")
    y -= 6

    notes = incident.get("notes", "")
    write_line("Analyst Notes", bold=True)
    write_line(notes if notes else "- None")

    c.save()
    return buffer.getvalue()
