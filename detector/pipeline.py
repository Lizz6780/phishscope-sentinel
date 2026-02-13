from datetime import UTC, datetime

from detector.phishing_logic import extract_urls, phishing_decision
from intel.abuseipdb import check_ip
from intel.virustotal import check_url
from mitre.mapping import map_to_mitre
from parsing.attachment_analysis import analyze_attachments
from parsing.email_parser import parse_email
from parsing.header_checks import analyze_headers
from reports.incident_writer import write_incident
from scoring.risk_engine import calculate_risk


def severity_from_risk(risk: float) -> str:
    if risk >= 81:
        return "CRITICAL"
    if risk >= 61:
        return "HIGH"
    if risk >= 31:
        return "MEDIUM"
    return "LOW"


def process_email(email_path: str) -> str:
    headers, body, msg = parse_email(email_path)
    attachments = analyze_attachments(msg)

    header_findings = analyze_headers(headers)
    urls = extract_urls(body)

    url_results = [check_url(u) for u in urls]
    url_malicious = any(r["malicious"] for r in url_results)

    sender_ip = "8.8.8.8"
    ip_score = check_ip(sender_ip)

    findings = {
        **header_findings,
        "urls": urls,
        "url_malicious": url_malicious,
        "ip_abuse_score": ip_score,
        "attachment_suspicious": any(
            item.get("suspicious", False) for item in attachments if isinstance(item, dict)
        ),
    }

    risk = calculate_risk(findings)
    mitre = map_to_mitre(findings, attachments)
    verdict = phishing_decision(risk)

    incident = {
        "verdict": verdict,
        "risk_score": risk,
        "severity": severity_from_risk(risk),
        "source_email": email_path,
        "urls": urls,
        "attachments": attachments,
        "mitre": mitre,
        "timestamp": datetime.now(UTC).isoformat(),
    }

    return write_incident(incident)
