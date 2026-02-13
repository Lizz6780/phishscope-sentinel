def calculate_risk(findings):
    risk = 0

    if findings.get("spf_fail", False):
        risk += 15
    if findings.get("dkim_fail", False):
        risk += 15
    if findings.get("spoofing", False):
        risk += 20

    if findings.get("url_malicious", False):
        risk += 30
    elif findings.get("urls", []):
        risk += 10

    if findings.get("ip_abuse_score", 0) > 80:
        risk += 25

    # Suspicious attachment indicators are a strong phishing signal.
    if findings.get("attachment_suspicious", False):
        risk += 35

    return risk
