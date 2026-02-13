def map_to_mitre(findings, attachments):
    techniques = []

    if findings.get("url_malicious", False):
        techniques.append({
            "tactic": "Initial Access",
            "technique": "T1566.002",
            "name": "Spearphishing Link"
        })

    if any(a.get("suspicious", False) for a in attachments):
        techniques.append({
            "tactic": "Initial Access",
            "technique": "T1566.001",
            "name": "Spearphishing Attachment"
        })

    return techniques
