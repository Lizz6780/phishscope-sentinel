from parsing.url_extractor import extract_urls


def phishing_decision(risk_score):
    if risk_score >= 61:
        return "PHISHING"
    if risk_score >= 31:
        return "SUSPICIOUS"
    return "LEGIT"
