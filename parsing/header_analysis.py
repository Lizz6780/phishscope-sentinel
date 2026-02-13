import email
from email import policy

def analyze_headers(eml_path):
    with open(eml_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    headers = dict(msg.items())

    spf = headers.get("Received-SPF", "unknown")
    dkim = headers.get("Authentication-Results", "unknown")
    from_addr = headers.get("From", "")
    return_path = headers.get("Return-Path", "")

    return {
        "from": from_addr,
        "return_path": return_path,
        "spf": spf,
        "dkim": dkim
    }
