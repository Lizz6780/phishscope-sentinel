def analyze_headers(headers):
    spf_header = (headers.get("Received-SPF") or "").lower()
    auth_results = (headers.get("Authentication-Results") or "").lower()

    from_addr = headers.get("From", "")
    return_path = headers.get("Return-Path", "")

    spf_fail = "fail" in spf_header
    dkim_fail = "dkim=fail" in auth_results

    # Basic spoofing heuristic: sender differs from return path.
    spoofing = bool(from_addr and return_path and from_addr not in return_path)

    return {
        "from": from_addr,
        "return_path": return_path,
        "spf": spf_header or "unknown",
        "dkim": auth_results or "unknown",
        "spf_fail": spf_fail,
        "dkim_fail": dkim_fail,
        "spoofing": spoofing,
    }
