SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".wsf",
    ".bat",
    ".cmd",
    ".ps1",
    ".hta",
    ".jar",
    ".iso",
    ".img",
    ".lnk",
    ".dll",
    ".msi",
    ".docm",
    ".xlsm",
    ".pptm",
}


def analyze_attachments(msg):
    attachments = []

    for part in msg.walk():
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()

        if disposition != "attachment" and not filename:
            continue

        payload = part.get_payload(decode=True) or b""
        lower_name = (filename or "").lower()

        reasons = []
        if any(lower_name.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            reasons.append("suspicious_extension")
        if lower_name.count(".") >= 2:
            reasons.append("double_extension")

        attachments.append(
            {
                "filename": filename or "unknown",
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
                "suspicious": bool(reasons),
                "reasons": reasons,
            }
        )

    return attachments
