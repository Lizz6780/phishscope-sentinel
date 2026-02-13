import hashlib

def extract_attachments(msg):
    attachments = []

    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            content = part.get_payload(decode=True)
            sha256 = hashlib.sha256(content).hexdigest()

            suspicious = any(filename.lower().endswith(ext) for ext in [
                ".html", ".htm", ".zip", ".exe", ".js", ".iso"
            ])

            attachments.append({
                "filename": filename,
                "sha256": sha256,
                "suspicious": suspicious
            })

    return attachments
