import email
from email import policy


def parse_email(eml_path):
    with open(eml_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    headers = dict(msg.items())

    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                parts.append(part.get_content())
        body = "\n".join(parts)
    else:
        body = msg.get_content() or ""

    return headers, body, msg
