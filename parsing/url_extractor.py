import re

URL_REGEX = r'https?://[^\s"]+'

def extract_urls(email_body):
    return re.findall(URL_REGEX, email_body)
