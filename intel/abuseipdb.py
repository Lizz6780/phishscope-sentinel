import requests

API_KEY = "PUT_ABUSEIPDB_API_KEY_HERE"


def check_ip(ip):
    headers = {
        "Key": API_KEY,
        "Accept": "application/json",
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=10,
        )
    except requests.RequestException:
        return 0

    if r.status_code != 200:
        return 0

    return r.json()["data"]["abuseConfidenceScore"]
