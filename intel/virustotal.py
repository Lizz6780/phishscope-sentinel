import base64
import requests

API_KEY = "PUT_VIRUSTOTAL_API_KEY_HERE"


def check_url(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": API_KEY}

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10,
        )
    except requests.RequestException:
        return {"malicious": False, "detections": 0}

    if r.status_code != 200:
        return {"malicious": False, "detections": 0}

    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
    detections = stats.get("malicious", 0)

    return {
        "malicious": detections > 0,
        "detections": detections
    }
