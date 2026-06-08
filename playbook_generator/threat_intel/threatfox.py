import requests
from settings import THREATFOX_AUTH_KEY
from threat_intel.common import source_result


def check_threatfox(ioc_value, ioc_type):
    if ioc_type in ["IP Address", "Domain", "URL", "MD5 Hash", "SHA1 Hash", "SHA256 Hash"]:
        query = {"query": "search_ioc", "search_term": ioc_value}
    else:
        return source_result("ThreatFox", summary="Unsupported IOC type")

    headers = {"Content-Type": "application/json"}
    if THREATFOX_AUTH_KEY:
        headers["Auth-Key"] = THREATFOX_AUTH_KEY
    try:
        response = requests.post("https://threatfox-api.abuse.ch/api/v1/", json=query, headers=headers, timeout=15)
        if response.status_code != 200:
            return source_result("ThreatFox", status="error", summary=f"API error: HTTP {response.status_code}")
        data = response.json()
        if data.get("query_status") == "ok":
            first = data.get("data", [{}])[0]
            malware = first.get("malware_printable") or first.get("malware") or "malware IOC"
            confidence = first.get("confidence_level", "unknown")
            return source_result("ThreatFox", status="found", malicious=True, score=85, summary=f"Listed as {malware}. Confidence: {confidence}", details=first)
        return source_result("ThreatFox", status="not_found", summary="Not listed in ThreatFox")
    except requests.exceptions.RequestException as e:
        return source_result("ThreatFox", status="error", summary=f"Request failed: {e}")
