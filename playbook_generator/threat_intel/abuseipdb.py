import requests
from settings import ABUSEIPDB_API_KEY
from ioc_extractor import is_public_ip
from threat_intel.common import source_result


def check_abuseipdb(ioc_value, ioc_type):
    if ioc_type != "IP Address":
        return source_result("AbuseIPDB", summary="Skipped: source supports IP addresses only")
    if not ABUSEIPDB_API_KEY:
        return source_result("AbuseIPDB", summary="Skipped: API key is not configured")
    if not is_public_ip(ioc_value):
        return source_result("AbuseIPDB", summary="Skipped: private, reserved, or local IP")

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Accept": "application/json", "Key": ABUSEIPDB_API_KEY},
            params={"ipAddress": ioc_value, "maxAgeInDays": 90},
            timeout=15
        )
        if response.status_code != 200:
            return source_result("AbuseIPDB", status="error", summary=f"API error: HTTP {response.status_code}")
        data = response.json().get("data", {})
        abuse_score = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        return source_result(
            "AbuseIPDB", status="found", malicious=abuse_score >= 20,
            score=abuse_score, summary=f"Abuse confidence score: {abuse_score}, Reports: {total_reports}", details=data
        )
    except requests.exceptions.RequestException as e:
        return source_result("AbuseIPDB", status="error", summary=f"Request failed: {e}")
