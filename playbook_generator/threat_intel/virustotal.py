import base64
import requests
from settings import VIRUSTOTAL_API_KEY
from ioc_extractor import is_public_ip
from threat_intel.common import source_result


def vt_url_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def vt_headers():
    return {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}


def check_virustotal(ioc_value, ioc_type):
    if not VIRUSTOTAL_API_KEY:
        return source_result("VirusTotal", summary="Skipped: API key is not configured")

    base_url = "https://www.virustotal.com/api/v3"
    if ioc_type == "IP Address":
        if not is_public_ip(ioc_value):
            return source_result("VirusTotal", status="skipped", summary="Skipped: private, reserved, or local IP")
        endpoint = f"{base_url}/ip_addresses/{ioc_value}"
    elif ioc_type == "Domain":
        endpoint = f"{base_url}/domains/{ioc_value}"
    elif ioc_type == "URL":
        endpoint = f"{base_url}/urls/{vt_url_id(ioc_value)}"
    elif ioc_type in ["MD5 Hash", "SHA1 Hash", "SHA256 Hash"]:
        endpoint = f"{base_url}/files/{ioc_value}"
    else:
        return source_result("VirusTotal", summary="Unsupported IOC type")

    try:
        response = requests.get(endpoint, headers=vt_headers(), timeout=15)
        if response.status_code == 404:
            return source_result("VirusTotal", status="not_found", summary="Not found in VirusTotal dataset")
        if response.status_code == 401:
            return source_result("VirusTotal", status="error", summary="Unauthorized: invalid API key")
        if response.status_code == 429:
            return source_result("VirusTotal", status="error", summary="Rate limit exceeded")
        if response.status_code != 200:
            return source_result("VirusTotal", status="error", summary=f"API error: HTTP {response.status_code}")

        data = response.json().get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        score = min(100, malicious * 10 + suspicious * 5)
        is_malicious = malicious > 0 or suspicious >= 3
        summary = f"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {stats.get('harmless', 0)}, Undetected: {stats.get('undetected', 0)}"
        return source_result("VirusTotal", status="found", malicious=is_malicious, score=score, summary=summary, details=stats)
    except requests.exceptions.RequestException as e:
        return source_result("VirusTotal", status="error", summary=f"Request failed: {e}")
