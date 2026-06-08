import requests
from settings import OTX_API_KEY
from threat_intel.common import source_result


def check_otx(ioc_value, ioc_type):
    if not OTX_API_KEY:
        return source_result("AlienVault OTX", summary="Skipped: API key is not configured")
    if ioc_type == "IP Address":
        indicator_type = "IPv4"
    elif ioc_type == "Domain":
        indicator_type = "domain"
    elif ioc_type == "URL":
        indicator_type = "url"
    elif ioc_type in ["MD5 Hash", "SHA1 Hash", "SHA256 Hash"]:
        indicator_type = "file"
    else:
        return source_result("AlienVault OTX", summary="Unsupported IOC type")

    try:
        encoded = requests.utils.quote(ioc_value, safe="")
        endpoint = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{encoded}/general"
        response = requests.get(endpoint, headers={"X-OTX-API-KEY": OTX_API_KEY}, timeout=15)
        if response.status_code == 404:
            return source_result("AlienVault OTX", status="not_found", summary="Not found in OTX")
        if response.status_code != 200:
            return source_result("AlienVault OTX", status="error", summary=f"API error: HTTP {response.status_code}")
        data = response.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        malicious = pulse_count > 0
        score = min(100, pulse_count * 15)
        return source_result("AlienVault OTX", status="found", malicious=malicious, score=score, summary=f"Related OTX pulses: {pulse_count}", details=data.get("pulse_info", {}))
    except requests.exceptions.RequestException as e:
        return source_result("AlienVault OTX", status="error", summary=f"Request failed: {e}")
