import requests
from settings import URLHAUS_AUTH_KEY
from threat_intel.common import source_result


def check_urlhaus(ioc_value, ioc_type):
    if ioc_type != "URL":
        return source_result("URLhaus", summary="Skipped: source supports URLs only")
    headers = {}
    if URLHAUS_AUTH_KEY:
        headers["Auth-Key"] = URLHAUS_AUTH_KEY
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": ioc_value}, headers=headers, timeout=15
        )
        if response.status_code != 200:
            return source_result("URLhaus", status="error", summary=f"API error: HTTP {response.status_code}")
        data = response.json()
        query_status = data.get("query_status")
        if query_status == "ok":
            url_status = data.get("url_status", "unknown")
            threat = data.get("threat", "unknown")
            return source_result("URLhaus", status="found", malicious=True, score=90, summary=f"Listed as {threat}, URL status: {url_status}", details=data)
        return source_result("URLhaus", status="not_found", summary="Not listed in URLhaus")
    except requests.exceptions.RequestException as e:
        return source_result("URLhaus", status="error", summary=f"Request failed: {e}")
