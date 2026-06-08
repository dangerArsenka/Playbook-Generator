from threat_intel.virustotal import check_virustotal
from threat_intel.abuseipdb import check_abuseipdb
from threat_intel.urlhaus import check_urlhaus
from threat_intel.malwarebazaar import check_malwarebazaar
from threat_intel.threatfox import check_threatfox
from threat_intel.otx import check_otx
from threat_intel.scoring import calculate_agent_verdict


def enrich_iocs(iocs):
    enriched = []
    for ioc in iocs:
        value = ioc["value"]
        ioc_type = ioc["type"]
        source_results = [
            check_virustotal(value, ioc_type),
            check_abuseipdb(value, ioc_type),
            check_urlhaus(value, ioc_type),
            check_malwarebazaar(value, ioc_type),
            check_threatfox(value, ioc_type),
            check_otx(value, ioc_type),
        ]
        verdict, confidence, summary = calculate_agent_verdict(source_results)
        enriched.append({
            "value": value,
            "type": ioc_type,
            "sources_checked": [r["source"] for r in source_results if r["status"] in ["found", "not_found"]],
            "malicious_sources": len([r for r in source_results if r.get("malicious")]),
            "verdict": verdict,
            "confidence": confidence,
            "summary": summary,
            "source_results": source_results
        })
    return enriched
