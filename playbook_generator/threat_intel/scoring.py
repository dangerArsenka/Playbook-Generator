def calculate_agent_verdict(source_results):
    checked = [r for r in source_results if r["status"] in ["found", "not_found"]]
    malicious_sources = [r for r in source_results if r.get("malicious")]
    checked_count = len(checked)
    malicious_count = len(malicious_sources)

    if checked_count == 0:
        return "Unknown", "Low", "No source could provide a reliable result for this IOC."
    if malicious_count >= 2:
        return "Malicious", "High", "Multiple independent sources indicate malicious activity."
    if malicious_count == 1:
        return "Suspicious", "Medium", "One source indicates suspicious or malicious activity."
    return "Clean or Not Listed", "Medium", "No checked source reported this IOC as malicious."
