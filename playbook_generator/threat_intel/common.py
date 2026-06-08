def source_result(source, status="skipped", malicious=False, score=0, summary="", details=None):
    return {
        "source": source,
        "status": status,
        "malicious": malicious,
        "score": score,
        "summary": summary,
        "details": details or {}
    }
