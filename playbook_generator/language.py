import re
from copy import deepcopy


def detect_response_language(text):
    """Return 'uk' when the scenario is mostly Ukrainian/Cyrillic, otherwise 'en'."""
    if not text:
        return "en"
    cyrillic_chars = re.findall(r"[А-Яа-яІіЇїЄєҐґ]", text)
    latin_chars = re.findall(r"[A-Za-z]", text)
    if len(cyrillic_chars) >= 10 and len(cyrillic_chars) >= len(latin_chars) * 0.25:
        return "uk"
    return "en"


def language_name(code):
    return "Ukrainian" if code == "uk" else "English"


def ai_language_instruction(code):
    if code == "uk":
        return (
            "Generate all user-facing analysis text in Ukrainian. This includes severity rationale, "
            "IOC context notes, MITRE evidence, MITRE reasoning, playbook text, recommendations, "
            "and Mermaid node labels. Keep IOC values, commands, file paths, source names such as "
            "VirusTotal or URLhaus, MITRE technique IDs, and official MITRE technique names unchanged. "
            "Keep severity and confidence values in English: Informational, Low, Medium, High, Critical; "
            "Low, Medium, High."
        )
    return (
        "Generate all user-facing analysis text in English. Keep IOC values, commands, file paths, "
        "source names, MITRE technique IDs, and official MITRE technique names unchanged."
    )


def localized_no_ioc_message(code):
    if code == "uk":
        return "IOC не були виявлені. Оцінювання виконано на основі поведінки, уражених активів та можливого впливу інциденту."
    return "No IOCs were extracted. The assessment was based on behavior, affected assets, and potential incident impact."


def localize_ioc_results(enriched_iocs, code):
    """Add a user-facing display_summary in the scenario language.

    Technical verdict/confidence/source names remain in English for consistency.
    """
    localized = deepcopy(enriched_iocs or [])
    for ioc in localized:
        checked_count = len(ioc.get("sources_checked") or [])
        malicious_count = ioc.get("malicious_sources", 0)
        verdict = ioc.get("verdict", "Unknown")
        confidence = ioc.get("confidence", "Low")
        if code == "uk":
            if checked_count == 0:
                summary = "Жодне доступне джерело Threat Intelligence не надало надійного результату для цього IOC."
            elif malicious_count > 0:
                summary = (
                    f"{malicious_count} із {checked_count} перевірених джерел позначили цей IOC як підозрілий або шкідливий. "
                    f"Фінальний висновок агента: {verdict}; впевненість: {confidence}."
                )
            else:
                summary = (
                    f"0 із {checked_count} перевірених джерел позначили цей IOC як шкідливий. "
                    f"Фінальний висновок агента: {verdict}; впевненість: {confidence}."
                )
        else:
            if checked_count == 0:
                summary = "No available Threat Intelligence source provided a reliable result for this IOC."
            elif malicious_count > 0:
                summary = (
                    f"{malicious_count} of {checked_count} checked sources marked this IOC as suspicious or malicious. "
                    f"Final agent verdict: {verdict}; confidence: {confidence}."
                )
            else:
                summary = (
                    f"0 of {checked_count} checked sources marked this IOC as malicious. "
                    f"Final agent verdict: {verdict}; confidence: {confidence}."
                )
        ioc["display_summary"] = summary
    return localized
