import json
import re
from settings import GEMINI_API_KEY, model
from language import ai_language_instruction, language_name

ALLOWED_MITRE_TECHNIQUES = """
T1566 - Phishing - Initial Access
T1204 - User Execution - Execution
T1059 - Command and Scripting Interpreter - Execution
T1059.001 - PowerShell - Execution
T1105 - Ingress Tool Transfer - Command and Control
T1071 - Application Layer Protocol - Command and Control
T1078 - Valid Accounts - Initial Access / Persistence / Defense Evasion / Privilege Escalation
T1110 - Brute Force - Credential Access
T1003 - OS Credential Dumping - Credential Access
T1555 - Credentials from Password Stores - Credential Access
T1021 - Remote Services - Lateral Movement
T1041 - Exfiltration Over C2 Channel - Exfiltration
T1486 - Data Encrypted for Impact - Impact
T1490 - Inhibit System Recovery - Impact
T1082 - System Information Discovery - Discovery
T1083 - File and Directory Discovery - Discovery
T1053 - Scheduled Task/Job - Execution / Persistence
T1547 - Boot or Logon Autostart Execution - Persistence / Privilege Escalation
T1036 - Masquerading - Defense Evasion
T1027 - Obfuscated Files or Information - Defense Evasion
"""


def extract_json_object_from_ai_response(text):
    if not text:
        return {}
    cleaned = text.strip().replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return {}
    return {}


def build_ioc_summary_for_ai(enriched_iocs, response_language="en"):
    if not enriched_iocs:
        if response_language == "uk":
            return "IOC не були виявлені. Оціни інцидент на основі поведінки, уражених активів та ознак впливу."
        return "No IOCs were extracted from the scenario. Assess the incident based on behavior, affected assets, and impact indicators."
    lines = []
    for ioc in enriched_iocs:
        lines.append(
            f"- IOC: {ioc.get('value')} ({ioc.get('type')}), Verdict: {ioc.get('verdict')}, "
            f"Confidence: {ioc.get('confidence')}, Malicious sources: {ioc.get('malicious_sources')}, Summary: {ioc.get('display_summary', ioc.get('summary'))}"
        )
        for src in ioc.get("source_results", [])[:6]:
            lines.append(f"  - {src.get('source')}: status={src.get('status')}, malicious={src.get('malicious')}, summary={src.get('summary')}")
    return "\n".join(lines)


def ai_incident_analysis(user_scenario, enriched_iocs, response_language="en"):
    default_result = {
        "severity": {
            "level": "Unknown",
            "confidence": "Low",
            "rationale": "AI incident analysis was not completed.",
            "ioc_context_note": "No IOC context was processed."
        },
        "mitre_suggestions": []
    }

    if not GEMINI_API_KEY:
        default_result["severity"]["rationale"] = "GEMINI_API_KEY is not configured."
        return default_result

    ioc_summary = build_ioc_summary_for_ai(enriched_iocs, response_language)
    output_language_name = language_name(response_language)
    language_rules = ai_language_instruction(response_language)

    prompt = f"""
You are an AI Incident Analysis Agent for a SOC playbook generator.

Detected response language: {output_language_name}.
Language requirements:
{language_rules}

Your task:
Analyze the incident scenario and available Threat Intelligence context. Return:
1. AI-based severity assessment.
2. Possible MITRE ATT&CK Enterprise tactics and techniques.

Important severity rules:
- The user scenario may or may not contain IOCs.
- If IOCs are present, use Threat Intelligence results as additional context.
- If no IOCs are present, still assess severity based on described behavior, affected assets, and impact.
- Do NOT lower severity only because no IOC was provided.
- Never assign Low severity to a scenario that describes confirmed impact such as encrypted files, ransom notes, disabled backups, data exfiltration, compromised privileged accounts, domain controller compromise, affected file servers, or disruption of critical services.
- Severity must be one of: Informational, Low, Medium, High, Critical. Keep these values in English.
- Severity confidence must be one of: Low, Medium, High. Keep these values in English.
- Write rationale and IOC context note in the detected response language.

MITRE rules:
- Suggest POSSIBLE MITRE ATT&CK techniques only. Do not claim they are confirmed.
- Select techniques ONLY from the allowed MITRE ATT&CK list below.
- Do NOT invent technique IDs.
- If evidence is weak, use Low or Medium confidence. Keep confidence values in English.
- If there is not enough evidence, do not include the technique.
- Write MITRE evidence and reasoning in the detected response language. Keep MITRE IDs and official technique names unchanged.

Allowed MITRE ATT&CK techniques:
{ALLOWED_MITRE_TECHNIQUES}

Incident scenario:
{user_scenario}

Threat Intelligence context:
{ioc_summary}

Return ONLY valid JSON with this exact structure:
{{
  "severity": {{
    "level": "Critical",
    "confidence": "High",
    "rationale": "Explain why this severity was selected in the detected response language.",
    "ioc_context_note": "Explain whether IOC context was available and how it affected or did not affect the assessment in the detected response language."
  }},
  "mitre_suggestions": [
    {{
      "technique_id": "T1486",
      "technique_name": "Data Encrypted for Impact",
      "tactic": "Impact",
      "confidence": "High",
      "evidence": "Evidence in the detected response language.",
      "reasoning": "Reasoning in the detected response language."
    }}
  ]
}}
"""

    try:
        response = model.generate_content(prompt)
        if not response or not response.candidates:
            return default_result
        result = extract_json_object_from_ai_response(response.text)
        if not result:
            return default_result

        severity = result.get("severity", {})
        level = severity.get("level", "Unknown")
        if level not in ["Informational", "Low", "Medium", "High", "Critical"]:
            level = "Unknown"
        confidence = severity.get("confidence", "Low")
        if confidence not in ["Low", "Medium", "High"]:
            confidence = "Low"

        allowed_ids = {line.split("-")[0].strip() for line in ALLOWED_MITRE_TECHNIQUES.strip().splitlines()}
        cleaned_mitre = []
        for item in result.get("mitre_suggestions", []):
            tid = item.get("technique_id", "").strip()
            if tid not in allowed_ids:
                continue
            conf = item.get("confidence", "Low")
            if conf not in ["Low", "Medium", "High"]:
                conf = "Low"
            cleaned_mitre.append({
                "technique_id": tid,
                "technique_name": item.get("technique_name", "Unknown"),
                "tactic": item.get("tactic", "Unknown"),
                "confidence": conf,
                "evidence": item.get("evidence", "No specific evidence provided."),
                "reasoning": item.get("reasoning", "AI-assisted suggestion based on the scenario.")
            })

        return {
            "severity": {
                "level": level,
                "confidence": confidence,
                "rationale": severity.get("rationale", "No rationale provided."),
                "ioc_context_note": severity.get("ioc_context_note", "No IOC context note provided.")
            },
            "mitre_suggestions": cleaned_mitre
        }
    except Exception as e:
        default_result["severity"]["rationale"] = f"AI incident analysis failed: {e}"
        return default_result
