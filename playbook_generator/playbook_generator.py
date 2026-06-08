from settings import GEMINI_API_KEY, model
from markdown_helpers import clean_model_output
from language import ai_language_instruction, language_name


def generate_playbook(user_scenario, enriched_iocs, incident_analysis, response_language="en"):
    severity = incident_analysis.get("severity", {})
    mitre_matches = incident_analysis.get("mitre_suggestions", [])

    ioc_context = "\n".join([
        f"- {ioc['value']} ({ioc['type']}): Verdict={ioc['verdict']}, Confidence={ioc['confidence']}, Summary={ioc.get('display_summary', ioc.get('summary', '-'))}"
        for ioc in enriched_iocs
    ]) or "No IOCs were extracted."

    mitre_context = "\n".join([
        f"- {item['technique_id']} {item['technique_name']} ({item['tactic']}), Confidence: {item['confidence']}, Evidence: {item['evidence']}, Reasoning: {item['reasoning']}"
        for item in mitre_matches
    ]) or "No possible MITRE ATT&CK techniques were suggested."

    output_language_name = language_name(response_language)
    language_rules = ai_language_instruction(response_language)

    system_instruction = f"""
Role: You are a Senior Incident Responder and SOC Manager acting as an automated playbook generator.

Detected response language: {output_language_name}.
Language requirements:
{language_rules}

Task:
Analyze the network security scenario provided by the user and generate a professional Incident Response Playbook.

Use the additional automated analysis results below when creating the playbook.

AI-Based Severity Assessment:
- Level: {severity.get('level', 'Unknown')}
- Confidence: {severity.get('confidence', 'Low')}
- Rationale: {severity.get('rationale', '-')}
- IOC Context Note: {severity.get('ioc_context_note', '-')}

Threat Intelligence Agent Results:
{ioc_context}

AI-Assisted Possible MITRE ATT&CK Suggestions:
{mitre_context}

Important:
- MITRE ATT&CK results are AI-assisted suggestions, not confirmed attacker techniques.
- Use them carefully and describe them as possible or likely techniques.
- Generate the complete playbook text in the detected response language.
- Generate Mermaid node labels in the detected response language, while keeping Mermaid syntax keywords in English.
- Keep severity and confidence values in English.
- If the scenario contains ransomware indicators, encrypted files, ransom notes, disabled backups, affected file servers, data exfiltration, or disruption of critical services, reflect that severity appropriately even if no IOC is present.

Formatting rules:
- Do not wrap the full response inside ```markdown, ```md, or any other global code block.
- Only the Mermaid diagram must be placed inside a single ```mermaid code block.
- All other content must be normal Markdown text.
- Use Markdown headers and bullet points.
- Do not use HTML.
- Use the detected response language for phase explanations and recommendations.

Strictly structure your response into these 5 phases using Markdown headers (###) for phases and bullet points (*) for steps.

1. Identification & Scoping:
   - Determine the type of attack.
   - List logs/tools to check.
   - Assess severity.
   - Include relevant IOCs and possible MITRE ATT&CK techniques if available.

2. Containment:
   - Short-term actions.
   - Long-term actions.

3. Eradication:
   - Steps to remove root cause.

4. Recovery:
   - Steps to restore systems.
   - Validation checks.

5. Lessons Learned:
   - Root cause analysis summary.
   - Recommendations.

Create a Mermaid.js flowchart that visually summarizes the full 5-phase incident response process.

IMPORTANT For Mermaid Diagram:
- The entire mermaid code must be inside a single standard markdown code block.
- Start with graph TD.
- Use inline styling only, for example: A[Step]:::ACTION
- Do NOT use old syntax like: class A,B,C process;
- Keep node text short.
- If the detected response language is Ukrainian, use short Ukrainian node labels.
- Do not use ampersand symbol & in node text. Use "and" for English or "та" for Ukrainian.
- Do not use parentheses inside node labels. Use colon instead.
- Example: use "Attack type: Phishing" instead of "Attack type (Phishing)".
- Do not use quotation marks inside node labels.
- Do not use semicolons inside node labels.
- Do not use slashes inside node labels.
- Do not use very long labels.
- For decision arrows, use this format: A -->|Yes| B
- Do not use this format: A -- Yes --> B

Mermaid styling requirements:
Define the following classes at the end of the mermaid code:

classDef DECISION fill:#330000,stroke:#ff0000,stroke-width:2px,color:#fff;
classDef ACTION fill:#001a00,stroke:#00ff00,stroke-width:2px,color:#fff;
classDef START_END fill:#1a1a1a,stroke:#fff,stroke-width:2px,color:#fff;

Input Scenario:
"{user_scenario}"
"""
    if not GEMINI_API_KEY:
        return "Error: GEMINI_API_KEY is not configured in the .env file."

    response = model.generate_content(system_instruction)
    if response and response.candidates:
        return clean_model_output(response.text)
    return "Warning: No response was received."
