from datetime import datetime
import json

from flask import Flask, render_template, request, redirect, url_for, send_file, flash
import markdown

from settings import FLASK_SECRET_KEY
from database import init_db, save_analysis, get_all_analyses, get_analysis_by_id, delete_analysis_by_id
from ioc_extractor import extract_iocs
from threat_intel.agent import enrich_iocs
from language import detect_response_language, localize_ioc_results
from incident_analysis import ai_incident_analysis
from playbook_generator import generate_playbook
from markdown_helpers import extract_mermaid_code, sanitize_mermaid_in_markdown
from pdf_report import build_pdf_report

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

init_db()


@app.route("/", methods=["GET", "POST"])
def index():
    response_html = ""
    user_scenario = ""
    enriched_iocs = []
    mitre_matches = []
    severity = {"level": "", "confidence": "", "rationale": "", "ioc_context_note": ""}
    analysis_id = None

    if request.method == "POST":
        user_scenario = request.form.get("prompt", "").strip()
        if not user_scenario:
            flash("Please enter an incident scenario first.")
            return redirect(url_for("index"))

        response_language = detect_response_language(user_scenario)

        extracted_iocs = extract_iocs(user_scenario)
        enriched_iocs = enrich_iocs(extracted_iocs) if extracted_iocs else []
        enriched_iocs = localize_ioc_results(enriched_iocs, response_language)
        incident_analysis = ai_incident_analysis(user_scenario, enriched_iocs, response_language)
        severity = incident_analysis.get("severity", severity)
        mitre_matches = incident_analysis.get("mitre_suggestions", [])

        try:
            raw_markdown = generate_playbook(user_scenario, enriched_iocs, incident_analysis, response_language)
            raw_markdown = sanitize_mermaid_in_markdown(raw_markdown)
            response_html = markdown.markdown(raw_markdown, extensions=["fenced_code", "tables"])
            mermaid_code = extract_mermaid_code(raw_markdown)

            analysis_id = save_analysis({
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scenario": user_scenario,
                "severity": severity.get("level", "Unknown"),
                "severity_confidence": severity.get("confidence", "Low"),
                "severity_rationale": severity.get("rationale", "-"),
                "ioc_context_note": severity.get("ioc_context_note", "-"),
                "iocs": enriched_iocs,
                "mitre": mitre_matches,
                "playbook_markdown": raw_markdown,
                "playbook_html": response_html,
                "mermaid_code": mermaid_code,
                "language": response_language
            })
        except Exception as e:
            response_html = f"<p>Error: An error occurred:<br>{e}</p>"

    return render_template(
        "index.html",
        response_text=response_html,
        original_prompt=user_scenario,
        enriched_iocs=enriched_iocs,
        mitre_matches=mitre_matches,
        severity=severity,
        analysis_id=analysis_id
    )


@app.route("/history")
def history():
    rows = get_all_analyses()
    return render_template("history.html", analyses=rows)


@app.route("/history/<int:analysis_id>")
def view_analysis(analysis_id):
    row = get_analysis_by_id(analysis_id)
    if not row:
        flash("Analysis not found.")
        return redirect(url_for("history"))
    iocs = json.loads(row["iocs_json"] or "[]")
    mitre = json.loads(row["mitre_json"] or "[]")
    severity = {
        "level": row["severity"],
        "confidence": row["severity_confidence"],
        "rationale": row["severity_rationale"],
        "ioc_context_note": row["ioc_context_note"]
    }
    return render_template(
        "view_analysis.html",
        analysis=row,
        enriched_iocs=iocs,
        mitre_matches=mitre,
        severity=severity,
        response_text=row["playbook_html"],
        original_prompt=row["scenario"],
        analysis_id=analysis_id,
        mermaid_code=row["mermaid_code"] or ""
    )


@app.route("/delete/<int:analysis_id>", methods=["POST"])
def delete_analysis(analysis_id):
    delete_analysis_by_id(analysis_id)
    flash(f"Analysis #{analysis_id} was deleted.")
    return redirect(url_for("history"))


@app.route("/export/<int:analysis_id>")
def export_pdf(analysis_id):
    pdf_path = build_pdf_report(analysis_id)
    if not pdf_path:
        flash("Analysis not found.")
        return redirect(url_for("history"))
    return send_file(pdf_path, as_attachment=True, download_name=f"soc_playbook_report_{analysis_id}.pdf")


if __name__ == "__main__":
    app.run(debug=True)
