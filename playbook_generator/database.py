import json
import sqlite3
from settings import DB_PATH


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            scenario TEXT NOT NULL,
            severity TEXT,
            severity_confidence TEXT,
            severity_rationale TEXT,
            ioc_context_note TEXT,
            iocs_json TEXT,
            mitre_json TEXT,
            playbook_markdown TEXT,
            playbook_html TEXT,
            mermaid_code TEXT,
            language TEXT DEFAULT 'en'
        )
        """
    )
    columns = [row[1] for row in conn.execute("PRAGMA table_info(analyses)").fetchall()]
    if "language" not in columns:
        conn.execute("ALTER TABLE analyses ADD COLUMN language TEXT DEFAULT 'en'")
    conn.commit()
    conn.close()


def save_analysis(record):
    conn = get_db_connection()
    cur = conn.execute(
        """
        INSERT INTO analyses (
            created_at, scenario, severity, severity_confidence, severity_rationale,
            ioc_context_note, iocs_json, mitre_json, playbook_markdown,
            playbook_html, mermaid_code, language
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record["created_at"], record["scenario"], record["severity"],
            record["severity_confidence"], record["severity_rationale"],
            record["ioc_context_note"], json.dumps(record["iocs"], ensure_ascii=False),
            json.dumps(record["mitre"], ensure_ascii=False), record["playbook_markdown"],
            record["playbook_html"], record["mermaid_code"], record.get("language", "en")
        )
    )
    conn.commit()
    analysis_id = cur.lastrowid
    conn.close()
    return analysis_id


def get_all_analyses():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM analyses ORDER BY id DESC").fetchall()
    conn.close()
    return rows


def get_analysis_by_id(analysis_id):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
    conn.close()
    return row


def delete_analysis_by_id(analysis_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
    conn.commit()
    conn.close()
