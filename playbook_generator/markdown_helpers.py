import re


def clean_model_output(text):
    if not text:
        return ""
    cleaned = text.strip()
    if cleaned.startswith("```markdown"):
        cleaned = cleaned.replace("```markdown", "", 1).strip()
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3].strip()
    elif cleaned.startswith("```md"):
        cleaned = cleaned.replace("```md", "", 1).strip()
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3].strip()
    return cleaned


def sanitize_mermaid_code(code):
    """
    Makes Mermaid flowcharts more stable for rendering in Mermaid.js.

    It fixes common model-generated issues such as parentheses inside node
    labels, ampersands, risky punctuation, and old edge-label syntax.
    The goal is to avoid UI errors like "Syntax error in text" while
    keeping the diagram content readable.
    """
    if not code:
        return ""

    sanitized = code.strip()
    sanitized = sanitized.replace("\r\n", "\n").replace("\r", "\n")

    sanitized = re.sub(
        r"(\w+)\s*--\s*([^->\n]+?)\s*-->\s*(\w+)",
        lambda m: f"{m.group(1)} -->|{_clean_mermaid_label(m.group(2))}| {m.group(3)}",
        sanitized,
    )

    sanitized = re.sub(
        r"(\w+)\[([^\]]+)\](:::\w+)?",
        lambda m: f"{m.group(1)}[{_clean_mermaid_label(m.group(2))}]{m.group(3) or ''}",
        sanitized,
    )

    sanitized = re.sub(
        r"(\w+)\{([^}]+)\}(:::\w+)?",
        lambda m: f"{m.group(1)}{{{_clean_mermaid_label(m.group(2))}}}{m.group(3) or ''}",
        sanitized,
    )

    sanitized = re.sub(
        r"(\w+)\(\((.*?)\)\)(:::\w+)?",
        lambda m: f"{m.group(1)}(({_clean_mermaid_label(m.group(2))})){m.group(3) or ''}",
        sanitized,
    )

    return sanitized


def _clean_mermaid_label(label):
    if not label:
        return ""

    cleaned = str(label)
    cleaned = cleaned.replace("(", ": ").replace(")", "")
    cleaned = cleaned.replace("&", "and")
    cleaned = cleaned.replace("/", " or ")
    cleaned = cleaned.replace(";", "")
    cleaned = cleaned.replace("`", "")
    cleaned = cleaned.replace("\"", "").replace("'", "")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def sanitize_mermaid_in_markdown(markdown_text):
    """
    Replaces Mermaid code blocks inside Markdown with sanitized Mermaid code.
    This ensures both the current UI and saved History use the cleaned diagram.
    """
    if not markdown_text:
        return ""

    def replace_block(match):
        code = match.group(1).strip()
        cleaned_code = sanitize_mermaid_code(code)
        return f"```mermaid\n{cleaned_code}\n```"

    return re.sub(
        r"```mermaid\s*(.*?)```",
        replace_block,
        markdown_text,
        flags=re.DOTALL | re.IGNORECASE,
    )


def extract_mermaid_code(markdown_text):
    if not markdown_text:
        return ""
    match = re.search(r"```mermaid\s*(.*?)```", markdown_text, re.DOTALL | re.IGNORECASE)
    if match:
        return sanitize_mermaid_code(match.group(1).strip())
    return ""


def html_to_plain_text(html_text):
    if not html_text:
        return ""
    text = re.sub(r"<br\s*/?>", "\n", html_text, flags=re.I)
    text = re.sub(r"</p>", "\n", text, flags=re.I)
    text = re.sub(r"</li>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    return text.strip()


def markdown_to_plain_text(markdown_text):
    if not markdown_text:
        return ""
    text = re.sub(r"```mermaid\s*.*?```", "[Mermaid diagram included separately]", markdown_text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"```.*?```", "[Code block omitted]", text, flags=re.DOTALL)
    text = re.sub(r"^#{1,6}\s*", "", text, flags=re.MULTILINE)
    text = text.replace("**", "")
    return text.strip()
