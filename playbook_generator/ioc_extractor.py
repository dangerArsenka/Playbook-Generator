import ipaddress
import re

FILE_EXTENSIONS = {
    "zip", "rar", "7z", "exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "jar",
    "doc", "docx", "xls", "xlsx", "pdf", "txt", "png", "jpg", "jpeg", "gif",
    "mp4", "iso", "msi", "lnk", "tmp", "log", "csv", "json", "xml", "html", "htm",
    "sh", "bash", "py", "php", "asp", "aspx", "jsp", "bin", "dat", "cfg", "conf", "yaml", "yml"
}

COMMON_FALSE_DOMAIN_SUFFIXES = FILE_EXTENSIONS


def normalize_defanged_ioc(text):
    if not text:
        return text
    return (
        text.replace("[.]", ".")
            .replace("(.)", ".")
            .replace("{.}", ".")
            .replace("[dot]", ".")
            .replace("(dot)", ".")
            .replace("hxxp[:]//", "http://")
            .replace("hxxps[:]//", "https://")
            .replace("hxxp://", "http://")
            .replace("hxxps://", "https://")
            .replace("[:]", ":")
    )


def is_public_ip(ip_value):
    try:
        ip_obj = ipaddress.ip_address(ip_value)
        return not (
            ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
            or ip_obj.is_multicast or ip_obj.is_link_local
        )
    except ValueError:
        return False


def _looks_like_file_name(value):
    """Avoid treating filenames such as bin.sh, update.ps1 or invoice.zip as domains."""
    if not value or "." not in value:
        return False
    parts = value.lower().split(".")
    if len(parts) != 2:
        return False
    name, ext = parts
    if ext in COMMON_FALSE_DOMAIN_SUFFIXES:
        return True
    if len(name) <= 2 and ext in FILE_EXTENSIONS:
        return True
    return False


def _is_domain_inside_path(normalized_text, value):
    """Detect a domain candidate that is actually a filename/path segment."""
    for match in re.finditer(re.escape(value), normalized_text, flags=re.IGNORECASE):
        before = normalized_text[match.start() - 1] if match.start() > 0 else ""
        after = normalized_text[match.end()] if match.end() < len(normalized_text) else ""
        if before in {"/", "\\"} or after in {"/", "\\"}:
            return True
    return False


def extract_iocs(text):
    normalized_text = normalize_defanged_ioc(text)
    patterns = {
        "IP Address": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        "URL": r"\bhttps?://[^\s<>'\"]+",
        "SHA256 Hash": r"\b[a-fA-F0-9]{64}\b",
        "SHA1 Hash": r"\b[a-fA-F0-9]{40}\b",
        "MD5 Hash": r"\b[a-fA-F0-9]{32}\b",
        "Domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
    }

    extracted = []
    urls = re.findall(patterns["URL"], normalized_text)
    url_domains = set()

    for url in urls:
        clean_url = url.strip(".,;:()[]{}<>\"'")
        extracted.append({"value": clean_url, "type": "URL"})
        domain_match = re.search(r"https?://([^/\s:]+)", clean_url)
        if domain_match:
            host = domain_match.group(1).lower()
            url_domains.add(host)
            try:
                ipaddress.ip_address(host)
                extracted.append({"value": host, "type": "IP Address"})
            except ValueError:
                pass

    for ioc_type, pattern in patterns.items():
        if ioc_type == "URL":
            continue
        matches = re.findall(pattern, normalized_text)
        for match in matches:
            value = match.strip(".,;:()[]{}<>\"'")
            if ioc_type in ["Domain", "IP Address"]:
                value = value.lower()

            if ioc_type == "IP Address":
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    continue

            if ioc_type == "Domain":
                if value in url_domains:
                    continue

                if _looks_like_file_name(value):
                    continue

                if _is_domain_inside_path(normalized_text, value):
                    continue

                if "\\" in value or "/" in value:
                    continue

                if re.fullmatch(r"[a-fA-F0-9]{32,64}", value.replace(".", "")):
                    continue

            extracted.append({"value": value, "type": ioc_type})

    unique_iocs = []
    seen = set()
    for item in extracted:
        key = (item["value"], item["type"])
        if key not in seen:
            seen.add(key)
            unique_iocs.append(item)
    return unique_iocs
