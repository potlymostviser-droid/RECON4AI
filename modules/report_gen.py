# recon_tool/modules/report_gen.py
#
# Directory: recon_tool/modules/report_gen.py
#
# JSON and Markdown report generation module.
#
# CRITICAL FIX FROM PHASE 1 CRITIQUE:
# The `_md_table_separator` function was simplified to take exactly
# a column count, removing the dead code and confusing overloading.
# The custom `--output` suffix is now accepted and properly appended.

"""
report_gen
==========
Consumes the complete scan data dictionary and writes two output files:

  1. A machine-readable JSON file.
  2. A human-readable Markdown file structured specifically for pasting
     into an AI assistant.

Public API
----------
    generate_reports(scan_data, output_dir, target_domain, custom_suffix) -> dict
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_TOOL_NAME = "Professional Recon Tool"
_TOOL_VERSION = "1.0.0"

ReportPaths = Dict[str, Optional[Path]]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sanitise_cell(value: Any) -> str:
    """
    Make a value safe for inclusion in a Markdown table cell.
    """
    text = str(value) if value is not None else "—"
    text = text.replace("\n", " ").replace("\r", "")
    text = text.replace("|", "&#124;")
    return text


def _md_table_row(*cells: Any) -> str:
    """
    Format a list of values as a Markdown table row string.
    """
    sanitised = [_sanitise_cell(c) for c in cells]
    return "| " + " | ".join(sanitised) + " |\n"


def _md_table_separator(column_count: int) -> str:
    """
    Generate a Markdown table separator row.
    """
    return "|" + "|".join(["---"] * column_count) + "|\n"


# ---------------------------------------------------------------------------
# Findings summary generator
# ---------------------------------------------------------------------------

def _build_findings_summary(data: dict) -> List[str]:
    """
    Derive a list of notable-finding strings from the scan data.
    """
    findings: List[str] = []

    try:
        missing = [
            h["header_name"] for h in data.get("headers", [])
            if not h.get("present", False)
        ]
        if missing:
            findings.append(f"Missing security headers ({len(missing)}): {', '.join(missing)}")
    except Exception as exc:
        logger.error("[report_gen] Error summarising headers: %s", exc)

    try:
        insecure = [
            c["name"] for c in data.get("technology", {}).get("cookies", [])
            if not c.get("httponly") or not c.get("secure")
        ]
        if insecure:
            findings.append(f"Cookies missing HttpOnly or Secure flag ({len(insecure)}): {', '.join(insecure)}")
    except Exception as exc:
        logger.error("[report_gen] Error summarising cookies: %s", exc)

    try:
        kw_count = len(data.get("javascript", {}).get("keyword_findings", []))
        if kw_count:
            findings.append(f"Sensitive keyword assignments in JavaScript: {kw_count} occurrence(s)")
    except Exception as exc:
        logger.error("[report_gen] Error summarising JS keywords: %s", exc)

    try:
        sensitive_200 = [
            p["url"] for p in data.get("surface", {}).get("common_paths", [])
            if p.get("status_code") == 200
        ]
        if sensitive_200:
            findings.append(f"Sensitive paths returning HTTP 200 ({len(sensitive_200)}): {', '.join(sensitive_200)}")
    except Exception as exc:
        logger.error("[report_gen] Error summarising sensitive paths: %s", exc)

    try:
        ep_count = len(data.get("javascript", {}).get("endpoints", []))
        if ep_count:
            findings.append(f"API endpoint strings extracted from JavaScript: {ep_count}")
    except Exception as exc:
        logger.error("[report_gen] Error summarising endpoints: %s", exc)

    if not findings:
        findings.append("No significant findings detected during passive scan. Manual investigation is recommended.")

    return findings


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------

def _write_json(data: dict, path: Path) -> bool:
    try:
        with path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str, ensure_ascii=False)
        return True
    except Exception as exc:
        logger.error("[report_gen] Failed to write JSON report: %s", exc)
        return False


def _build_markdown(data: dict) -> str:
    lines: List[str] = []
    meta = data.get("meta", {})
    tech = data.get("technology", {})
    headers_data = data.get("headers", [])
    dns_data = data.get("dns", {})
    whois_data = data.get("whois", {})
    surface_data = data.get("surface", {})
    js_data = data.get("javascript", {})
    summary = data.get("findings_summary", [])

    lines.append(f"# Reconnaissance Report\n\n")
    lines.append(f"**Target:** {_sanitise_cell(meta.get('target', 'Unknown'))}\n\n")
    lines.append(f"**Scan Timestamp:** {_sanitise_cell(meta.get('scan_timestamp', 'Unknown'))}\n\n")
    lines.append(f"**Tool:** {_sanitise_cell(meta.get('tool_name', _TOOL_NAME))} v{_sanitise_cell(meta.get('tool_version', _TOOL_VERSION))}\n\n")
    lines.append("---\n\n")

    lines.append("## Legal Notice\n\n")
    lines.append("This tool is for authorised bug bounty hunters only. Unauthorised use is strictly prohibited.\n\n")
    lines.append("---\n\n")

    lines.append("## How To Use This Report\n\n")
    lines.append("**NEXT STEP:** Copy the entire contents of this Markdown report and paste it into an AI assistant such as ChatGPT or Claude.\n\n")
    lines.append("Ask the AI to:\n")
    lines.append("- Analyze the findings and identify potential vulnerabilities\n")
    lines.append("- Suggest which attack surfaces to prioritize\n")
    lines.append("- Recommend specific security tests to perform based on the discovered technology stack\n\n")
    lines.append("---\n\n")

    lines.append("## Technology Stack\n\n")
    lines.append("| Component | Detected Value |\n")
    lines.append(_md_table_separator(2))
    lines.append(_md_table_row("Web Server", tech.get("server_info", {}).get("server", "Not disclosed")))
    lines.append(_md_table_row("Platform", tech.get("server_info", {}).get("powered_by", "Not disclosed")))
    lines.append(_md_table_row("CMS", tech.get("cms", "Unknown or custom")))
    for fw in tech.get("frameworks", []):
        lines.append(_md_table_row("JS Framework", f"{fw.get('name')} ({fw.get('version')})"))
    lines.append("\n---\n\n")

    lines.append("## Security Header Audit\n\n")
    lines.append("| Header | Present | Notes |\n")
    lines.append(_md_table_separator(3))
    for h in headers_data:
        lines.append(_md_table_row(h.get("header_name"), "Yes" if h.get("present") else "No", h.get("notes")))
    lines.append("\n---\n\n")

    lines.append("## Cookie Security\n\n")
    if tech.get("cookies"):
        lines.append("| Cookie Name | HttpOnly | Secure | SameSite |\n")
        lines.append(_md_table_separator(4))
        for c in tech.get("cookies"):
            lines.append(_md_table_row(c.get("name"), "Yes" if c.get("httponly") else "No", "Yes" if c.get("secure") else "No", c.get("samesite")))
    else:
        lines.append("No cookies set.\n")
    lines.append("\n---\n\n")

    lines.append("## DNS Records\n\n")
    lines.append("### A Records\n\n")
    for ip in dns_data.get("a_records", []): lines.append(f"- `{ip}`\n")
    lines.append("\n### MX Records\n\n")
    for mx in dns_data.get("mx_records", []): lines.append(f"- Priority {mx.get('priority')}: `{mx.get('mail_server')}`\n")
    lines.append("\n### NS Records\n\n")
    for ns in dns_data.get("ns_records", []): lines.append(f"- `{ns}`\n")
    lines.append("\n### TXT Records\n\n")
    for txt in dns_data.get("txt_records", []): lines.append(f"- `{_sanitise_cell(txt)}`\n")
    lines.append("\n### CNAME Record\n\n")
    lines.append(f"- `{dns_data.get('cname_record')}`\n" if dns_data.get('cname_record') else "- None\n")
    lines.append("\n---\n\n")

    lines.append("## WHOIS Information\n\n")
    lines.append("| Field | Value |\n")
    lines.append(_md_table_separator(2))
    for k, v in whois_data.items():
        if isinstance(v, list): v = ", ".join(v)
        lines.append(_md_table_row(k.replace("_", " ").title(), v))
    lines.append("\n---\n\n")

    lines.append("## Discovered Links\n\n")
    internal = surface_data.get("links", {}).get("internal_links", [])
    lines.append(f"**Internal:** {len(internal)} | **External:** {len(surface_data.get('links', {}).get('external_links', []))}\n\n")
    for link in internal[:20]: lines.append(f"- {_sanitise_cell(link)}\n")
    lines.append("\n---\n\n")

    lines.append("## Forms Discovered\n\n")
    for idx, form in enumerate(surface_data.get("forms", []), 1):
        lines.append(f"### Form {idx}\n- **Action:** {form.get('action')}\n- **Method:** {form.get('method')}\n")
        for f in form.get("fields", []):
            lines.append(f"  - {f.get('name')} ({f.get('type')})\n")
        lines.append("\n")
    lines.append("---\n\n")

    lines.append("## URL Parameters Found\n\n")
    for param in surface_data.get("url_parameters", []): lines.append(f"- `{_sanitise_cell(param)}`\n")
    lines.append("\n---\n\n")

    lines.append("## Sensitive Path Check\n\n")
    lines.append("| Path | Status Code | Content Exists |\n")
    lines.append(_md_table_separator(3))
    for p in surface_data.get("common_paths", []):
        lines.append(_md_table_row(p.get("url"), p.get("status_code"), "Yes" if p.get("content_exists") else "No"))
    lines.append("\n---\n\n")

    lines.append("## JavaScript Analysis\n\n")
    lines.append(f"**First-party:** {len(js_data.get('first_party_scripts', []))} | **Third-party:** {len(js_data.get('third_party_scripts', []))}\n\n")
    lines.append("### Sensitive Keywords\n\n")
    kw_findings = js_data.get("keyword_findings", [])
    if kw_findings:
        lines.append("| File | Keyword | Line | Context |\n")
        lines.append(_md_table_separator(4))
        for f in kw_findings[:50]:
            lines.append(_md_table_row("…" + f.get("file", "")[-40:], f.get("keyword"), f.get("line_number"), f.get("context")))
    else:
        lines.append("No sensitive assignments found.\n")
    lines.append("\n### Endpoints\n\n")
    for ep in js_data.get("endpoints", []): lines.append(f"- `{_sanitise_cell(ep)}`\n")
    lines.append("\n---\n\n")

    lines.append("## Summary of Notable Findings\n\n")
    for finding in summary: lines.append(f"- {finding}\n")
    lines.append("\n---\n\n")

    lines.append("## Next Steps\n\n")
    lines.append("Copy this entire document and paste it into your AI assistant. The AI will formulate your specific testing strategy based on these findings.\n")

    return "".join(lines)


def _write_markdown(data: dict, path: Path) -> bool:
    try:
        with path.open("w", encoding="utf-8") as fh:
            fh.write(_build_markdown(data))
        return True
    except Exception as exc:
        logger.error("[report_gen] Failed to write Markdown: %s", exc)
        return False


def generate_reports(
    scan_data: dict,
    output_dir: Path,
    target_domain: str,
    custom_suffix: Optional[str] = None
) -> ReportPaths:
    """
    Generate JSON and MD reports.

    Args:
        scan_data: Complete dict.
        output_dir: Destination path.
        target_domain: Used for filename.
        custom_suffix: Appended to the filename if provided.
    """
    result: ReportPaths = {"json_path": None, "markdown_path": None}

    try:
        scan_data["findings_summary"] = _build_findings_summary(scan_data)
    except Exception as exc:
        scan_data["findings_summary"] = ["Error generating summary."]

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_domain = target_domain.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
    
    suffix = f"_{custom_suffix}" if custom_suffix else ""
    base_name = f"{clean_domain}{suffix}_{timestamp}"

    json_path = output_dir / f"{base_name}.json"
    md_path = output_dir / f"{base_name}.md"

    if _write_json(scan_data, json_path): result["json_path"] = json_path
    if _write_markdown(scan_data, md_path): result["markdown_path"] = md_path

    return result
