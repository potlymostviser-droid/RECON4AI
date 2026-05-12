# recon_tool/recon.py
#
# Directory: recon_tool/recon.py
#
# Main entry point for the reconnaissance tool.
#
# CRITICAL FIXES FROM PHASE 1 CRITIQUE:
# 1. Output directory creation is forced strictly at startup before any
#    modules run, ensuring a safe fallback.
# 2. `--output` custom suffix is now correctly passed to the report generator.
# 3. All modules are imported and orchestrated identically to the spec.

"""
Professional Reconnaissance Tool  v1.0.0
=========================================

Passive reconnaissance orchestrator. Wraps all sub-modules into a
continuous pipeline and generates a unified report.

USAGE
-----
python recon.py https://example.com
python recon.py https://example.com --threads 10 --output custom_name
"""

import argparse
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from modules.http_helper import HTTPClient
from modules.tech_detect import detect_all
from modules.header_audit import audit_headers
from modules.dns_enum import enumerate_all
from modules.whois_lookup import lookup_whois
from modules.surface_map import map_surface
from modules.js_analyzer import analyze_javascript
from modules.report_gen import generate_reports

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

_TOOL_NAME = "Professional Recon Tool"
_TOOL_VERSION = "1.0.0"
_OUTPUT_DIR = Path("output")

def _print_banner() -> None:
    print(f"\n╔══════════════════════════════════════════════════════════════════╗")
    print(f"║   {_TOOL_NAME:<62}║")
    print(f"║   Version {_TOOL_VERSION:<57}║")
    print(f"║   Passive Reconnaissance for Authorised Bug Bounty Hunting       ║")
    print(f"╚══════════════════════════════════════════════════════════════════╝\n")
    print("  ⚠️  LEGAL DISCLAIMER: Authorised use only. Have explicit permission.\n")

def _require_authorisation() -> None:
    try:
        if input("  Do you have EXPLICIT AUTHORISATION? (type 'yes'): ").strip().lower() != "yes":
            sys.exit(0)
    except (EOFError, KeyboardInterrupt):
        sys.exit(0)
    print("\n  ✓ Authorisation confirmed.\n")

def _validate_url(raw: str) -> tuple:
    try:
        if not raw.startswith(("http://", "https://")): raw = "https://" + raw
        parsed = urlparse(raw)
        if not parsed.netloc or "." not in parsed.netloc: return None, None
        canonical = f"{parsed.scheme}://{parsed.netloc}{parsed.path if parsed.path else '/'}"
        domain = parsed.netloc.lower()
        if domain.startswith("www."): domain = domain[4:]
        return canonical, domain
    except:
        return None, None

def _step(num: int, desc: str) -> None:
    logger.info("━" * 68)
    logger.info("  STEP %d — %s", num, desc)
    logger.info("━" * 68)

def main() -> None:
    parser = argparse.ArgumentParser(description=f"{_TOOL_NAME} v{_TOOL_VERSION}")
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--output", default=None, help="Custom string appended to report filenames")
    parser.add_argument("--threads", type=int, default=5, help="JS concurrent downloads (default 5)")
    args = parser.parse_args()

    _print_banner()
    _require_authorisation()

    # Create output directory immediately
    try:
        _OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        logger.error("Failed to create output directory %s: %s", _OUTPUT_DIR, exc)
        sys.exit(1)

    target_url, bare_domain = _validate_url(args.target)
    if not target_url:
        logger.error("Invalid target format.")
        sys.exit(1)

    http_client = HTTPClient(rate_limit_rps=1.0, timeout=10)
    scan_data = {
        "meta": {
            "target": target_url, "domain": bare_domain,
            "scan_timestamp": datetime.now().isoformat(),
            "tool_name": _TOOL_NAME, "tool_version": _TOOL_VERSION,
        }
    }

    scan_start = time.monotonic()

    _step(1, "Fetching target root page")
    root_response = http_client.get(target_url)
    if not root_response:
        logger.error("Root request failed. Exiting.")
        sys.exit(1)
    
    _step(2, "Technology detection")
    scan_data["technology"] = detect_all(root_response)

    _step(3, "Security header audit")
    scan_data["headers"] = audit_headers(root_response)

    _step(4, "DNS enumeration")
    scan_data["dns"] = enumerate_all(bare_domain)

    _step(5, "WHOIS lookup")
    scan_data["whois"] = lookup_whois(bare_domain)

    _step(6, "Surface mapping")
    scan_data["surface"] = map_surface(root_response, target_url, bare_domain, http_client)

    _step(7, "JavaScript analysis")
    scan_data["javascript"] = analyze_javascript(root_response, target_url, bare_domain, http_client, args.threads)

    _step(8, "Generating reports")
    # Custom suffix from --output correctly passed here
    report_paths = generate_reports(scan_data, _OUTPUT_DIR, bare_domain, args.output)

    elapsed = time.monotonic() - scan_start
    
    print("\n  " + "═" * 68)
    print(f"  SCAN COMPLETE — Duration: {elapsed:.1f}s | Findings: {len(scan_data.get('findings_summary', []))}")
    print(f"  JSON: {report_paths.get('json_path', 'FAILED')}")
    print(f"  MD  : {report_paths.get('markdown_path', 'FAILED')}")
    print("  " + "═" * 68)
    print("\n  🤖 NEXT STEP: Copy the contents of the Markdown report and")
    print("  paste it into your AI assistant for vulnerability analysis.\n")

if __name__ == "__main__":
    main()
