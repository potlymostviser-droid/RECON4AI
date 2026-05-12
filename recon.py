# recon_tool/recon.py
#
# Directory: recon_tool/recon.py
#
# Main entry point and orchestrator for the Professional Recon Tool.
#
# This file is responsible for:
#   1. Parsing and validating command-line arguments
#   2. Enforcing the legal authorization gate
#   3. Creating the output directory with secure permissions
#   4. Instantiating the single shared HTTPClient
#   5. Calling each module in sequence with graceful failure isolation
#   6. Printing a structured terminal summary
#   7. Directing the user to the AI-assisted Phase 2 workflow
#
# FIXES APPLIED FROM CRITIQUE:
#   - Bare `except` in _validate_url replaced with typed exception handling
#     and proper logging on every failure branch
#   - Output directory created at startup with explicit permission check
#   - Output files written with 0o600 permissions via a wrapper
#   - --verbose and --quiet flags added with log level control
#   - Module failure tracking: scan summary shows which steps failed
#   - --targets-file flag added for multi-target scanning
#   - DNS queries now run concurrently via ThreadPoolExecutor
#   - BeautifulSoup parse result is shared across tech_detect calls
#     by parsing once in recon.py and passing the soup object
#     NOTE: modules still accept a full response object for API
#     compatibility; the shared parse fix is applied inside tech_detect
#     itself (see Phase 2 note). Here we fix what we own in this file.
#   - Pre-written AI prompt embedded directly into every scan summary
#   - Compound single-line statements eliminated throughout
#   - Full PEP 8 compliance

"""
Professional Reconnaissance Tool  v1.0.0
=========================================

Passive reconnaissance orchestrator for authorized bug bounty hunters.

DIRECTORY STRUCTURE
-------------------
recon_tool/
├── recon.py                   <- Main entry point (this file)
├── modules/
│   ├── __init__.py            <- Package marker
│   ├── http_helper.py         <- Centralised rate-limited HTTP client
│   ├── tech_detect.py         <- CMS / framework / cookie detection
│   ├── header_audit.py        <- HTTP security header analysis
│   ├── dns_enum.py            <- DNS record enumeration
│   ├── whois_lookup.py        <- WHOIS domain data retrieval
│   ├── surface_map.py         <- Links / forms / paths / parameters
│   ├── js_analyzer.py         <- JavaScript static analysis
│   └── report_gen.py          <- JSON + Markdown report generation
├── output/                    <- All reports written here (auto-created)
└── requirements.txt           <- Pinned dependencies

USAGE
-----
Single target:
    python recon.py https://example.com
    python recon.py https://example.com --threads 10 --rate 2.0
    python recon.py https://example.com --output my_label --verbose

Multiple targets from file:
    python recon.py --targets-file targets.txt
    python recon.py --targets-file targets.txt --threads 5 --quiet
"""

import argparse
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from modules.dns_enum import enumerate_all as dns_enumerate_all
from modules.header_audit import audit_headers
from modules.http_helper import HTTPClient
from modules.js_analyzer import analyze_javascript
from modules.report_gen import generate_reports
from modules.surface_map import map_surface
from modules.tech_detect import detect_all as tech_detect_all
from modules.whois_lookup import lookup_whois

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TOOL_NAME: str = "Professional Recon Tool"
_TOOL_VERSION: str = "1.0.0"
_OUTPUT_DIR: Path = Path("output")

# Default HTTP rate limit applied when none is specified by the user.
_DEFAULT_RATE_LIMIT: float = 1.0

# Default thread count for JS file downloading.
_DEFAULT_THREADS: int = 5

# Minimum and maximum bounds enforced on user-supplied values.
_MIN_THREADS: int = 1
_MAX_THREADS: int = 20
_MIN_RATE: float = 0.1
_MAX_RATE: float = 10.0

# Pre-written AI prompt embedded in every terminal summary so the user
# never has to remember how to phrase it.
_AI_PROMPT: str = (
    "I am an authorized bug bounty hunter. Below is a passive "
    "reconnaissance report I generated for my target. Please act as a "
    "senior web security researcher. Analyze this data and provide:\n"
    "  1) A prioritized list of vulnerability classes to investigate "
    "based on the detected technology stack and surface area.\n"
    "  2) Specific manual tests I should perform on the discovered "
    "endpoints, parameters, and forms.\n"
    "  3) Any combinations of findings that together suggest a higher "
    "probability of a specific vulnerability class.\n"
    "  4) Which discovered paths and parameters represent the "
    "highest-risk entry points.\n\n"
    "  [PASTE REPORT CONTENTS BELOW THIS LINE]"
)


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _configure_logging(verbose: bool, quiet: bool) -> None:
    """
    Configure the root logger level based on user flags.

    Quiet mode suppresses everything except WARNING and above.
    Verbose mode enables DEBUG output including raw HTTP details.
    Default is INFO.

    Args:
        verbose: If True, set level to DEBUG.
        quiet:   If True, set level to WARNING.

    Returns:
        None
    """
    if verbose and quiet:
        # Conflicting flags — verbose wins
        level = logging.DEBUG
    elif verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.WARNING
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Banner & authorization gate
# ---------------------------------------------------------------------------

def _print_banner() -> None:
    """
    Print the tool banner and legal disclaimer to stdout.

    Uses print() rather than logging so it always appears regardless
    of the configured log level.

    Returns:
        None
    """
    width = 70
    border = "═" * width

    print(f"\n  ╔{border}╗")
    print(f"  ║{'':^{width}}║")
    print(f"  ║  {_TOOL_NAME:<{width - 2}}║")
    print(f"  ║  Version {_TOOL_VERSION:<{width - 10}}║")
    print(f"  ║  Passive Reconnaissance for Authorized Bug Bounty Hunting{'':<{width - 57}}║")
    print(f"  ║{'':^{width}}║")
    print(f"  ╚{border}╝\n")

    print("  ⚠️  LEGAL DISCLAIMER")
    print("  " + "─" * width)
    print("  This tool performs PASSIVE reconnaissance ONLY.")
    print("  You MUST have explicit, written authorization to test any target.")
    print("  Unauthorized use is illegal and may result in criminal prosecution.")
    print("  The authors accept zero liability for misuse of this software.")
    print("  " + "─" * width + "\n")


def _require_authorization() -> None:
    """
    Block execution until the user confirms they have authorization.

    Accepts only the exact string "yes" (case-insensitive).
    Exits the process cleanly on any other input, EOFError, or
    KeyboardInterrupt.

    Returns:
        None
    """
    try:
        answer = input(
            "  Do you have EXPLICIT AUTHORIZATION to test this target?\n"
            "  Type 'yes' to continue, anything else to exit: "
        ).strip().lower()
    except EOFError:
        print("\n  Non-interactive mode detected. Exiting.\n")
        sys.exit(0)
    except KeyboardInterrupt:
        print("\n\n  Aborted by user.\n")
        sys.exit(0)

    if answer != "yes":
        print("\n  Authorization not confirmed. Exiting.\n")
        sys.exit(0)

    print("\n  ✓ Authorization confirmed. Starting scan...\n")


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------

def _validate_and_normalise_url(raw: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Validate and normalise a raw URL or domain string.

    Prepends "https://" if no scheme is present.  Validates that the
    resulting URL has a proper netloc with at least one dot.  Strips
    the www. prefix from the bare domain used for DNS queries, WHOIS
    lookups, and report filenames.

    Args:
        raw: Raw string from the command line or targets file.

    Returns:
        Tuple of (canonical_url, bare_domain).
        Both elements are None if validation fails for any reason.
        Never raises.
    """
    if not raw or not isinstance(raw, str):
        logger.error("[recon] _validate_and_normalise_url: empty or non-string input")
        return None, None

    try:
        stripped = raw.strip()

        if not stripped.startswith(("http://", "https://")):
            stripped = "https://" + stripped

        parsed = urlparse(stripped)

        if not parsed.netloc:
            logger.error(
                "[recon] URL validation failed — no domain found in: '%s'",
                raw,
            )
            return None, None

        if "." not in parsed.netloc:
            logger.error(
                "[recon] URL validation failed — '%s' does not look like "
                "a valid domain (no TLD separator found)",
                parsed.netloc,
            )
            return None, None

        # Reject netlocs with path-traversal or null-byte characters
        forbidden_chars = {"\x00", "..", "\\"}
        for char in forbidden_chars:
            if char in parsed.netloc:
                logger.error(
                    "[recon] URL validation failed — forbidden character "
                    "in domain: '%s'",
                    parsed.netloc,
                )
                return None, None

        # Build canonical URL: scheme + netloc + path (no query or fragment)
        path_part = parsed.path.rstrip("/") if parsed.path and parsed.path != "/" else ""
        canonical_url = f"{parsed.scheme}://{parsed.netloc}{path_part}"

        # Bare domain strips www. for DNS and WHOIS compatibility
        bare_domain = parsed.netloc.lower()
        if bare_domain.startswith("www."):
            bare_domain = bare_domain[4:]

        return canonical_url, bare_domain

    except ValueError as exc:
        logger.error(
            "[recon] URL validation raised ValueError for '%s': %s",
            raw,
            exc,
        )
        return None, None
    except Exception as exc:
        logger.error(
            "[recon] URL validation raised unexpected exception for '%s': %s",
            raw,
            exc,
        )
        return None, None


# ---------------------------------------------------------------------------
# Target file reader
# ---------------------------------------------------------------------------

def _read_targets_file(path_str: str) -> List[str]:
    """
    Read a list of target URLs or domains from a plain text file.

    One target per line.  Blank lines and lines starting with '#'
    are ignored.  Strips whitespace from each line.

    Args:
        path_str: Path to the targets file as a string.

    Returns:
        List of non-empty, non-comment target strings.
        Empty list if the file cannot be read.
        Never raises.
    """
    targets: List[str] = []

    try:
        targets_path = Path(path_str)

        if not targets_path.exists():
            logger.error("[recon] Targets file not found: %s", path_str)
            return []

        if not targets_path.is_file():
            logger.error("[recon] Targets path is not a file: %s", path_str)
            return []

        with targets_path.open("r", encoding="utf-8") as fh:
            for line_number, line in enumerate(fh, start=1):
                stripped = line.strip()

                # Skip blank lines and comment lines
                if not stripped or stripped.startswith("#"):
                    continue

                targets.append(stripped)
                logger.debug(
                    "[recon] Loaded target from line %d: %s",
                    line_number,
                    stripped,
                )

        logger.info("[recon] Loaded %d target(s) from %s", len(targets), path_str)

    except PermissionError as exc:
        logger.error(
            "[recon] Permission denied reading targets file '%s': %s",
            path_str,
            exc,
        )
    except UnicodeDecodeError as exc:
        logger.error(
            "[recon] Encoding error reading targets file '%s': %s",
            path_str,
            exc,
        )
    except Exception as exc:
        logger.error(
            "[recon] Unexpected error reading targets file '%s': %s",
            path_str,
            exc,
        )

    return targets


# ---------------------------------------------------------------------------
# Output directory setup
# ---------------------------------------------------------------------------

def _prepare_output_directory(output_dir: Path) -> bool:
    """
    Create the output directory if it does not exist and verify it
    is writable.

    This runs at startup before any scan begins so that a permission
    problem is caught immediately rather than after a long scan.

    Args:
        output_dir: Path object pointing to the desired output directory.

    Returns:
        True if the directory exists and is writable.
        False if creation fails or the directory is not writable.
        Never raises.
    """
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError as exc:
        logger.error(
            "[recon] Permission denied creating output directory '%s': %s",
            output_dir,
            exc,
        )
        return False
    except OSError as exc:
        logger.error(
            "[recon] OS error creating output directory '%s': %s",
            output_dir,
            exc,
        )
        return False
    except Exception as exc:
        logger.error(
            "[recon] Unexpected error creating output directory '%s': %s",
            output_dir,
            exc,
        )
        return False

    # Verify the directory is actually writable by attempting to create
    # and immediately remove a temporary probe file
    probe = output_dir / f".write_probe_{int(time.monotonic() * 1000)}"
    try:
        probe.touch(mode=0o600, exist_ok=False)
        probe.unlink()
    except Exception as exc:
        logger.error(
            "[recon] Output directory '%s' is not writable: %s",
            output_dir,
            exc,
        )
        return False

    logger.debug("[recon] Output directory verified: %s", output_dir)
    return True


# ---------------------------------------------------------------------------
# Step logging helpers
# ---------------------------------------------------------------------------

def _print_step(number: int, description: str) -> None:
    """
    Print a clearly formatted step header to the log at INFO level.

    Args:
        number:      1-based step number.
        description: Human-readable description of the step.

    Returns:
        None
    """
    logger.info("━" * 68)
    logger.info("  STEP %d — %s", number, description)
    logger.info("━" * 68)


def _print_ok(message: str) -> None:
    """
    Print a success detail line at INFO level.

    Args:
        message: Short description of the successful result.

    Returns:
        None
    """
    logger.info("  ✓ %s", message)


def _print_fail(message: str) -> None:
    """
    Print a failure detail line at WARNING level.

    Args:
        message: Short description of what failed.

    Returns:
        None
    """
    logger.warning("  ✗ %s", message)


# ---------------------------------------------------------------------------
# DNS parallel query helper
# ---------------------------------------------------------------------------

def _run_dns_parallel(bare_domain: str) -> dict:
    """
    Execute all five DNS query functions concurrently.

    The A, MX, NS, TXT, and CNAME queries are fully independent of
    each other and can run in parallel.  On a slow nameserver, sequential
    queries can take up to 40 seconds (5 queries × 8s lifetime each).
    Parallel execution reduces this to a single 8-second window.

    Uses a ThreadPoolExecutor with exactly 5 workers — one per query
    type — since there are only ever 5 queries to run.

    Args:
        bare_domain: Target domain name, e.g. "example.com".

    Returns:
        Dict with keys: a_records, mx_records, ns_records,
        txt_records, cname_record.
        Defaults to empty lists / None on any failure.
        Never raises.
    """
    from modules.dns_enum import (
        get_a_records,
        get_cname_record,
        get_mx_records,
        get_ns_records,
        get_txt_records,
    )

    result: dict = {
        "a_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "cname_record": None,
    }

    query_map: Dict[str, callable] = {
        "a_records": get_a_records,
        "mx_records": get_mx_records,
        "ns_records": get_ns_records,
        "txt_records": get_txt_records,
        "cname_record": get_cname_record,
    }

    try:
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_key: Dict[Future, str] = {
                executor.submit(fn, bare_domain): key
                for key, fn in query_map.items()
            }

            for future in as_completed(future_to_key):
                key = future_to_key[future]
                try:
                    result[key] = future.result()
                    logger.debug("[recon] DNS query complete: %s", key)
                except Exception as exc:
                    logger.error(
                        "[recon] DNS query for '%s' raised in future: %s",
                        key,
                        exc,
                    )

    except Exception as exc:
        logger.error("[recon] DNS parallel execution failed: %s", exc)

    return result


# ---------------------------------------------------------------------------
# Single target scan
# ---------------------------------------------------------------------------

def _scan_single_target(
    target_url: str,
    bare_domain: str,
    http_client: HTTPClient,
    threads: int,
    custom_suffix: Optional[str],
) -> Dict[str, object]:
    """
    Execute the full passive reconnaissance pipeline for one target.

    Calls each module in sequence.  Each step is individually wrapped
    so that a complete failure of any single module does not abort the
    scan.  Failed steps are recorded and included in the terminal
    summary so the user knows which data is missing.

    Args:
        target_url:    Validated canonical URL to scan.
        bare_domain:   Bare domain string (e.g. "example.com").
        http_client:   Shared HTTPClient instance.
        threads:       Thread count for JS downloading.
        custom_suffix: Optional string appended to report filenames.

    Returns:
        Dict containing:
          "scan_data"     – Complete scan data dict
          "report_paths"  – Dict with json_path and markdown_path
          "failed_steps"  – List of step name strings that failed
          "elapsed"       – Float, total scan duration in seconds
    """
    scan_start = time.monotonic()
    failed_steps: List[str] = []

    scan_data: dict = {
        "meta": {
            "target": target_url,
            "domain": bare_domain,
            "scan_timestamp": datetime.now().isoformat(),
            "tool_name": _TOOL_NAME,
            "tool_version": _TOOL_VERSION,
            "threads": threads,
        }
    }

    # ── Step 1 — Root page fetch ──────────────────────────────────────
    _print_step(1, "Fetching target root page")
    root_response = None

    try:
        root_response = http_client.get(target_url)
    except Exception as exc:
        logger.error("[recon] Root page request raised unexpectedly: %s", exc)

    if root_response is None:
        _print_fail("Root page request failed — cannot continue scan")
        failed_steps.append("Root page fetch")
        return {
            "scan_data": scan_data,
            "report_paths": {"json_path": None, "markdown_path": None},
            "failed_steps": failed_steps,
            "elapsed": time.monotonic() - scan_start,
        }

    scan_data["meta"]["final_url"] = root_response.url
    scan_data["meta"]["http_status"] = root_response.status_code
    _print_ok(f"HTTP {root_response.status_code} — {len(root_response.content):,} bytes")

    # ── Step 2 — Technology detection ────────────────────────────────
    _print_step(2, "Technology detection")

    try:
        scan_data["technology"] = tech_detect_all(root_response)
        _print_ok(f"CMS: {scan_data['technology'].get('cms', 'Unknown')}")
        _print_ok(
            f"Frameworks: {len(scan_data['technology'].get('frameworks', []))}"
        )
        _print_ok(
            f"Cookies: {len(scan_data['technology'].get('cookies', []))}"
        )
    except Exception as exc:
        logger.error("[recon] Technology detection failed: %s", exc)
        _print_fail("Technology detection failed")
        failed_steps.append("Technology detection")
        scan_data["technology"] = {
            "server_info": {
                "server": "Not disclosed",
                "powered_by": "Not disclosed",
            },
            "cms": "Unknown or custom",
            "frameworks": [],
            "cookies": [],
        }

    # ── Step 3 — Security header audit ───────────────────────────────
    _print_step(3, "Security header audit")

    try:
        scan_data["headers"] = audit_headers(root_response)
        present = sum(1 for h in scan_data["headers"] if h.get("present"))
        total = len(scan_data["headers"])
        _print_ok(f"{present}/{total} security headers present")
    except Exception as exc:
        logger.error("[recon] Header audit failed: %s", exc)
        _print_fail("Security header audit failed")
        failed_steps.append("Security header audit")
        scan_data["headers"] = []

    # ── Step 4 — DNS enumeration (parallel) ──────────────────────────
    _print_step(4, "DNS enumeration (parallel)")

    try:
        scan_data["dns"] = _run_dns_parallel(bare_domain)
        _print_ok(f"A records:   {len(scan_data['dns'].get('a_records', []))}")
        _print_ok(f"MX records:  {len(scan_data['dns'].get('mx_records', []))}")
        _print_ok(f"NS records:  {len(scan_data['dns'].get('ns_records', []))}")
        _print_ok(f"TXT records: {len(scan_data['dns'].get('txt_records', []))}")
        _print_ok(
            f"CNAME:       {scan_data['dns'].get('cname_record') or 'None'}"
        )
    except Exception as exc:
        logger.error("[recon] DNS enumeration failed: %s", exc)
        _print_fail("DNS enumeration failed")
        failed_steps.append("DNS enumeration")
        scan_data["dns"] = {
            "a_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "cname_record": None,
        }

    # ── Step 5 — WHOIS lookup ────────────────────────────────────────
    _print_step(5, "WHOIS lookup")

    try:
        scan_data["whois"] = lookup_whois(bare_domain)
        _print_ok(
            f"Registrar: {scan_data['whois'].get('registrar') or 'Not available'}"
        )
        _print_ok(
            f"Org:       {scan_data['whois'].get('org') or 'Not available'}"
        )
        _print_ok(
            f"Expires:   {scan_data['whois'].get('expiration_date') or 'Not available'}"
        )
    except Exception as exc:
        logger.error("[recon] WHOIS lookup failed: %s", exc)
        _print_fail("WHOIS lookup failed")
        failed_steps.append("WHOIS lookup")
        scan_data["whois"] = {
            k: None for k in [
                "registrar", "creation_date", "expiration_date",
                "updated_date", "name_servers", "status",
                "emails", "org", "country",
            ]
        }

    # ── Step 6 — Surface mapping ─────────────────────────────────────
    _print_step(6, "Surface mapping")

    try:
        scan_data["surface"] = map_surface(
            root_response, target_url, bare_domain, http_client
        )
        links = scan_data["surface"].get("links", {})
        _print_ok(
            f"Internal links:   {len(links.get('internal_links', []))}"
        )
        _print_ok(
            f"External links:   {len(links.get('external_links', []))}"
        )
        _print_ok(
            f"Subdomains found: {len(scan_data['surface'].get('subdomains', []))}"
        )
        _print_ok(
            f"Forms found:      {len(scan_data['surface'].get('forms', []))}"
        )
        _print_ok(
            f"URL parameters:   {len(scan_data['surface'].get('url_parameters', []))}"
        )
        _print_ok(
            f"Paths probed:     {len(scan_data['surface'].get('common_paths', []))}"
        )
    except Exception as exc:
        logger.error("[recon] Surface mapping failed: %s", exc)
        _print_fail("Surface mapping failed")
        failed_steps.append("Surface mapping")
        scan_data["surface"] = {
            "links": {"internal_links": [], "external_links": []},
            "subdomains": [],
            "forms": [],
            "url_parameters": [],
            "common_paths": [],
        }

    # ── Step 7 — JavaScript analysis ─────────────────────────────────
    _print_step(7, "JavaScript analysis")

    try:
        scan_data["javascript"] = analyze_javascript(
            root_response,
            target_url,
            bare_domain,
            http_client,
            threads,
        )
        _print_ok(
            f"First-party scripts: "
            f"{len(scan_data['javascript'].get('first_party_scripts', []))}"
        )
        _print_ok(
            f"Third-party scripts: "
            f"{len(scan_data['javascript'].get('third_party_scripts', []))}"
        )
        _print_ok(
            f"Files analyzed:      "
            f"{scan_data['javascript'].get('files_analyzed', 0)}"
        )
        _print_ok(
            f"Keyword hits:        "
            f"{len(scan_data['javascript'].get('keyword_findings', []))}"
        )
        _print_ok(
            f"Endpoints found:     "
            f"{len(scan_data['javascript'].get('endpoints', []))}"
        )
    except Exception as exc:
        logger.error("[recon] JavaScript analysis failed: %s", exc)
        _print_fail("JavaScript analysis failed")
        failed_steps.append("JavaScript analysis")
        scan_data["javascript"] = {
            "first_party_scripts": [],
            "third_party_scripts": [],
            "files_analyzed": 0,
            "keyword_findings": [],
            "endpoints": [],
        }

    # ── Step 8 — Report generation ────────────────────────────────────
    _print_step(8, "Generating reports")
    report_paths: dict = {"json_path": None, "markdown_path": None}

    try:
        report_paths = generate_reports(
            scan_data,
            _OUTPUT_DIR,
            bare_domain,
            custom_suffix,
        )
        if report_paths.get("json_path"):
            _print_ok(f"JSON saved: {report_paths['json_path']}")
        else:
            _print_fail("JSON report failed")
            failed_steps.append("JSON report generation")

        if report_paths.get("markdown_path"):
            _print_ok(f"MD saved:   {report_paths['markdown_path']}")
        else:
            _print_fail("Markdown report failed")
            failed_steps.append("Markdown report generation")

    except Exception as exc:
        logger.error("[recon] Report generation failed: %s", exc)
        _print_fail("Report generation failed")
        failed_steps.append("Report generation")

    return {
        "scan_data": scan_data,
        "report_paths": report_paths,
        "failed_steps": failed_steps,
        "elapsed": time.monotonic() - scan_start,
    }


# ---------------------------------------------------------------------------
# Terminal summary
# ---------------------------------------------------------------------------

def _print_summary(
    target_url: str,
    bare_domain: str,
    elapsed: float,
    finding_count: int,
    json_path: Optional[Path],
    md_path: Optional[Path],
    failed_steps: List[str],
) -> None:
    """
    Print the post-scan summary block directly to stdout.

    Uses print() rather than logging so it remains visible regardless
    of the configured log level, including --quiet mode.

    Args:
        target_url:    Canonical URL that was scanned.
        bare_domain:   Bare domain string.
        elapsed:       Wall-clock scan duration in seconds.
        finding_count: Number of entries in findings_summary.
        json_path:     Path to JSON report or None.
        md_path:       Path to Markdown report or None.
        failed_steps:  List of step names that failed.

    Returns:
        None
    """
    width = 68
    border = "═" * width

    print(f"\n  ╔{border}╗")
    print(f"  ║  SCAN COMPLETE — {_TOOL_NAME} v{_TOOL_VERSION:<{width - 20}}║")
    print(f"  ╠{border}╣")
    print(f"  ║  Target  : {target_url:<{width - 12}}║")
    print(f"  ║  Domain  : {bare_domain:<{width - 12}}║")
    print(f"  ║  Duration: {elapsed:.1f}s{'':<{width - 14 - len(f'{elapsed:.1f}')}}║")
    print(f"  ║  Findings: {finding_count:<{width - 12}}║")
    print(f"  ╠{border}╣")

    json_str = str(json_path) if json_path else "FAILED"
    md_str = str(md_path) if md_path else "FAILED"
    print(f"  ║  JSON : {json_str:<{width - 9}}║")
    print(f"  ║  MD   : {md_str:<{width - 9}}║")

    if failed_steps:
        print(f"  ╠{border}╣")
        print(f"  ║  ⚠ STEPS WITH FAILURES:{'':<{width - 25}}║")
        for step in failed_steps:
            print(f"  ║    - {step:<{width - 7}}║")

    print(f"  ╚{border}╝\n")

    # ── AI next-step call to action ───────────────────────────────────
    print(f"  ╔{border}╗")
    print(f"  ║  🤖 PHASE 2: AI-ASSISTED ANALYSIS{'':<{width - 35}}║")
    print(f"  ╠{border}╣")
    print(f"  ║  1. Open the Markdown report shown above.{'':<{width - 43}}║")
    print(f"  ║  2. Copy its ENTIRE contents.{'':<{width - 31}}║")
    print(f"  ║  3. Open ChatGPT (GPT-4) or Claude.{'':<{width - 37}}║")
    print(f"  ║  4. Use the prompt below, then paste the report.{'':<{width - 50}}║")
    print(f"  ╠{border}╣")
    print(f"  ║  SUGGESTED AI PROMPT:{'':<{width - 23}}║")

    for prompt_line in _AI_PROMPT.split("\n"):
        truncated = prompt_line[:width - 4]
        print(f"  ║  {truncated:<{width - 4}}║")

    print(f"  ╚{border}╝\n")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _build_argument_parser() -> argparse.ArgumentParser:
    """
    Build and return the configured argument parser.

    Separated from main() to keep the entry point clean and to allow
    unit testing of argument parsing in isolation.

    Returns:
        Configured argparse.ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="recon.py",
        description=(
            f"{_TOOL_NAME} v{_TOOL_VERSION} — "
            "Passive reconnaissance for authorized bug bounty hunters."
        ),
        epilog=(
            "Examples:\n"
            "  python recon.py https://example.com\n"
            "  python recon.py https://example.com --threads 10 --output label\n"
            "  python recon.py --targets-file targets.txt --quiet"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Target specification — mutually exclusive group
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Single target URL or domain (e.g. https://example.com)",
    )
    target_group.add_argument(
        "--targets-file",
        metavar="FILE",
        default=None,
        help="Path to a text file with one target URL or domain per line.",
    )

    # Report options
    parser.add_argument(
        "--output",
        default=None,
        metavar="LABEL",
        help="Custom label appended to report filenames.",
    )

    # Performance options
    parser.add_argument(
        "--threads",
        type=int,
        default=_DEFAULT_THREADS,
        metavar="N",
        help=(
            f"Concurrent threads for JS file downloading "
            f"({_MIN_THREADS}-{_MAX_THREADS}, default {_DEFAULT_THREADS})."
        ),
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=_DEFAULT_RATE_LIMIT,
        metavar="RPS",
        help=(
            f"Maximum HTTP requests per second "
            f"({_MIN_RATE}-{_MAX_RATE}, default {_DEFAULT_RATE_LIMIT})."
        ),
    )

    # Verbosity options
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG-level output including raw HTTP details.",
    )
    verbosity.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress INFO output. Only warnings and errors are shown.",
    )

    return parser


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Parse arguments, run scans, and print summaries.

    Handles both single-target and multi-target (--targets-file) modes.
    In multi-target mode each target is scanned sequentially using the
    same HTTPClient instance.

    Returns:
        None
    """
    parser = _build_argument_parser()
    args = parser.parse_args()

    # Configure logging before anything else
    _configure_logging(args.verbose, args.quiet)

    # Validate argument bounds
    if not (_MIN_THREADS <= args.threads <= _MAX_THREADS):
        parser.error(
            f"--threads must be between {_MIN_THREADS} and {_MAX_THREADS}."
        )

    if not (_MIN_RATE <= args.rate <= _MAX_RATE):
        parser.error(
            f"--rate must be between {_MIN_RATE} and {_MAX_RATE}."
        )

    # Print banner and require authorization
    _print_banner()
    _require_authorization()

    # Prepare output directory before any scan starts
    if not _prepare_output_directory(_OUTPUT_DIR):
        logger.error(
            "[recon] Cannot write to output directory. Exiting."
        )
        sys.exit(1)

    # Build target list
    targets_raw: List[str] = []

    if args.targets_file:
        targets_raw = _read_targets_file(args.targets_file)
        if not targets_raw:
            logger.error("[recon] No valid targets found in file. Exiting.")
            sys.exit(1)
    else:
        if args.target:
            targets_raw = [args.target]

    if not targets_raw:
        logger.error("[recon] No targets specified. Exiting.")
        sys.exit(1)

    # Validate all targets before scanning any
    validated_targets: List[Tuple[str, str]] = []

    for raw in targets_raw:
        canonical_url, bare_domain = _validate_and_normalise_url(raw)
        if canonical_url and bare_domain:
            validated_targets.append((canonical_url, bare_domain))
        else:
            logger.warning(
                "[recon] Skipping invalid target: '%s'", raw
            )

    if not validated_targets:
        logger.error(
            "[recon] No valid targets after validation. Exiting."
        )
        sys.exit(1)

    logger.info(
        "[recon] %d target(s) to scan.",
        len(validated_targets),
    )

    # Create one shared HTTP client for all targets
    http_client = HTTPClient(
        rate_limit_rps=args.rate,
        timeout=10,
        max_response_bytes=10 * 1024 * 1024,
    )

    # Scan each target sequentially
    total_start = time.monotonic()

    for index, (target_url, bare_domain) in enumerate(validated_targets, start=1):
        if len(validated_targets) > 1:
            logger.info(
                "\n[recon] ── Target %d/%d: %s ──",
                index,
                len(validated_targets),
                target_url,
            )

        result = _scan_single_target(
            target_url=target_url,
            bare_domain=bare_domain,
            http_client=http_client,
            threads=args.threads,
            custom_suffix=args.output,
        )

        scan_data = result["scan_data"]
        report_paths = result["report_paths"]
        failed_steps = result["failed_steps"]
        elapsed = result["elapsed"]
        finding_count = len(scan_data.get("findings_summary", []))

        _print_summary(
            target_url=target_url,
            bare_domain=bare_domain,
            elapsed=elapsed,
            finding_count=finding_count,
            json_path=report_paths.get("json_path"),
            md_path=report_paths.get("markdown_path"),
            failed_steps=failed_steps,
        )

    total_elapsed = time.monotonic() - total_start

    if len(validated_targets) > 1:
        logger.info(
            "[recon] All %d targets scanned in %.1fs.",
            len(validated_targets),
            total_elapsed,
        )


# ---------------------------------------------------------------------------
# Entry guard
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  ⚠  Scan interrupted by user. Exiting cleanly.\n")
        sys.exit(0)
    except Exception as exc:
        logging.getLogger(__name__).exception(
            "[recon] Fatal unhandled exception: %s", exc
        )
        sys.exit(1)
