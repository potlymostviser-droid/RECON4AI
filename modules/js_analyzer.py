# recon_tool/modules/js_analyzer.py
#
# Directory: recon_tool/modules/js_analyzer.py
#
# JavaScript file discovery, download, and static analysis module.
#
# CRITICAL FIX FROM PHASE 1 CRITIQUE:
# The previous version used bare word regexes (e.g. `\btoken\b`) which
# resulted in thousands of false positives (matching variable declarations,
# console.log statements, etc.). This version wraps every target keyword
# in an assignment-context regex, meaning it only flags the keyword if
# it is immediately followed by an assignment operator (= or :) and a
# value indicator (quote, true/false, or a digit).

"""
js_analyzer
===========
Performs static analysis of JavaScript files served by the target.

Execution flow
--------------
1. Parses <script src> tags and separates first-party from third-party.
2. Downloads first-party files concurrently using the ThreadPoolExecutor.
3. Scans file content for sensitive keyword assignments.
4. Extracts API endpoint paths using conservative regex patterns.

Context snippets around keyword matches are limited to 80 characters.
Actual secrets are not extracted or verified — this module only flags
the *location* of potential secrets for manual review.

Public API
----------
    analyze_javascript(response, base_url, target_domain, http_client, max_workers) -> dict
"""

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from modules.http_helper import HTTPClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

JSFiles = Dict[str, List[str]]
JSContents = Dict[str, str]
KeywordFinding = Dict[str, Any]
JSReport = Dict[str, Any]


# ---------------------------------------------------------------------------
# Keyword and endpoint patterns
# ---------------------------------------------------------------------------

_RAW_KEYWORDS: tuple = (
    "api_key", "apikey", "api-key", "secret", "secret_key", "token",
    "access_token", "auth_token", "password", "passwd", "pwd", "admin",
    "debug", "private_key", "aws_access", "aws_secret", "bearer"
)

# Build context-aware patterns. This matches the keyword (optionally in
# quotes), followed by whitespace, an assignment operator (: or =),
# whitespace, and then the start of a value (a quote, digit, or boolean).
_KEYWORD_PATTERNS: List[re.Pattern] = [
    re.compile(
        rf'(?:["\']?(?:{re.escape(kw)})["\']?)\s*[:=]\s*(?:["\'\d]|true|false)',
        re.IGNORECASE
    )
    for kw in _RAW_KEYWORDS
]

# Endpoint extraction pattern
_ENDPOINT_PATTERN: re.Pattern = re.compile(
    r'["\'](/(?:api|v\d+|graphql)/[^"\'?\s]{1,100})["\']'
)


# ---------------------------------------------------------------------------
# 8a — JS file discovery
# ---------------------------------------------------------------------------

def discover_js_files(
    response, base_url: str, target_domain: str
) -> JSFiles:
    """
    Parse the page for <script src> tags and categorise each URL.

    Args:
        response:      `requests.Response` for the root page.
        base_url:      Canonical root URL.
        target_domain: Bare domain, e.g. "example.com".

    Returns:
        Dict with keys "first_party_scripts" and "third_party_scripts".
    """
    first_party: set = set()
    third_party: set = set()

    try:
        soup = BeautifulSoup(response.text, "html.parser")

        for script_tag in soup.find_all("script", src=True):
            raw_src: str = script_tag.get("src", "").strip()
            if not raw_src:
                continue

            absolute = urljoin(base_url, raw_src)

            try:
                parsed = urlparse(absolute)
            except ValueError:
                continue

            netloc = parsed.netloc.lower()
            if target_domain in netloc or not netloc:
                first_party.add(absolute)
            else:
                third_party.add(absolute)

    except Exception as exc:
        logger.error("[js_analyzer] JS file discovery failed: %s", exc)

    return {
        "first_party_scripts": sorted(first_party),
        "third_party_scripts": sorted(third_party),
    }


# ---------------------------------------------------------------------------
# 8b — Concurrent JS downloading
# ---------------------------------------------------------------------------

def _download_single_file(
    url: str, http_client: HTTPClient
) -> Tuple[str, str]:
    """
    Download one JavaScript file safely.

    Args:
        url:         Fully-qualified URL.
        http_client: Shared HTTPClient instance.

    Returns:
        Tuple of (url, content). Content is "" on failure.
    """
    try:
        response = http_client.get(url)
        if response is not None and response.status_code == 200:
            return (url, response.text)
        logger.warning(
            "[js_analyzer] Non-200 or failed response for JS file: %s", url
        )
        return (url, "")
    except Exception as exc:
        logger.error("[js_analyzer] Error downloading %s: %s", url, exc)
        return (url, "")


def download_js_files(
    urls: List[str],
    http_client: HTTPClient,
    max_workers: int,
) -> JSContents:
    """
    Download multiple JS files concurrently.

    Args:
        urls:        List of JS file URLs.
        http_client: Shared HTTPClient.
        max_workers: Thread count.

    Returns:
        Dict mapping URL -> file content string.
    """
    contents: JSContents = {}

    if not urls:
        return contents

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(_download_single_file, url, http_client): url
                for url in urls
            }
            for future in as_completed(future_map):
                try:
                    url, content = future.result()
                    if content:
                        contents[url] = content
                except Exception as exc:
                    logger.error(
                        "[js_analyzer] Thread pool future raised: %s", exc
                    )

    except Exception as exc:
        logger.error("[js_analyzer] Thread pool error: %s", exc)

    return contents


# ---------------------------------------------------------------------------
# 8c — Keyword scanning
# ---------------------------------------------------------------------------

def scan_for_keywords(js_contents: JSContents) -> List[KeywordFinding]:
    """
    Search JS files for sensitive keyword assignments.

    Args:
        js_contents: Dict mapping URL -> file text.

    Returns:
        List of KeywordFinding dicts.
    """
    findings: List[KeywordFinding] = []

    try:
        for url, content in js_contents.items():
            if not content:
                continue

            lines = content.splitlines()

            for pattern in _KEYWORD_PATTERNS:
                for line_number, line in enumerate(lines, start=1):
                    for match in pattern.finditer(line):
                        start = max(0, match.start() - 40)
                        end = min(len(line), match.end() + 40)
                        snippet = line[start:end].strip()

                        findings.append(
                            {
                                "file": url,
                                "keyword": pattern.pattern,
                                "line_number": line_number,
                                "context": snippet,
                            }
                        )

    except Exception as exc:
        logger.error("[js_analyzer] Keyword scan failed: %s", exc)

    return findings


# ---------------------------------------------------------------------------
# 8d — Endpoint extraction
# ---------------------------------------------------------------------------

def extract_endpoints(js_contents: JSContents) -> List[str]:
    """
    Extract API endpoint path strings from JS files.

    Args:
        js_contents: Dict mapping URL -> file text.

    Returns:
        Deduplicated, sorted list of endpoint paths.
    """
    endpoints: set = set()

    try:
        for content in js_contents.values():
            if not content:
                continue
            for match in _ENDPOINT_PATTERN.finditer(content):
                endpoints.add(match.group(1))

    except Exception as exc:
        logger.error("[js_analyzer] Endpoint extraction failed: %s", exc)

    return sorted(endpoints)


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

def analyze_javascript(
    response,
    base_url: str,
    target_domain: str,
    http_client: HTTPClient,
    max_workers: int,
) -> JSReport:
    """
    Orchestrate JS discovery, downloading, and analysis.

    Args:
        response:      `requests.Response` for the root page.
        base_url:      Canonical root URL.
        target_domain: Bare domain string.
        http_client:   Shared HTTPClient instance.
        max_workers:   Thread count.

    Returns:
        JSReport dict.
    """
    try:
        js_files = discover_js_files(response, base_url, target_domain)

        logger.info(
            "[js_analyzer] Downloading %d first-party JS file(s)...",
            len(js_files["first_party_scripts"]),
        )
        js_contents = download_js_files(
            js_files["first_party_scripts"], http_client, max_workers
        )

        return {
            "first_party_scripts": js_files["first_party_scripts"],
            "third_party_scripts": js_files["third_party_scripts"],
            "files_analyzed": len(js_contents),
            "keyword_findings": scan_for_keywords(js_contents),
            "endpoints": extract_endpoints(js_contents),
        }

    except Exception as exc:
        logger.error("[js_analyzer] analyze_javascript failed: %s", exc)
        return {
            "first_party_scripts": [],
            "third_party_scripts": [],
            "files_analyzed": 0,
            "keyword_findings": [],
            "endpoints": [],
        }
