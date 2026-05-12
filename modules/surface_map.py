# recon_tool/modules/surface_map.py
#
# Directory: recon_tool/modules/surface_map.py
#
# Attack surface mapping: links, subdomains, forms, parameters, paths.
#
# Extracts all surface-level data that an attacker would enumerate
# during passive reconnaissance:
#   * Internal and external hyperlinks
#   * Subdomains mentioned in page source
#   * HTML forms (action, method, fields)
#   * URL query parameter names
#   * HTTP responses from a fixed list of sensitive paths
#
# CRITICAL FIX FROM PHASE 1 CRITIQUE:
# The previous implementation used `urljoin(base_url, path)` which
# would fail if `base_url` contained a path component (e.g.
# "https://example.com/subdir/").  This version strips to the origin
# before joining paths so that path checks always query the site root.

"""
surface_map
===========
Extracts attack-surface data from the target page and probes for
common sensitive paths.

All HTML parsing uses `html.parser` (stdlib) to avoid the lxml
dependency.  All network requests use the shared `HTTPClient` instance
passed by the caller — this module never constructs its own HTTP
connections.

Public API
----------
    map_surface(response, base_url, target_domain, http_client) -> dict
"""

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup

from modules.http_helper import HTTPClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

LinkReport = Dict[str, List[str]]
FormField = Dict[str, Any]
FormReport = Dict[str, Any]
PathResult = Dict[str, Any]
SurfaceReport = Dict[str, Any]


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _parse_html(html_text: str) -> Optional[BeautifulSoup]:
    """
    Parse an HTML string into a BeautifulSoup document.

    Args:
        html_text: Raw HTML string.

    Returns:
        BeautifulSoup document, or None if parsing fails.
    """
    try:
        return BeautifulSoup(html_text, "html.parser")
    except Exception as exc:
        logger.error("[surface_map] HTML parse error: %s", exc)
        return None


def _extract_origin(url: str) -> str:
    """
    Extract the scheme + netloc origin from a URL.

    Used to ensure path probes always target the site root regardless
    of whether the base URL contained a path component.

    Args:
        url: Full URL string.

    Returns:
        Origin string, e.g. "https://example.com".
    """
    try:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    except Exception as exc:
        logger.error("[surface_map] Failed to extract origin from %s: %s", url, exc)
        return url  # Fallback to original URL


# ---------------------------------------------------------------------------
# 7a — Link extraction
# ---------------------------------------------------------------------------

def extract_links(
    response, base_url: str, target_domain: str
) -> LinkReport:
    """
    Extract and categorise all hyperlinks from the page.

    Relative URLs are resolved against `base_url`.  Each link is
    classified as internal (same apex domain as `target_domain`) or
    external.  Both lists are deduplicated and sorted for stable output.

    Fragment-only hrefs (e.g. "#top"), empty hrefs, and javascript:
    pseudo-URLs are skipped.

    Args:
        response:      A `requests.Response` object.
        base_url:      The canonical URL of the target's root page.
        target_domain: The bare domain, e.g. "example.com".

    Returns:
        Dict with keys:
          "internal_links" – List[str]
          "external_links" – List[str]
    """
    internal: set = set()
    external: set = set()

    try:
        soup = _parse_html(response.text)
        if soup is None:
            return {"internal_links": [], "external_links": []}

        for tag in soup.find_all("a", href=True):
            href: str = tag["href"].strip()

            # Skip empty, fragment-only, and javascript: hrefs
            if (
                not href
                or href.startswith("#")
                or href.lower().startswith("javascript:")
            ):
                continue

            absolute = urljoin(base_url, href)

            try:
                parsed = urlparse(absolute)
            except ValueError:
                continue

            # Classify by netloc: target_domain present = internal
            netloc = parsed.netloc.lower()
            if target_domain in netloc:
                internal.add(absolute)
            elif netloc:
                external.add(absolute)
            # Links with no netloc after urljoin are malformed — skip

    except Exception as exc:
        logger.error("[surface_map] Link extraction failed: %s", exc)

    return {
        "internal_links": sorted(internal),
        "external_links": sorted(external),
    }


# ---------------------------------------------------------------------------
# 7b — Subdomain extraction
# ---------------------------------------------------------------------------

def extract_subdomains(response, target_domain: str) -> List[str]:
    """
    Find subdomain references in the raw page source.

    Uses a regex anchored to `target_domain` to find strings of the
    form `<label>.<label>....<target_domain>`.  The main domain itself
    is excluded from results (we want sub-domains only).

    Args:
        response:      A `requests.Response` object.
        target_domain: The bare domain, e.g. "example.com".

    Returns:
        Deduplicated, sorted list of subdomain strings.
    """
    subdomains: set = set()

    try:
        html_text = response.text
        escaped = re.escape(target_domain)

        # Pattern: one or more DNS label prefixes followed by the domain
        # Each label is alphanumeric with optional internal hyphens
        pattern = re.compile(
            r'([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
            r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.'
            r')' + escaped,
            re.IGNORECASE,
        )

        for match in pattern.finditer(html_text):
            full = match.group(0).lower()
            # Exclude bare domain and www variant
            if full != target_domain and full != f"www.{target_domain}":
                subdomains.add(full)

    except Exception as exc:
        logger.error("[surface_map] Subdomain extraction failed: %s", exc)

    return sorted(subdomains)


# ---------------------------------------------------------------------------
# 7c — Form extraction
# ---------------------------------------------------------------------------

def extract_forms(response, base_url: str) -> List[FormReport]:
    """
    Extract HTML forms and their input fields.

    For each <form>, records:
      * action URL (resolved to absolute)
      * method (GET or POST, upper-cased; defaults to GET)
      * list of fields: name, type, value, and whether hidden

    <textarea> and <select> elements are included as form fields because
    they are equally relevant to parameter injection testing.

    Args:
        response: A `requests.Response` object.
        base_url: Used to resolve relative action URLs.

    Returns:
        List of form dicts.  Empty list if no forms or on error.
    """
    forms: List[FormReport] = []

    try:
        soup = _parse_html(response.text)
        if soup is None:
            return forms

        for form_tag in soup.find_all("form"):
            raw_action: str = form_tag.get("action", "")
            action = urljoin(base_url, raw_action) if raw_action else base_url
            method: str = form_tag.get("method", "GET").upper()

            fields: List[FormField] = []

            # ── Input fields ──────────────────────────────────────────
            for input_tag in form_tag.find_all("input"):
                field_type: str = input_tag.get("type", "text").lower()
                fields.append(
                    {
                        "name": input_tag.get("name", ""),
                        "type": field_type,
                        "value": input_tag.get("value", ""),
                        "hidden": field_type == "hidden",
                    }
                )

            # ── Textarea fields ───────────────────────────────────────
            for textarea_tag in form_tag.find_all("textarea"):
                fields.append(
                    {
                        "name": textarea_tag.get("name", ""),
                        "type": "textarea",
                        "value": "",
                        "hidden": False,
                    }
                )

            # ── Select fields ─────────────────────────────────────────
            for select_tag in form_tag.find_all("select"):
                fields.append(
                    {
                        "name": select_tag.get("name", ""),
                        "type": "select",
                        "value": "",
                        "hidden": False,
                    }
                )

            forms.append(
                {
                    "action": action,
                    "method": method,
                    "fields": fields,
                }
            )

    except Exception as exc:
        logger.error("[surface_map] Form extraction failed: %s", exc)

    return forms


# ---------------------------------------------------------------------------
# 7d — URL parameter extraction
# ---------------------------------------------------------------------------

def extract_url_parameters(all_links: List[str]) -> List[str]:
    """
    Collect unique query-parameter names from a list of URLs.

    Only parameter names are recorded — not values — to avoid
    inadvertently capturing sensitive data that appears in URLs
    (e.g. session tokens in legacy links).

    Args:
        all_links: Combined list of internal and external links.

    Returns:
        Deduplicated, sorted list of parameter name strings.
    """
    param_names: set = set()

    try:
        for link in all_links:
            try:
                parsed = urlparse(link)
                if parsed.query:
                    for name in parse_qs(parsed.query, keep_blank_values=True):
                        param_names.add(name)
            except Exception as inner_exc:
                logger.debug(
                    "[surface_map] Skipping malformed URL in param "
                    "extraction: %s (%s)",
                    link,
                    inner_exc,
                )

    except Exception as exc:
        logger.error("[surface_map] URL parameter extraction failed: %s", exc)

    return sorted(param_names)


# ---------------------------------------------------------------------------
# 7e — Common path probing
# ---------------------------------------------------------------------------

# Exact list from the specification — do not add to this.
_SENSITIVE_PATHS: tuple = (
    "/robots.txt",
    "/sitemap.xml",
    "/.env",
    "/.git/HEAD",
    "/backup/",
    "/admin/",
    "/phpinfo.php",
    "/.htaccess",
    "/wp-config.php",
    "/config.php",
)


def check_common_paths(
    base_url: str, http_client: HTTPClient
) -> List[PathResult]:
    """
    Probe a fixed list of sensitive paths and record HTTP status codes.

    Only the status code and whether the response body is non-empty are
    stored.  Response body content is never read, logged, or stored,
    to avoid accidentally capturing sensitive data.

    CRITICAL FIX:
    Always probe against the site origin, not the full base_url which
    may contain a path component.  This ensures we check
    "https://example.com/.env" not "https://example.com/subdir/.env".

    Args:
        base_url:    The canonical root URL of the target.
        http_client: Shared HTTPClient instance.

    Returns:
        List of dicts, each with keys:
          "url"            – str, full URL probed
          "status_code"    – int (0 if request failed entirely)
          "content_exists" – bool (True if body was non-empty)
    """
    results: List[PathResult] = []

    # Extract origin to ensure we always probe the site root
    origin = _extract_origin(base_url)

    for path in _SENSITIVE_PATHS:
        # Path always starts with / so we can concatenate directly
        full_url = origin + path

        try:
            response = http_client.get(full_url)
            if response is not None:
                results.append(
                    {
                        "url": full_url,
                        "status_code": response.status_code,
                        "content_exists": len(response.content) > 0,
                    }
                )
            else:
                results.append(
                    {
                        "url": full_url,
                        "status_code": 0,
                        "content_exists": False,
                    }
                )
        except Exception as exc:
            logger.error(
                "[surface_map] Path check failed for %s: %s", full_url, exc
            )
            results.append(
                {
                    "url": full_url,
                    "status_code": 0,
                    "content_exists": False,
                }
            )

    return results


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

def map_surface(
    response,
    base_url: str,
    target_domain: str,
    http_client: HTTPClient,
) -> SurfaceReport:
    """
    Orchestrate all surface-mapping functions and return a unified report.

    Args:
        response:      `requests.Response` for the target root page.
        base_url:      Canonical root URL.
        target_domain: Bare domain string.
        http_client:   Shared HTTPClient instance.

    Returns:
        Dict with keys:
          "links"          – LinkReport
          "subdomains"     – List[str]
          "forms"          – List[FormReport]
          "url_parameters" – List[str]
          "common_paths"   – List[PathResult]
    """
    try:
        links = extract_links(response, base_url, target_domain)
        all_links = links["internal_links"] + links["external_links"]

        return {
            "links": links,
            "subdomains": extract_subdomains(response, target_domain),
            "forms": extract_forms(response, base_url),
            "url_parameters": extract_url_parameters(all_links),
            "common_paths": check_common_paths(base_url, http_client),
        }

    except Exception as exc:
        logger.error("[surface_map] map_surface failed: %s", exc)
        return {
            "links": {"internal_links": [], "external_links": []},
            "subdomains": [],
            "forms": [],
            "url_parameters": [],
            "common_paths": [],
        }
