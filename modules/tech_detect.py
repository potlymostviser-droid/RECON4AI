# recon_tool/modules/tech_detect.py
#
# Directory: recon_tool/modules/tech_detect.py
#
# Technology and infrastructure fingerprinting module.
#
# Performs passive detection of web technologies from a single HTTP
# response object.  This module makes ZERO additional network requests;
# it works entirely from the response data supplied by the caller.
#
# Detection is intentionally conservative: we only assert a match when
# a known, documented indicator is present.  When uncertain, we return
# "Unknown or custom" rather than guessing.

"""
tech_detect
===========
Passive technology stack detection from HTTP responses.

Detection categories
--------------------
1. Web server identification via Server and X-Powered-By headers
2. CMS identification via HTML patterns and meta tags
3. JavaScript framework detection via <script src> patterns
4. Cookie security flag audit (HttpOnly, Secure, SameSite)

All detection functions are independent and isolated.  A failure in
one detector does not prevent the others from running.

Public API
----------
    detect_all(response) -> dict
"""

import logging
import re
from typing import Any, Dict, List, Optional

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Type aliases for documentation clarity
# ---------------------------------------------------------------------------

ServerInfo = Dict[str, str]
FrameworkInfo = Dict[str, str]
CookieInfo = Dict[str, Any]
TechReport = Dict[str, Any]


# ---------------------------------------------------------------------------
# Internal HTML parsing helper
# ---------------------------------------------------------------------------

def _parse_html(response_text: str) -> Optional[BeautifulSoup]:
    """
    Parse an HTML string into a BeautifulSoup document.

    Uses the pure-Python `html.parser` backend to avoid requiring the
    lxml C extension.  This parser is slower but has no compiled
    dependencies beyond the standard library and beautifulsoup4.

    Args:
        response_text: Raw HTML string from response.text.

    Returns:
        BeautifulSoup document, or None if parsing fails.
    """
    try:
        return BeautifulSoup(response_text, "html.parser")
    except Exception as exc:
        logger.error("[tech_detect] HTML parse failed: %s", exc)
        return None


def _extract_version_from_src(src: str) -> str:
    """
    Attempt to extract a semantic version string from a script src URL.

    Tries three common version-encoding patterns in order:
      1. @major.minor.patch        (e.g. /vue@3.4.1/dist/vue.min.js)
      2. -major.minor.patch[./]    (e.g. jquery-3.6.0.min.js)
      3. /major.minor.patch/       (e.g. /libs/3.6.0/jquery.js)

    Version numbers may be two-part (x.y) or three-part (x.y.z).
    If no pattern matches, "version unknown" is returned.  No guessing.

    Args:
        src: The `src` attribute value from a <script> tag.

    Returns:
        Version string such as "3.6.0", or "version unknown".
    """
    patterns = [
        r'@(\d+\.\d+(?:\.\d+)?)',           # @x.y or @x.y.z
        r'-(\d+\.\d+(?:\.\d+)?)[\./]',      # -x.y.z. or -x.y.z/
        r'/(\d+\.\d+(?:\.\d+)?)[/.]',       # /x.y.z/ or /x.y.z.
    ]
    for pattern in patterns:
        match = re.search(pattern, src)
        if match:
            return match.group(1)
    return "version unknown"


# ---------------------------------------------------------------------------
# 3a — Web server detection
# ---------------------------------------------------------------------------

def detect_web_server(response) -> ServerInfo:
    """
    Extract web server technology from HTTP response headers.

    Reads the `Server` and `X-Powered-By` headers only.  Both are
    optional; their absence is not an error — many production servers
    suppress them deliberately.

    Args:
        response: A `requests.Response` object.

    Returns:
        Dict with keys:
          "server"     – value of the Server header, or "Not disclosed"
          "powered_by" – value of X-Powered-By, or "Not disclosed"
    """
    try:
        headers = response.headers
        return {
            "server": headers.get("Server", "Not disclosed"),
            "powered_by": headers.get("X-Powered-By", "Not disclosed"),
        }
    except Exception as exc:
        logger.error("[tech_detect] Server detection failed: %s", exc)
        return {
            "server": "Not disclosed",
            "powered_by": "Not disclosed",
        }


# ---------------------------------------------------------------------------
# 3b — CMS detection
# ---------------------------------------------------------------------------

def detect_cms(response) -> str:
    """
    Identify the CMS from known HTML signatures and response headers.

    Checks only the five CMS platforms specified:
      - WordPress
      - Joomla
      - Drupal
      - Shopify
      - Wix

    Uses indicators that are definitively associated with each platform.
    Returns "Unknown or custom" when no match is found.  No guessing.

    Detection order matters: more specific checks run first to avoid
    false positives.

    Args:
        response: A `requests.Response` object.

    Returns:
        One of: "WordPress", "Joomla", "Drupal", "Shopify", "Wix",
        or "Unknown or custom".
    """
    try:
        html_text = response.text
        headers = response.headers

        # ── WordPress (body pattern is strongest signal) ──────────────
        if "/wp-content/" in html_text or "/wp-includes/" in html_text:
            return "WordPress"

        # ── Parse HTML once for meta-tag checks ───────────────────────
        soup = _parse_html(html_text)
        if soup is not None:
            generator_tag = soup.find("meta", attrs={"name": "generator"})
            if generator_tag:
                content = generator_tag.get("content", "").lower()

                if "wordpress" in content:
                    return "WordPress"
                if "joomla" in content:
                    return "Joomla"
                if "drupal" in content:
                    return "Drupal"

        # ── Joomla (HTML body pattern) ────────────────────────────────
        if "/components/com_" in html_text:
            return "Joomla"

        # ── Drupal (response header) ──────────────────────────────────
        x_generator = headers.get("X-Generator", "")
        if "drupal" in x_generator.lower():
            return "Drupal"

        # ── Shopify (CDN hostname in HTML) ────────────────────────────
        if "cdn.shopify.com" in html_text:
            return "Shopify"

        # ── Wix (static asset CDN) ────────────────────────────────────
        if "static.wixstatic.com" in html_text:
            return "Wix"

        return "Unknown or custom"

    except Exception as exc:
        logger.error("[tech_detect] CMS detection failed: %s", exc)
        return "Unknown or custom"


# ---------------------------------------------------------------------------
# 3c — JavaScript framework detection
# ---------------------------------------------------------------------------

def detect_frameworks(response) -> List[FrameworkInfo]:
    """
    Identify JavaScript frameworks from <script src> attributes.

    Inspects every <script> tag that carries a `src` attribute and
    matches it against known filename / path patterns for five
    frameworks:
      - React
      - Vue.js
      - Angular
      - jQuery
      - Bootstrap

    Version extraction is attempted via `_extract_version_from_src()`
    but is never guessed; "version unknown" is returned when no
    version string is found.

    Duplicate framework entries (e.g. two React script tags) are
    collapsed into a single entry by tracking names in a set.

    Args:
        response: A `requests.Response` object.

    Returns:
        List of FrameworkInfo dicts, each with keys:
          "name"    – framework name string
          "version" – version string or "version unknown"
        Empty list if no frameworks are detected or parsing fails.
    """
    seen_names: set = set()
    frameworks: List[FrameworkInfo] = []

    try:
        soup = _parse_html(response.text)
        if soup is None:
            return frameworks

        for script_tag in soup.find_all("script", src=True):
            src: str = script_tag.get("src", "")
            if not src:
                continue

            # Each condition is intentionally independent so that a
            # single <script> tag cannot match multiple frameworks.
            framework_name: Optional[str] = None

            # ── React ─────────────────────────────────────────────────
            if (
                "react.min.js" in src
                or "react.development.js" in src
                or "react-dom" in src
            ):
                framework_name = "React"

            # ── Vue.js ────────────────────────────────────────────────
            elif (
                "vue.min.js" in src
                or "/vue@" in src
                or re.search(r'/vue\.js', src)
            ):
                framework_name = "Vue.js"

            # ── Angular ───────────────────────────────────────────────
            elif "angular.min.js" in src or "@angular/core" in src:
                framework_name = "Angular"

            # ── jQuery ────────────────────────────────────────────────
            elif "jquery.min.js" in src or re.search(r'jquery-\d', src):
                framework_name = "jQuery"

            # ── Bootstrap ─────────────────────────────────────────────
            elif "bootstrap.min.js" in src or "bootstrap.bundle" in src:
                framework_name = "Bootstrap"

            # ── Record unique frameworks only ─────────────────────────
            if framework_name and framework_name not in seen_names:
                seen_names.add(framework_name)
                frameworks.append(
                    {
                        "name": framework_name,
                        "version": _extract_version_from_src(src),
                    }
                )

    except Exception as exc:
        logger.error("[tech_detect] Framework detection failed: %s", exc)

    return frameworks


# ---------------------------------------------------------------------------
# 3d — Cookie security analysis
# ---------------------------------------------------------------------------

def analyze_cookies(response) -> List[CookieInfo]:
    """
    Audit cookies set by the server for missing security flags.

    Reads Set-Cookie headers from the raw response.  Each cookie is
    examined for the presence of the HttpOnly, Secure, and SameSite
    directives.  Actual cookie values are never stored.

    CRITICAL FIX FROM PHASE 1 CRITIQUE:
    The previous implementation split on commas to separate multiple
    Set-Cookie headers, but this breaks on cookies that contain commas
    in their expiry dates or values (e.g. "expires=Thu, 01 Jan 2026").
    This version uses `response.raw.headers` (a urllib3 HTTPHeaderDict)
    which preserves duplicate headers without merging them.

    Args:
        response: A `requests.Response` object.

    Returns:
        List of CookieInfo dicts, each with keys:
          "name"      – cookie name string
          "httponly"  – bool
          "secure"    – bool
          "samesite"  – str (e.g. "Strict", "Lax", "None") or None
        Empty list if no Set-Cookie headers are present.
    """
    results: List[CookieInfo] = []

    try:
        # ── Extract raw Set-Cookie headers without merging ────────────
        # urllib3's HTTPHeaderDict provides getlist() which returns
        # all values for a given header name as separate strings.
        cookie_strings: List[str] = []

        try:
            raw_headers = response.raw.headers
            if hasattr(raw_headers, "getlist"):
                cookie_strings = raw_headers.getlist("Set-Cookie")
            else:
                # Extremely rare fallback: if raw.headers doesn't have
                # getlist (shouldn't happen with urllib3 >= 1.0), read
                # from response.cookies instead.
                logger.warning(
                    "[tech_detect] raw.headers.getlist unavailable; "
                    "falling back to response.cookies"
                )
                for cookie in response.cookies:
                    results.append(
                        {
                            "name": cookie.name or "(unnamed)",
                            "httponly": False,  # Not reliably detectable
                            "secure": bool(cookie.secure),
                            "samesite": None,
                        }
                    )
                return results
        except Exception as inner_exc:
            logger.warning(
                "[tech_detect] Unable to read raw headers: %s — "
                "trying response.cookies fallback",
                inner_exc,
            )
            for cookie in response.cookies:
                results.append(
                    {
                        "name": cookie.name or "(unnamed)",
                        "httponly": False,
                        "secure": bool(cookie.secure),
                        "samesite": None,
                    }
                )
            return results

        # ── Parse each Set-Cookie header independently ────────────────
        for cookie_str in cookie_strings:
            if not cookie_str:
                continue

            # The cookie name is the part before the first '=' in the
            # first segment (before the first ';').
            segments = cookie_str.split(";")
            name_value_pair = segments[0].strip()

            if "=" in name_value_pair:
                name = name_value_pair.split("=", 1)[0].strip()
            else:
                name = name_value_pair.strip() or "(unnamed)"

            lower_str = cookie_str.lower()

            # ── SameSite value extraction ─────────────────────────────
            samesite_value: Optional[str] = None
            samesite_match = re.search(
                r'samesite\s*=\s*([a-zA-Z]+)',
                cookie_str,
                re.IGNORECASE,
            )
            if samesite_match:
                # Capitalise for consistency (Strict / Lax / None)
                samesite_value = samesite_match.group(1).capitalize()

            results.append(
                {
                    "name": name,
                    "httponly": "httponly" in lower_str,
                    "secure": "secure" in lower_str,
                    "samesite": samesite_value,
                }
            )

    except Exception as exc:
        logger.error("[tech_detect] Cookie analysis failed: %s", exc)

    return results


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

def detect_all(response) -> TechReport:
    """
    Run all four technology detection functions and return a unified report.

    This is the only function that `recon.py` calls.  It orchestrates
    the four independent sub-detectors and returns their results under
    predictable keys so that downstream consumers (report_gen) can rely
    on a stable schema.

    Each detection function is wrapped in a dedicated try/except block
    so that a failure in one cannot prevent the others from running.

    Args:
        response: A `requests.Response` object for the target root page.

    Returns:
        Dict with keys:
          "server_info"  – ServerInfo dict from detect_web_server()
          "cms"          – str from detect_cms()
          "frameworks"   – List[FrameworkInfo] from detect_frameworks()
          "cookies"      – List[CookieInfo] from analyze_cookies()

        On catastrophic failure (response object is unusable), returns
        safe defaults for all keys.
    """
    result: TechReport = {
        "server_info": {"server": "Not disclosed", "powered_by": "Not disclosed"},
        "cms": "Unknown or custom",
        "frameworks": [],
        "cookies": [],
    }

    try:
        result["server_info"] = detect_web_server(response)
    except Exception as exc:
        logger.error("[tech_detect] detect_web_server raised: %s", exc)

    try:
        result["cms"] = detect_cms(response)
    except Exception as exc:
        logger.error("[tech_detect] detect_cms raised: %s", exc)

    try:
        result["frameworks"] = detect_frameworks(response)
    except Exception as exc:
        logger.error("[tech_detect] detect_frameworks raised: %s", exc)

    try:
        result["cookies"] = analyze_cookies(response)
    except Exception as exc:
        logger.error("[tech_detect] analyze_cookies raised: %s", exc)

    return result
