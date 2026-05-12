# recon_tool/modules/header_audit.py
#
# Directory: recon_tool/modules/header_audit.py
#
# HTTP security header analysis module.
#
# Evaluates the presence and configuration of seven HTTP security
# headers that are routinely checked during web application security
# assessments.
#
# Design principles:
#   - Each header is checked independently in its own function.
#   - Observations are factual only; we record what is objectively
#     present or absent without prescribing remediation steps.
#   - Remediation advice belongs in the AI-assisted Phase 2 analysis,
#     not in this passive reconnaissance tool.

"""
header_audit
============
Evaluates seven HTTP security headers for presence and basic
configuration issues.

Headers audited
----------------
1. Content-Security-Policy
2. Strict-Transport-Security
3. X-Frame-Options
4. X-Content-Type-Options
5. Referrer-Policy
6. Permissions-Policy
7. X-XSS-Protection (deprecated but still commonly seen)

Each header is checked in isolation.  A failure in one check cannot
mask another.  All checks return a consistent schema so that report
generators can iterate over them uniformly.

Output schema (per header)
---------------------------
{
    "header_name": str,     # Canonical header name
    "present":     bool,    # True if header exists in response
    "value":       str | None,  # Header value, or None if absent
    "notes":       str      # Factual observation about the header
}

Public API
----------
    audit_headers(response) -> List[dict]
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Type alias for documentation clarity
# ---------------------------------------------------------------------------

HeaderAuditResult = Dict[str, Optional[object]]


# ---------------------------------------------------------------------------
# Individual header check functions
# ---------------------------------------------------------------------------

def _check_csp(headers: dict) -> HeaderAuditResult:
    """
    Evaluate the Content-Security-Policy header.

    Flags the presence of the `unsafe-inline` and `unsafe-eval`
    directives because both are widely recognised as weakening the
    policy's XSS-mitigation effectiveness.

    Does not parse the full CSP grammar or evaluate every directive —
    only checks for those two specific strings.

    Args:
        headers: Case-insensitive dict of response header names to values.

    Returns:
        HeaderAuditResult dict.
    """
    name = "Content-Security-Policy"
    value: Optional[str] = headers.get(name)

    if value is None:
        return {
            "header_name": name,
            "present": False,
            "value": None,
            "notes": "Header is absent.",
        }

    notes_parts = ["Header is present."]
    if "unsafe-inline" in value:
        notes_parts.append("Contains 'unsafe-inline'.")
    if "unsafe-eval" in value:
        notes_parts.append("Contains 'unsafe-eval'.")

    return {
        "header_name": name,
        "present": True,
        "value": value,
        "notes": " ".join(notes_parts),
    }


def _check_hsts(headers: dict) -> HeaderAuditResult:
    """
    Evaluate the Strict-Transport-Security header.

    Records whether `max-age` and `includeSubDomains` directives are
    present.  Does not parse the numeric value of `max-age` or judge
    what a "good" value is.

    Args:
        headers: Case-insensitive dict of response headers.

    Returns:
        HeaderAuditResult dict.
    """
    name = "Strict-Transport-Security"
    value: Optional[str] = headers.get(name)

    if value is None:
        return {
            "header_name": name,
            "present": False,
            "value": None,
            "notes": "Header is absent.",
        }

    notes_parts = ["Header is present."]
    if "max-age" in value.lower():
        notes_parts.append("Includes max-age directive.")
    else:
        notes_parts.append("max-age directive is missing.")

    if "includeSubDomains" in value:
        notes_parts.append("Includes includeSubDomains.")

    return {
        "header_name": name,
        "present": True,
        "value": value,
        "notes": " ".join(notes_parts),
    }


def _check_xfo(headers: dict) -> HeaderAuditResult:
    """
    Evaluate the X-Frame-Options header.

    Accepted values are DENY and SAMEORIGIN.  Any other value is
    noted as non-standard without further judgement.

    Args:
        headers: Case-insensitive dict of response headers.

    Returns:
        HeaderAuditResult dict.
    """
    name = "X-Frame-Options"
    value: Optional[str] = headers.get(name)

    if value is None:
        return {
            "header_name": name,
            "present": False,
            "value": None,
            "notes": "Header is absent.",
        }

    normalised = value.strip().upper()
    if normalised in {"DENY", "SAMEORIGIN"}:
        notes = f"Present with recognised value: {value}."
    else:
        notes = f"Present with non-standard value: '{value}'."

    return {
        "header_name": name,
        "present": True,
        "value": value,
        "notes": notes,
    }


def _check_xcto(headers: dict) -> HeaderAuditResult:
    """
    Evaluate the X-Content-Type-Options header.

    The only accepted value is `nosniff`.  Any other value is noted.

    Args:
        headers: Case-insensitive dict of response headers.

    Returns:
        HeaderAuditResult dict.
    """
    name = "X-Content-Type-Options"
    value: Optional[str] = headers.get(name)

    if value is None:
        return {
            "header_name": name,
            "present": False,
            "value": None,
            "notes": "Header is absent.",
        }

    if value.strip().lower() == "nosniff":
        notes = "Present with correct value: nosniff."
    else:
        notes = f"Present but value is not 'nosniff': '{value}'."

    return {
        "header_name": name,
        "present": True,
        "value": value,
        "notes": notes,
    }


def _check_referrer_policy(headers: dict) -> HeaderAuditResult:
    """
    Record the Referrer-Policy header value without evaluating it.

    There are multiple legitimate values depending on the application's
    requirements.  We record what is present and leave interpretation
    to the AI-assisted phase.

    Args:
        headers: Case-insensitive dict of response headers.

    Returns:
        HeaderAuditResult dict.
    """
    name = "Referrer-Policy"
    value: Optional[str] = headers.get(name)

    if value is None:
        return {
            "header_name": name,
            "present": False,
            "value": None,
            "notes": "Header is absent.",
        }

    return {
        "header_name": name,
        "present": True,
        "value": value,
        "notes": f"Present with value: '{value}'.",
    }


def _check_permissions_policy(headers: dict) -> HeaderAuditResult:
    """
    Record the Permissions-Policy header presence.

    This header replaced Feature-Policy and has a complex grammar.
    We only check whether it is present, not whether it is well-formed.

    Args:
        headers: Case-insensitive dict of response headers.

    Returns:
        HeaderAuditResult dict.
    """
    name = "Permissions-Policy"
    value: Optional[str] = headers.get(name)

    if value is None:
        return {
            "header_name": name,
            "present": False,
            "value": None,
            "notes": "Header is absent.",
        }

    return {
        "header_name": name,
        "present": True,
        "value": value,
        "notes": "Present.",
    }


def _check_xxss(headers: dict) -> HeaderAuditResult:
    """
    Record the X-XSS-Protection header.

    This header is deprecated and not honoured by modern browsers.
    Its presence is recorded as a factual observation only.

    Args:
        headers: Case-insensitive dict of response headers.

    Returns:
        HeaderAuditResult dict.
    """
    name = "X-XSS-Protection"
    value: Optional[str] = headers.get(name)

    if value is None:
        return {
            "header_name": name,
            "present": False,
            "value": None,
            "notes": "Header is absent. (Header is deprecated.)",
        }

    return {
        "header_name": name,
        "present": True,
        "value": value,
        "notes": (
            f"Present with value: '{value}'. "
            "Note: this header is deprecated and ignored by modern browsers."
        ),
    }


# ---------------------------------------------------------------------------
# Public aggregator
# ---------------------------------------------------------------------------

def audit_headers(response) -> List[HeaderAuditResult]:
    """
    Run all seven security-header checks and return the results.

    Each check function is called in a dedicated try/except block so
    that a failure in one check cannot prevent the others from running.

    Args:
        response: A `requests.Response` object.

    Returns:
        List of HeaderAuditResult dicts in the order the checks ran:
          1. Content-Security-Policy
          2. Strict-Transport-Security
          3. X-Frame-Options
          4. X-Content-Type-Options
          5. Referrer-Policy
          6. Permissions-Policy
          7. X-XSS-Protection

        Returns an empty list only if the response object itself is
        unusable (no headers attribute).
    """
    results: List[HeaderAuditResult] = []

    try:
        headers = response.headers
    except Exception as exc:
        logger.error("[header_audit] Cannot read response headers: %s", exc)
        return results

    # Define check functions in the canonical order.
    # The order matches the specification and the markdown report order.
    check_functions = [
        _check_csp,
        _check_hsts,
        _check_xfo,
        _check_xcto,
        _check_referrer_policy,
        _check_permissions_policy,
        _check_xxss,
    ]

    for check_fn in check_functions:
        try:
            results.append(check_fn(headers))
        except Exception as exc:
            logger.error(
                "[header_audit] Check %s failed: %s",
                check_fn.__name__,
                exc,
            )
            # Append a safe default so the results list always has 7 entries
            results.append(
                {
                    "header_name": "Unknown",
                    "present": False,
                    "value": None,
                    "notes": f"Check failed: {exc}",
                }
            )

    return results
