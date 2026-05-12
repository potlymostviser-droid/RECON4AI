# recon_tool/modules/whois_lookup.py
#
# Directory: recon_tool/modules/whois_lookup.py
#
# WHOIS domain registration data retrieval module.
#
# Retrieves domain registration metadata using the `python-whois`
# library.  Only the nine fields listed in the specification are
# extracted.  Any field that is absent, None, or raises an
# AttributeError is recorded as None in the output rather than
# omitted, so that downstream consumers can always rely on a stable
# key set.
#
# Date fields are normalised to ISO 8601 strings.  When a field
# contains a list (common in WHOIS data), only the first element is
# used.
#
# This module makes no HTTP requests; it communicates directly with
# WHOIS servers via the `whois` library's own socket layer.

"""
whois_lookup
============
Retrieves domain registration metadata from WHOIS servers.

Field extraction is fully defensive: each field is read in its own
try/except block so that a malformed value in one field cannot
prevent the others from being extracted.

The output always contains all nine keys specified, with None values
for any field that could not be retrieved.

Public API
----------
    lookup_whois(domain) -> dict
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import whois  # python-whois

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------

WHOISReport = Dict[str, Optional[Any]]


# ---------------------------------------------------------------------------
# Internal normalisation helpers
# ---------------------------------------------------------------------------

def _normalise_date(value: Any) -> Optional[str]:
    """
    Convert a date value from a WHOIS field to an ISO 8601 string.

    Handles:
      - datetime objects (converted via .isoformat())
      - Lists of datetime objects (takes first element)
      - Plain strings (returned as-is)

    Returns None for any value that cannot be sensibly converted.

    Args:
        value: The raw value from a python-whois date field.

    Returns:
        ISO 8601 date string, or None.
    """
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    # Some WHOIS parsers return pre-formatted strings
    return str(value)


def _normalise_scalar(value: Any) -> Optional[str]:
    """
    Return the first element if `value` is a list, else str(value).

    Args:
        value: Raw value from a python-whois field.

    Returns:
        String, or None if value is None or an empty list.
    """
    if value is None:
        return None
    if isinstance(value, list):
        if not value:
            return None
        return str(value[0])
    return str(value)


def _normalise_list(value: Any) -> Optional[List[str]]:
    """
    Return `value` as a list of strings, or None if absent.

    For nameservers, status codes, and emails which are often returned
    as lists from python-whois.  Converts all elements to lowercase
    strings and strips whitespace.

    Args:
        value: Raw value from a python-whois field that may be
               a string or a list of strings.

    Returns:
        List[str], or None if value is absent or empty.
    """
    if value is None:
        return None
    if isinstance(value, list):
        cleaned = [str(v).lower().strip() for v in value if v]
        return cleaned if cleaned else None
    return [str(value).lower().strip()]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lookup_whois(domain: str) -> WHOISReport:
    """
    Perform a WHOIS lookup and extract registration metadata.

    Extracts exactly the nine fields specified:
      registrar, creation_date, expiration_date, updated_date,
      name_servers, status, emails, org, country.

    All fields default to None if absent, malformed, or if the WHOIS
    lookup itself fails (e.g. for privacy-protected registrations or
    rate-limited WHOIS servers).

    Each field is extracted in its own try/except block so that a
    failure in one field cannot prevent the others from being read.
    This is critical for robustness: WHOIS data is notoriously
    inconsistent across TLDs and registrars.

    Args:
        domain: Bare domain name, e.g. "example.com".

    Returns:
        WHOISReport dict with all nine keys always present.  Values
        are None for fields that could not be retrieved.
    """
    # Default output: every key present, all values None
    result: WHOISReport = {
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": None,
        "status": None,
        "emails": None,
        "org": None,
        "country": None,
    }

    # ── Attempt the WHOIS query ───────────────────────────────────────
    try:
        w = whois.whois(domain)
    except Exception as exc:
        logger.error("[whois] WHOIS query failed for '%s': %s", domain, exc)
        return result

    if w is None:
        logger.warning("[whois] WHOIS returned no data for '%s'", domain)
        return result

    # ── Extract each field independently ──────────────────────────────
    # Each field extraction is wrapped in try/except so that a
    # malformed value in one field (e.g. an unparseable date string)
    # does not prevent other fields from being read.

    # ── registrar ─────────────────────────────────────────────────────
    try:
        result["registrar"] = _normalise_scalar(
            getattr(w, "registrar", None)
        )
    except Exception as exc:
        logger.error(
            "[whois] Error reading registrar for '%s': %s", domain, exc
        )

    # ── creation_date ─────────────────────────────────────────────────
    try:
        result["creation_date"] = _normalise_date(
            getattr(w, "creation_date", None)
        )
    except Exception as exc:
        logger.error(
            "[whois] Error reading creation_date for '%s': %s", domain, exc
        )

    # ── expiration_date ───────────────────────────────────────────────
    try:
        result["expiration_date"] = _normalise_date(
            getattr(w, "expiration_date", None)
        )
    except Exception as exc:
        logger.error(
            "[whois] Error reading expiration_date for '%s': %s",
            domain,
            exc,
        )

    # ── updated_date ──────────────────────────────────────────────────
    try:
        result["updated_date"] = _normalise_date(
            getattr(w, "updated_date", None)
        )
    except Exception as exc:
        logger.error(
            "[whois] Error reading updated_date for '%s': %s", domain, exc
        )

    # ── name_servers ──────────────────────────────────────────────────
    try:
        result["name_servers"] = _normalise_list(
            getattr(w, "name_servers", None)
        )
    except Exception as exc:
        logger.error(
            "[whois] Error reading name_servers for '%s': %s", domain, exc
        )

    # ── status ────────────────────────────────────────────────────────
    try:
        raw_status = getattr(w, "status", None)
        if isinstance(raw_status, list):
            result["status"] = [str(s) for s in raw_status if s]
        elif raw_status is not None:
            result["status"] = [str(raw_status)]
    except Exception as exc:
        logger.error(
            "[whois] Error reading status for '%s': %s", domain, exc
        )

    # ── emails ────────────────────────────────────────────────────────
    try:
        raw_emails = getattr(w, "emails", None)
        if isinstance(raw_emails, list):
            result["emails"] = [str(e) for e in raw_emails if e]
        elif raw_emails is not None:
            result["emails"] = [str(raw_emails)]
    except Exception as exc:
        logger.error(
            "[whois] Error reading emails for '%s': %s", domain, exc
        )

    # ── org ───────────────────────────────────────────────────────────
    try:
        result["org"] = _normalise_scalar(getattr(w, "org", None))
    except Exception as exc:
        logger.error("[whois] Error reading org for '%s': %s", domain, exc)

    # ── country ───────────────────────────────────────────────────────
    try:
        result["country"] = _normalise_scalar(getattr(w, "country", None))
    except Exception as exc:
        logger.error(
            "[whois] Error reading country for '%s': %s", domain, exc
        )

    return result
