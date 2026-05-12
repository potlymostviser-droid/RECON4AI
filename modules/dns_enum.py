# recon_tool/modules/dns_enum.py
#
# Directory: recon_tool/modules/dns_enum.py
#
# DNS record enumeration module.
#
# Queries DNS for the five record types most relevant to passive
# reconnaissance: A, MX, NS, TXT, and CNAME.
#
# CRITICAL FIX FROM PHASE 1 CRITIQUE:
# The previous implementation used the system default DNS resolver
# timeout which can be 30+ seconds per query on some systems.  This
# version creates a custom resolver with explicit lifetime and
# per-server timeout values to prevent the DNS step from blocking
# for minutes on non-responsive domains.

"""
dns_enum
========
Queries DNS for reconnaissance-relevant record types using a custom
resolver with explicit timeout configuration.

All queries use `dnspython`'s high-level `dns.resolver.Resolver()`
interface with configured timeout budgets.  Three specific exception
types are caught and logged separately so that the caller can
distinguish between:

  * NXDOMAIN  – the domain genuinely does not exist in DNS
  * NoAnswer  – the domain exists but has no records of this type
  * Timeout   – the resolver could not reach a nameserver in time

Any other exception is caught by a broad `except Exception` guard
to prevent unexpected failures from propagating upward.

No additional network requests are made beyond the DNS queries
themselves.  DNS queries do not go through the HTTP client.

Public API
----------
    enumerate_all(domain) -> dict
"""

import logging
from typing import Dict, List, Optional

import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Total time budget (in seconds) for a single DNS query across all
# nameserver attempts.  If the query has not completed within this
# window, it is aborted.
_RESOLVER_LIFETIME: float = 8.0

# Per-nameserver timeout (in seconds).  If a single nameserver does
# not respond within this window, the resolver tries the next one.
_RESOLVER_TIMEOUT: float = 4.0


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

MXRecord = Dict[str, object]      # {"priority": int, "mail_server": str}
DNSReport = Dict[str, object]


# ---------------------------------------------------------------------------
# Resolver factory
# ---------------------------------------------------------------------------

def _make_resolver() -> dns.resolver.Resolver:
    """
    Create a custom DNS resolver with explicit timeout configuration.

    The system default resolver (used when you call
    `dns.resolver.resolve()` without creating a custom resolver) picks
    up timeout values from `/etc/resolv.conf` or OS defaults, which
    can be 30 seconds or more per query.  This factory creates a
    resolver with much tighter timeouts suitable for reconnaissance
    scans where we want to move on quickly if DNS is unresponsive.

    Returns:
        A configured `dns.resolver.Resolver` instance.
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = _RESOLVER_LIFETIME
    resolver.timeout = _RESOLVER_TIMEOUT
    return resolver


# ---------------------------------------------------------------------------
# 5a — A records
# ---------------------------------------------------------------------------

def get_a_records(domain: str) -> List[str]:
    """
    Query A records for `domain`.

    Args:
        domain: Bare domain name, e.g. "example.com".

    Returns:
        List of IPv4 address strings, e.g. ["93.184.216.34"].
        Empty list on any error or absence of records.
    """
    try:
        resolver = _make_resolver()
        answers = resolver.resolve(domain, "A")
        return [str(rdata) for rdata in answers]
    except dns.resolver.NXDOMAIN:
        logger.error("[dns_enum] NXDOMAIN for A query on '%s'", domain)
        return []
    except dns.resolver.NoAnswer:
        logger.info("[dns_enum] No A records for '%s'", domain)
        return []
    except dns.exception.Timeout:
        logger.error(
            "[dns_enum] Timeout (%.1fs) on A query for '%s'",
            _RESOLVER_LIFETIME,
            domain,
        )
        return []
    except Exception as exc:
        logger.error(
            "[dns_enum] Unexpected error on A query for '%s': %s",
            domain,
            exc,
        )
        return []


# ---------------------------------------------------------------------------
# 5b — MX records
# ---------------------------------------------------------------------------

def get_mx_records(domain: str) -> List[MXRecord]:
    """
    Query MX records for `domain`, sorted by priority ascending.

    Args:
        domain: Bare domain name.

    Returns:
        List of dicts each with keys:
          "priority"    – int, lower value = higher priority
          "mail_server" – str, trailing dot stripped
        Empty list on error or absence.
    """
    try:
        resolver = _make_resolver()
        answers = resolver.resolve(domain, "MX")
        records: List[MXRecord] = [
            {
                "priority": int(rdata.preference),
                "mail_server": str(rdata.exchange).rstrip("."),
            }
            for rdata in answers
        ]
        # Sort by priority (lowest first = highest priority)
        records.sort(key=lambda r: r["priority"])
        return records
    except dns.resolver.NXDOMAIN:
        logger.error("[dns_enum] NXDOMAIN for MX query on '%s'", domain)
        return []
    except dns.resolver.NoAnswer:
        logger.info("[dns_enum] No MX records for '%s'", domain)
        return []
    except dns.exception.Timeout:
        logger.error(
            "[dns_enum] Timeout (%.1fs) on MX query for '%s'",
            _RESOLVER_LIFETIME,
            domain,
        )
        return []
    except Exception as exc:
        logger.error(
            "[dns_enum] Unexpected error on MX query for '%s': %s",
            domain,
            exc,
        )
        return []


# ---------------------------------------------------------------------------
# 5c — NS records
# ---------------------------------------------------------------------------

def get_ns_records(domain: str) -> List[str]:
    """
    Query NS records for `domain`.

    Args:
        domain: Bare domain name.

    Returns:
        List of nameserver hostname strings, trailing dots stripped.
        Empty list on error or absence.
    """
    try:
        resolver = _make_resolver()
        answers = resolver.resolve(domain, "NS")
        return [str(rdata).rstrip(".") for rdata in answers]
    except dns.resolver.NXDOMAIN:
        logger.error("[dns_enum] NXDOMAIN for NS query on '%s'", domain)
        return []
    except dns.resolver.NoAnswer:
        logger.info("[dns_enum] No NS records for '%s'", domain)
        return []
    except dns.exception.Timeout:
        logger.error(
            "[dns_enum] Timeout (%.1fs) on NS query for '%s'",
            _RESOLVER_LIFETIME,
            domain,
        )
        return []
    except Exception as exc:
        logger.error(
            "[dns_enum] Unexpected error on NS query for '%s': %s",
            domain,
            exc,
        )
        return []


# ---------------------------------------------------------------------------
# 5d — TXT records
# ---------------------------------------------------------------------------

def get_txt_records(domain: str) -> List[str]:
    """
    Query TXT records for `domain`.

    TXT records can contain multiple byte-string segments per RDATA.
    They are concatenated (without separator) to produce one string per
    record, matching the behaviour of `dig TXT`.

    Args:
        domain: Bare domain name.

    Returns:
        List of TXT value strings.
        Empty list on error or absence.
    """
    try:
        resolver = _make_resolver()
        answers = resolver.resolve(domain, "TXT")
        results: List[str] = []
        for rdata in answers:
            # rdata.strings is a tuple of bytes objects
            parts = []
            for segment in rdata.strings:
                if isinstance(segment, bytes):
                    parts.append(segment.decode("utf-8", errors="replace"))
                else:
                    parts.append(str(segment))
            results.append("".join(parts))
        return results
    except dns.resolver.NXDOMAIN:
        logger.error("[dns_enum] NXDOMAIN for TXT query on '%s'", domain)
        return []
    except dns.resolver.NoAnswer:
        logger.info("[dns_enum] No TXT records for '%s'", domain)
        return []
    except dns.exception.Timeout:
        logger.error(
            "[dns_enum] Timeout (%.1fs) on TXT query for '%s'",
            _RESOLVER_LIFETIME,
            domain,
        )
        return []
    except Exception as exc:
        logger.error(
            "[dns_enum] Unexpected error on TXT query for '%s': %s",
            domain,
            exc,
        )
        return []


# ---------------------------------------------------------------------------
# 5e — CNAME record
# ---------------------------------------------------------------------------

def get_cname_record(domain: str) -> Optional[str]:
    """
    Query the CNAME record for `domain`.

    Most apex domains do not have a CNAME record; NoAnswer is expected
    and is not treated as an error condition.

    Args:
        domain: Bare domain name.

    Returns:
        Canonical name string (trailing dot stripped), or None.
    """
    try:
        resolver = _make_resolver()
        answers = resolver.resolve(domain, "CNAME")
        # Return the first CNAME if multiple exist (unusual but allowed)
        return str(answers[0]).rstrip(".")
    except dns.resolver.NXDOMAIN:
        logger.error("[dns_enum] NXDOMAIN for CNAME query on '%s'", domain)
        return None
    except dns.resolver.NoAnswer:
        logger.info(
            "[dns_enum] No CNAME record for '%s' (expected for apex)",
            domain,
        )
        return None
    except dns.exception.Timeout:
        logger.error(
            "[dns_enum] Timeout (%.1fs) on CNAME query for '%s'",
            _RESOLVER_LIFETIME,
            domain,
        )
        return None
    except Exception as exc:
        logger.error(
            "[dns_enum] Unexpected error on CNAME query for '%s': %s",
            domain,
            exc,
        )
        return None


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

def enumerate_all(domain: str) -> DNSReport:
    """
    Run all five DNS queries and return a unified report.

    Args:
        domain: Bare domain name, e.g. "example.com".

    Returns:
        Dict with keys:
          "a_records"    – List[str]
          "mx_records"   – List[MXRecord]
          "ns_records"   – List[str]
          "txt_records"  – List[str]
          "cname_record" – str | None
    """
    try:
        return {
            "a_records": get_a_records(domain),
            "mx_records": get_mx_records(domain),
            "ns_records": get_ns_records(domain),
            "txt_records": get_txt_records(domain),
            "cname_record": get_cname_record(domain),
        }
    except Exception as exc:
        logger.error("[dns_enum] enumerate_all failed: %s", exc)
        return {
            "a_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "cname_record": None,
        }
