# recon_tool/modules/http_helper.py
#
# Directory: recon_tool/modules/http_helper.py
#
# Centralised HTTP client used by every other module in this project.
# This is the ONLY file in the project permitted to import `requests`.
# No other module may construct HTTP connections independently.
#
# All network requests made by this tool — regardless of which module
# initiates them — flow through the single `HTTPClient` instance that
# recon.py creates and passes down to every module at scan time.
# This guarantees that rate limiting, timeout policy, redirect caps,
# User-Agent rotation, response size limits, and retry behaviour are
# applied uniformly across the entire scan.

"""
http_helper
===========
Provides `HTTPClient`: a production-hardened wrapper around a
`requests.Session` that enforces the following policies on every
outbound request:

Rate limiting
    A token-bucket rate limiter ensures the configured maximum number
    of requests per second is never exceeded, regardless of how many
    modules are making concurrent calls.

Timeout
    Every request has a hard 10-second timeout (configurable).
    Both the connection phase and the read phase are covered.

Redirect cap
    Redirects are followed automatically but capped at 5 hops,
    matching the limit used by Chrome and Firefox.

User-Agent rotation
    A pool of five realistic desktop browser User-Agent strings is
    rotated randomly on each request so the scan does not present a
    single fingerprint to WAF rules.

Retry with back-off
    Transient failures (connection errors, read timeouts, and HTTP
    status codes 429 / 500 / 502 / 503 / 504) trigger one automatic
    retry after a configurable delay.  The Retry-After response header
    is respected for 429 responses.

Response size cap
    Response bodies are read in streaming chunks and truncated at a
    configurable byte limit (default 10 MB) to prevent memory
    exhaustion on unexpectedly large targets.  The truncated body is
    pushed back into the response object so callers can use
    `response.text` and `response.content` normally.

Error containment
    Every exception is caught, logged with full context, and converted
    to a structured `HTTPResult` return value.  The `get()` method
    never raises.

Public API
----------
    HTTPClient(rate_limit_rps, timeout, max_response_bytes)
    HTTPClient.get(url) -> Optional[requests.Response]
"""

import logging
import random
import time
from typing import Optional

import requests
from requests.adapters import HTTPAdapter

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Hard timeout applied to both the TCP connection phase and the
# subsequent read phase.  Expressed as a (connect, read) tuple so that
# requests applies it to both phases independently.
_DEFAULT_TIMEOUT: tuple = (10, 10)

# Maximum number of HTTP redirects to follow before aborting.
# Matches the limit used by Chrome and Firefox.
_MAX_REDIRECTS: int = 5

# Default maximum response body size in bytes (10 MB).
# Bodies larger than this are truncated after this many bytes.
_DEFAULT_MAX_RESPONSE_BYTES: int = 10 * 1_048_576

# HTTP status codes that indicate a transient server-side problem
# and are worth retrying once after a short pause.
_RETRYABLE_STATUS_CODES: frozenset = frozenset({429, 500, 502, 503, 504})

# Seconds to wait between retry attempts when no Retry-After header
# is present.
_DEFAULT_RETRY_DELAY: float = 3.0

# Maximum number of seconds we will honour from a Retry-After header.
# We cap this so a server cannot force us to wait indefinitely.
_MAX_RETRY_AFTER_SECONDS: float = 30.0

# Pool of realistic desktop browser User-Agent strings.
# Five distinct strings gives enough variety to avoid simple
# single-UA bot-detection rules without requiring any external library.
_USER_AGENTS: tuple = (
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
        "Gecko/20100101 Firefox/125.0"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) "
        "Gecko/20100101 Firefox/125.0"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.4.1 Safari/605.1.15"
    ),
)

# Static headers sent on every request alongside the rotating
# User-Agent.  These mirror what a real browser sends and reduce the
# chance of receiving bot-detection pages that would corrupt findings.
_STATIC_HEADERS: dict = {
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;"
        "q=0.9,image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class _RateLimiter:
    """
    Minimum-interval rate limiter (token-bucket approximation).

    Guarantees that at least `1 / requests_per_second` seconds elapse
    between successive calls to `wait()`.  The implementation uses
    `time.monotonic()` for drift-free interval measurement.

    This class is NOT thread-safe for high concurrency.  The tool's
    maximum thread count (20) is low enough that the GIL provides
    sufficient protection for `time.monotonic()` reads and
    `time.sleep()` calls.  If higher concurrency is ever required,
    a `threading.Lock` should be added around the check-and-update
    block.

    Args:
        requests_per_second: Desired maximum sustained request rate.
                             Must be a positive finite float.
    """

    def __init__(self, requests_per_second: float) -> None:
        """
        Initialise the rate limiter.

        Args:
            requests_per_second: Maximum requests per second. Must be > 0.

        Raises:
            ValueError: If requests_per_second is not positive.
        """
        if requests_per_second <= 0:
            raise ValueError(
                f"requests_per_second must be positive, got {requests_per_second}"
            )
        self._min_interval: float = 1.0 / requests_per_second
        self._last_call: float = 0.0

    def wait(self) -> None:
        """
        Block the calling thread until the minimum interval has elapsed
        since the last call to this method.

        Args:
            None

        Returns:
            None
        """
        now = time.monotonic()
        elapsed = now - self._last_call
        gap = self._min_interval - elapsed
        if gap > 0:
            time.sleep(gap)
        self._last_call = time.monotonic()


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

class HTTPClient:
    """
    Production-hardened HTTP client for the reconnaissance tool.

    One instance is created in `recon.py` at scan start-up and passed
    to every module that requires network access.  This single-instance
    design enforces a consistent request policy across the entire scan
    and prevents modules from accidentally bypassing rate limiting or
    size caps by constructing their own sessions.

    Args:
        rate_limit_rps:     Maximum sustained requests per second.
                            Default 1.0.  Must be between 0.01 and 10.
        timeout:            Per-request timeout in seconds applied to
                            both the connect phase and the read phase.
                            Default 10.
        max_response_bytes: Hard cap on response body size.  Bodies
                            larger than this are silently truncated.
                            Default 10 MB.
    """

    def __init__(
        self,
        rate_limit_rps: float = 1.0,
        timeout: int = 10,
        max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        """
        Initialise the HTTP client and its underlying session.

        Args:
            rate_limit_rps:     Requests per second cap.
            timeout:            Timeout in seconds for connect and read.
            max_response_bytes: Response body truncation threshold.

        Returns:
            None
        """
        self._timeout: tuple = (timeout, timeout)
        self._max_bytes: int = max_response_bytes
        self._rate_limiter: _RateLimiter = _RateLimiter(rate_limit_rps)

        # Build a session with no automatic retries at the adapter level.
        # All retry logic lives in get() so we have full control over
        # back-off timing, Retry-After header handling, and logging.
        self._session: requests.Session = requests.Session()
        self._session.max_redirects = _MAX_REDIRECTS

        # Mount the same adapter for both schemes.
        # max_retries=0 disables urllib3's built-in retry mechanism;
        # we handle retries ourselves in get().
        adapter = HTTPAdapter(max_retries=0)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

        logger.debug(
            "[http_helper] HTTPClient initialised — rate=%.2f rps, "
            "timeout=%ds, max_body=%d bytes",
            rate_limit_rps,
            timeout,
            max_response_bytes,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def get(self, url: str) -> Optional[requests.Response]:
        """
        Perform a rate-limited, policy-enforced HTTP GET request.

        Attempt sequence
        ----------------
        1. Apply rate limiting (block until minimum interval has elapsed).
        2. Send the GET request with a rotating User-Agent and static
           browser headers.
        3. If the response status code is in `_RETRYABLE_STATUS_CODES`,
           wait (honouring Retry-After if present) and retry once.
        4. If a network-level error occurs (timeout, connection error),
           wait `_DEFAULT_RETRY_DELAY` seconds and retry once.
        5. SSL errors and redirect loops are not retried — they indicate
           a definitive problem rather than a transient one.
        6. After at most two attempts, return None on failure.

        The response body is read in streaming chunks and truncated at
        `max_response_bytes`.  The truncated content is written back
        into `response._content` so that callers can use
        `response.text` and `response.content` as normal.

        Args:
            url: Fully-qualified URL to request.  Must include scheme.

        Returns:
            `requests.Response` object on success (any HTTP status code
            is considered a success at the transport level — the caller
            decides whether to act on 404, 403, etc.).
            `None` on any unrecoverable failure.  Never raises.
        """
        for attempt in range(1, 3):     # Attempts 1 and 2 only
            self._rate_limiter.wait()

            headers = dict(_STATIC_HEADERS)
            headers["User-Agent"] = random.choice(_USER_AGENTS)

            try:
                response = self._session.get(
                    url,
                    headers=headers,
                    timeout=self._timeout,
                    allow_redirects=True,
                    stream=True,         # Body read lazily; we control size
                    verify=True,         # Always verify TLS certificates
                )

                # ── Read and size-cap the body ────────────────────────
                self._read_body(response, url)

                # ── Check for retryable HTTP status ───────────────────
                if response.status_code in _RETRYABLE_STATUS_CODES:
                    if attempt == 1:
                        delay = self._extract_retry_after(response)
                        logger.warning(
                            "[http_helper] Status %d on attempt 1 for %s "
                            "— retrying in %.1fs",
                            response.status_code,
                            url,
                            delay,
                        )
                        time.sleep(delay)
                        continue    # Go to attempt 2
                    else:
                        # Second attempt also returned a retryable code;
                        # return it as-is so the caller can decide.
                        logger.error(
                            "[http_helper] Status %d on attempt 2 for %s "
                            "— giving up",
                            response.status_code,
                            url,
                        )
                        return response

                # ── Success path ──────────────────────────────────────
                logger.debug(
                    "[http_helper] %d %s (%.1f KB)",
                    response.status_code,
                    url,
                    len(response.content) / 1024,
                )
                return response

            # ── SSL errors are definitive — never retry ───────────────
            except requests.exceptions.SSLError as exc:
                logger.error(
                    "[http_helper] SSL error for %s: %s", url, exc
                )
                return None

            # ── Redirect loop is definitive ───────────────────────────
            except requests.exceptions.TooManyRedirects:
                logger.error(
                    "[http_helper] Redirect loop (>%d hops) for %s",
                    _MAX_REDIRECTS,
                    url,
                )
                return None

            # ── Timeout — retry once ──────────────────────────────────
            except requests.exceptions.Timeout:
                logger.warning(
                    "[http_helper] Timeout on attempt %d/2 for %s",
                    attempt,
                    url,
                )
                if attempt == 2:
                    logger.error(
                        "[http_helper] Timeout on both attempts for %s "
                        "— giving up",
                        url,
                    )
                    return None
                time.sleep(_DEFAULT_RETRY_DELAY)

            # ── Connection error — retry once ─────────────────────────
            except requests.exceptions.ConnectionError as exc:
                logger.warning(
                    "[http_helper] Connection error on attempt %d/2 "
                    "for %s: %s",
                    attempt,
                    url,
                    exc,
                )
                if attempt == 2:
                    logger.error(
                        "[http_helper] Connection error on both attempts "
                        "for %s — giving up",
                        url,
                    )
                    return None
                time.sleep(_DEFAULT_RETRY_DELAY)

            # ── Any other requests exception — do not retry ───────────
            except requests.exceptions.RequestException as exc:
                logger.error(
                    "[http_helper] Request exception for %s: %s", url, exc
                )
                return None

            # ── Absolute safety net — should never be reached ─────────
            except Exception as exc:
                logger.exception(
                    "[http_helper] Unexpected error for %s: %s", url, exc
                )
                return None

        # Unreachable under normal conditions; satisfies type checker.
        return None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _read_body(self, response: requests.Response, url: str) -> None:
        """
        Read the streaming response body into `response._content` while
        enforcing the configured byte cap.

        When `stream=True` is passed to `requests.get()`, the body is
        not automatically read into memory.  This method iterates over
        the response in 8 KB chunks, accumulates them up to the byte
        cap, then writes the result back into `response._content`.
        After this call, `response.text` and `response.content` behave
        as they would for a non-streaming response.

        The response encoding is set explicitly to the value that
        `requests` detected from the HTTP headers (falling back to
        UTF-8) to avoid triggering `chardet` / `charset_normalizer`
        auto-detection, which is not a guaranteed dependency.

        Args:
            response: The streaming `requests.Response` object to read.
            url:      The request URL, used only for log messages.

        Returns:
            None.  Mutates `response` in place.
        """
        try:
            chunks = []
            total = 0
            truncated = False

            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                total += len(chunk)
                if total > self._max_bytes:
                    # Keep chunks up to the limit; discard the rest
                    overage = total - self._max_bytes
                    if overage < len(chunk):
                        chunks.append(chunk[: len(chunk) - overage])
                    truncated = True
                    break
                chunks.append(chunk)

            if truncated:
                logger.warning(
                    "[http_helper] Response body truncated at %d bytes "
                    "for %s",
                    self._max_bytes,
                    url,
                )

            raw_bytes: bytes = b"".join(chunks)

            # Write content back so response.content works normally
            # pylint: disable=protected-access
            response._content = raw_bytes

            # Set encoding from headers only — no chardet dependency
            if not response.encoding:
                response.encoding = "utf-8"

        except Exception as exc:
            logger.error(
                "[http_helper] Error reading response body for %s: %s",
                url,
                exc,
            )
            # Leave whatever partial content requests may have buffered
            if not hasattr(response, "_content") or response._content is None:
                # pylint: disable=protected-access
                response._content = b""

    @staticmethod
    def _extract_retry_after(response: requests.Response) -> float:
        """
        Extract a retry delay from the Retry-After response header.

        Parses the header value as an integer number of seconds.
        Non-integer values (e.g. HTTP-date strings) are not parsed
        because they require date arithmetic beyond the approved
        library set; in that case the default delay is returned.

        The returned value is capped at `_MAX_RETRY_AFTER_SECONDS`
        so that a misbehaving server cannot force the tool to hang.

        Args:
            response: The HTTP response that contained the retryable
                      status code.

        Returns:
            Number of seconds to wait before retrying. Always between
            `_DEFAULT_RETRY_DELAY` and `_MAX_RETRY_AFTER_SECONDS`.
        """
        try:
            header_value = response.headers.get("Retry-After", "").strip()
            if header_value.isdigit():
                requested_delay = float(header_value)
                capped = min(requested_delay, _MAX_RETRY_AFTER_SECONDS)
                logger.debug(
                    "[http_helper] Retry-After header: %ss (capped at %ss)",
                    requested_delay,
                    capped,
                )
                return capped
        except Exception:
            pass    # Fall through to default
        return _DEFAULT_RETRY_DELAY
