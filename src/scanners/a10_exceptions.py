"""
scanners/a10_exceptions.py
---------------------------
OWASP Top 10 (2025 draft) - A10: Mishandling of Exceptions

Detects symptoms of exceptions being caught/surfaced incorrectly rather
than being handled safely and generically:

  1. NULL-reference hints     - "NULL pointer", "null value", NPE-style
                                 leaks across languages/runtimes
  2. Sensitive info in errors - file system paths, DB connection
                                 details, and stack traces bleeding
                                 sensitive detail into responses

This is a companion module to a09_logging.py (A09: Security Logging
Failures) - the two categories overlap heavily in symptoms but focus on
different root causes: A09 is about *failing to log/alert safely and
suppress general verbosity*, A10 is about *failing to catch/handle
exceptions safely*, so this module specifically concentrates on
null-handling bugs and sensitive-data leakage patterns rather than
generic error verbosity or debug endpoints (those stay in a09).

This scanner ONLY analyzes an already-populated Target object handed to
it by the existing crawler. It:

    - does NOT crawl, recursively discover pages, or build a sitemap
    - does NOT perform any active HTTP probing - this module is purely
      passive, so it needs no HttpClient at all
    - does NOT maintain a visited-URL set
    - does NOT build Endpoint or Target objects - every Finding attaches
      the exact Endpoint object the crawler already discovered and
      handed us via target.endpoints

A note on the "owasp" field / references:
    "A10: Mishandling of Exceptions" is not a category with a confirmed,
    published owasp.org page as of this module's writing - unlike A09's
    real 2021 OWASP Top 10 entry, this appears to be a project-specific
    or draft category name. Rather than fabricate an owasp.org URL,
    references below point at the relevant CWE entries (CWE-388 Error
    Handling, CWE-209/CWE-215 information exposure through error
    messages/debug info). Swap in an internal doc link if this project
    has one for its own A10 definition.

    exception
"""

from __future__ import annotations

import re
from typing import Optional

from ..core.models import Target, Endpoint, Finding, Severity

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------

# 1. NULL-reference hints - deliberately broader/more specific than a09's
# generic STACK_TRACE_PATTERNS "NullPointerException" entry: these cover
# the null/undefined-reference family across several languages/runtimes.
NULL_REFERENCE_PATTERNS: list[str] = [
    "NullPointerException",
    "NULL pointer",
    "null value",
    "Object reference not set to an instance of an object",
    "Cannot read property",
    "Cannot read properties of null",
    "Cannot read properties of undefined",
    "undefined is not an object",
    "NoneType' object has no attribute",
    "AttributeError: 'NoneType'",
    "TypeError: Cannot read",
]

# 2a. Database connection detail patterns - connection strings, driver
# URIs, and credential-bearing connection parameters that should never
# appear in a client-facing error response.
DB_CONNECTION_PATTERNS: list[str] = [
    "jdbc:",
    "mongodb://",
    "mongodb+srv://",
    "postgres://",
    "postgresql://",
    "mysql://",
    "oracle:",
    "sqlite:",
    "Initial Catalog=",
    "User Id=",
    "Password=",
    "ConnectionString",

    # Common connection string keys
    "Data Source=",
    "Initial Catalog=",
    "Database=",
    "Server=",
    "Host=",
    "Port=",

    # Credentials
    "User Id=",
    "UserID=",
    "UID=",
    "Username=",
    "Password=",
    "Pwd=",
    "pwd=",

    # Generic connection string indicators
    "ConnectionString",
    "connection string",
]

# 2b. File system path patterns - absolute Windows and Unix-style paths
# that reveal server-side directory layout when they leak into an error
# body (e.g. a Python "File "/app/src/handlers.py", line 42" traceback
# line, or a raw filesystem path embedded in a .NET/Java exception).
_WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:\\(?:[^\\\r\n\"'<>|]+\\)*[^\\\r\n\"'<>|]+")
_UNIX_PATH_RE = re.compile(r"/(?:etc|var|usr|home|opt|root|tmp|data|workspace|srv|app)/[^\s\"'<>]+")
_PYTHON_TRACEBACK_FILE_RE = re.compile(r'File "([^"]+\.py)", line (\d+)')
_JAVA_FILE_LINE_RE = re.compile(r"\(([A-Za-z0-9_$]+\.java):(\d+)\)")

FILESYSTEM_PATH_PATTERNS = (
    _WINDOWS_PATH_RE,
    _UNIX_PATH_RE,
    _PYTHON_TRACEBACK_FILE_RE,
    _JAVA_FILE_LINE_RE,
)

_OWASP_CATEGORY = "A10:2025(Draft)-Mishandling of Exceptions"
_CWE_ERROR_HANDLING = "https://cwe.mitre.org/data/definitions/388.html"
_CWE_INFO_EXPOSURE_ERROR = "https://cwe.mitre.org/data/definitions/209.html"
_CWE_INFO_EXPOSURE_DEBUG = "https://cwe.mitre.org/data/definitions/215.html"


class ExceptionMishandlingScanner:
    """Passive scanner for A10: Mishandling of Exceptions."""

    async def scan(self, target: Target) -> list[Finding]:
        """
        Analyze every Endpoint already discovered on ``target`` for
        symptoms of exceptions being surfaced rather than safely
        handled. Purely passive - no active checks, no HttpClient.

        Returns:
            Every Finding produced across all endpoints.
        """
        findings: list[Finding] = []

        for endpoint in target.endpoints:
            findings.extend(self._run_passive_checks(endpoint))

        return findings

    # ------------------------------------------------------------------
    # Passive checks
    # ------------------------------------------------------------------

    def _run_passive_checks(self, endpoint: Endpoint) -> list[Finding]:
        if endpoint.response.status_code < 400:
            return []
        findings: list[Finding] = []
        findings.extend(self._check_null_reference_errors(endpoint))
        findings.extend(self._check_filesystem_path_disclosure(endpoint))
        findings.extend(self._check_database_connection_disclosure(endpoint))
        return findings

    def _check_null_reference_errors(self, endpoint: Endpoint) -> list[Finding]:
        body = endpoint.response.body
        match = self._find_match(body, NULL_REFERENCE_PATTERNS)
        if not match:
            return []

        return [Finding(
            title="Null-Reference Exception Leaked to Response",
            severity=Severity.MEDIUM,
            endpoint=endpoint,
            description=(
                "The response body contains a null/undefined-reference "
                "error (e.g. a NullPointerException, 'Cannot read "
                "property of null/undefined', or an unset object "
                "reference). This indicates an unhandled exception path "
                "reaching the client rather than being caught and "
                "translated into a safe, generic error, and can hint at "
                "an underlying logic bug an attacker may be able to "
                "trigger deliberately."
            ),
            remediation=[
                "Catch null/undefined-reference exceptions at the "
                "appropriate layer instead of letting them propagate to "
                "the HTTP response.",
                "Validate inputs and object state before use so these "
                "conditions are prevented rather than merely caught.",
                "Return a generic, non-revealing error message to the "
                "client and log the full exception server-side only.",
            ],
            evidence={"pattern": match, "snippet": self._snippet(body, match)},
            references=[_CWE_ERROR_HANDLING, _CWE_INFO_EXPOSURE_ERROR],
            owasp=_OWASP_CATEGORY,
            cvss_score=5.3,
        )]

    def _check_filesystem_path_disclosure(self, endpoint: Endpoint) -> list[Finding]:
        body = endpoint.response.body
        match = self._find_path_match(body)
        if not match:
            return []

        return [Finding(
            title="File System Path Disclosure in Error Output",
            severity=Severity.HIGH,
            endpoint=endpoint,
            description=(
                "The response body contains an absolute file system "
                "path (or a source-file/line reference from an "
                "unhandled exception), revealing server-side directory "
                "layout, deployment structure, or source file "
                "organization to the client."
            ),
            remediation=[
                "Catch exceptions before their raw representation "
                "(including file paths and line numbers) reaches the "
                "client.",
                "Return a generic error message with no file system "
                "detail, and log the full exception - including paths - "
                "server-side only.",
            ],
            evidence={"matched_path": match, "snippet": self._snippet(body, match)},
            references=[_CWE_INFO_EXPOSURE_DEBUG, _CWE_INFO_EXPOSURE_ERROR],
            owasp=_OWASP_CATEGORY,
            cvss_score=7.1,
        )]

    def _check_database_connection_disclosure(self, endpoint: Endpoint) -> list[Finding]:
        body = endpoint.response.body
        match = self._find_match(body, DB_CONNECTION_PATTERNS)
        if not match:
            return []

        return [Finding(
            title="Database Connection Detail Disclosure in Error Output",
            severity=Severity.HIGH,
            endpoint=endpoint,
            description=(
                "The response body contains what appears to be a "
                "database connection string or connection parameter "
                "(driver URI, host, user, or password field), most "
                "likely leaked via an unhandled database exception. "
                "This can directly expose credentials or internal "
                "network/database topology."
            ),
            remediation=[
                "Catch database exceptions at the data-access layer and "
                "never let a raw connection string or driver exception "
                "reach the client.",
                "Rotate any credentials that may have already been "
                "exposed through this endpoint.",
                "Log the full exception, including connection details, "
                "server-side only, ideally with credential redaction.",
            ],
            evidence={"pattern": match, "snippet": self._snippet(body, match)},
            references=[_CWE_INFO_EXPOSURE_ERROR, _CWE_ERROR_HANDLING],
            owasp=_OWASP_CATEGORY,
            cvss_score=8.2,
        )]

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_match(text: str, patterns: list[str]) -> Optional[str]:
        """Return the first pattern found in ``text`` (case-insensitive), or None."""
        lowered = text.lower()
        for pattern in patterns:
            if pattern.lower() in lowered:
                return pattern
        return None

    @staticmethod
    def _find_path_match(text: str) -> Optional[str]:
        """Return the first file-system-path-like match found in ``text``, or None."""
        for pattern in FILESYSTEM_PATH_PATTERNS:
            match = pattern.search(text)
            if match:
                return match.group(0)
        return None

    @staticmethod
    def _snippet(body: str, match: str, context: int = 40) -> str:
        """Return a short excerpt of ``body`` centered on ``match`` as evidence."""
        idx = body.lower().find(match.lower())
        if idx == -1:
            return match
        start = max(0, idx - context)
        end = min(len(body), idx + len(match) + context)
        return body[start:end].strip()