"""
scanners/a09_logging.py
------------------------
OWASP A09:2021 - Security Logging and Monitoring Failures

Passive and minimal-active checks for logging/monitoring related
weaknesses: leaked stack traces, verbose error messages, server/
framework fingerprinting via response headers and bodies, exposed debug
headers, verbose HTTP 500 pages, and a small, fixed list of well-known
debug/log endpoints.

This scanner ONLY analyzes an already-populated Target object handed to
it by the existing crawler. It:

    - does NOT crawl, recursively discover pages, or build a sitemap
    - does NOT parse robots.txt
    - does NOT parse JavaScript to find URLs
    - does NOT maintain a visited-URL set
    - does NOT implement a spider or any HTTP infrastructure of its own

The only network activity this module performs is a short, fixed list
of well-known path probes (see DEBUG_ENDPOINT_PATHS / LOG_PATHS below),
issued through the project's existing, shared HttpClient - never a new
session, never requests/aiohttp/urllib.

A note on Finding.endpoint and the active-check probes:
    core.models.Finding.endpoint is typed as Endpoint, not a URL string,
    so every Finding this scanner produces must carry a real Endpoint
    instance. For passive checks that's trivial - we just attach the
    exact Endpoint object the crawler already discovered and handed us.
    For the active probes (a fixed handful of debug/log paths the
    crawler never visited), there is no existing Endpoint to reuse. The
    narrowest way to satisfy the Finding schema without reintroducing
    crawler/spider behavior is to wrap the single HTTP response the
    probe itself just received into a minimal Endpoint - purely as a
    reporting container for that one response, not as site discovery
    (no links/forms extraction, no queueing, no recursion). This is a
    judgment call reconciling two requirements that are in tension
    (Finding needs an Endpoint; the scanner must not build Endpoints);
    flagging it here rather than silently picking a side.
"""

from __future__ import annotations

from typing import Optional

from ..core.models import Target, Endpoint, ResponseData, Finding, Severity
from ..core.http_client import HttpClient

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------

STACK_TRACE_PATTERNS: list[str] = [
    "Traceback (most recent call last)",
    "java.lang.",
    "Exception in thread",
    "NullPointerException",
    "PHP Fatal error",
    "Warning:",
    "Notice:",
    "Stack trace",
]

VERBOSE_ERROR_PATTERNS: list[str] = [
    "SQLSTATE",
    "database error",
    "Undefined variable",
    "syntax error",
    "Exception:",
    "Internal Exception",
]

SERVER_INFO_HEADERS: list[str] = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-Runtime",
    "X-Generator",
]

DEBUG_HEADERS: list[str] = [
    "X-Debug",
    "X-Debug-Token",
    "X-Debug-Token-Link",
]

FRAMEWORK_DISCLOSURE_PATTERNS: list[str] = [
    "Express",
    "Spring Boot",
    "Apache Tomcat",
    "Werkzeug",
    "Django",
    "Flask",
]

# Small, fixed, predefined probe lists - no brute-force discovery.
DEBUG_ENDPOINT_PATHS: list[str] = [
    "/debug",
    "/debug/",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/mappings",
    "/env",
    "/server-status",
    "/phpinfo.php",
    "/trace.axd",
]

LOG_PATHS: list[str] = [
    "/logs/",
    "/log/",
    "/error.log",
    "/debug.log",
    "/access.log",
    "/logs/debug.log",
]

_OWASP_CATEGORY = "A09:2021-Security Logging and Monitoring Failures"
_OWASP_REFERENCE = "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"

# Explicit per-probe timeout (seconds). Must be passed on every
# HttpClient.get() call in this module - see the compatibility note in
# _probe_path for why leaving it unspecified would disable timeouts
# entirely rather than falling back to HttpClient's configured default.
_PROBE_TIMEOUT_SECONDS = 10


class LoggingFailureScanner:
    """OWASP A09 scanner: security logging & monitoring failures."""

    def __init__(self, http_client: HttpClient):
        """
        Args:
            http_client: The project's shared, already-configured
                HttpClient instance. This scanner never creates its own
                HTTP session - every active probe below reuses this one,
                and only when a fixed-path active check is being run.
        """
        self._http_client = http_client

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(self, target: Target) -> list[Finding]:
        """
        Analyze every Endpoint already discovered on ``target`` (passive
        checks), then probe a small fixed set of well-known debug/log
        paths against ``target.base_url`` (active checks).

        Returns:
            Every Finding produced by either phase.
        """
        findings: list[Finding] = []

        for endpoint in target.endpoints:
            findings.extend(self._run_passive_checks(endpoint))

        findings.extend(await self._run_active_checks(target))

        return findings

    # ------------------------------------------------------------------
    # Passive checks - inspect data the crawler already collected
    # ------------------------------------------------------------------

    def _run_passive_checks(self, endpoint: Endpoint) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_stack_traces(endpoint))
        findings.extend(self._check_verbose_errors(endpoint))
        findings.extend(self._check_server_info_leakage(endpoint))
        findings.extend(self._check_debug_headers(endpoint))
        findings.extend(self._check_framework_disclosure(endpoint))
        findings.extend(self._check_verbose_500(endpoint))
        return findings

    def _check_stack_traces(self, endpoint: Endpoint) -> list[Finding]:
        body = endpoint.response.body
        match = self._find_match(body, STACK_TRACE_PATTERNS)
        if not match:
            return []

        return [Finding(
            title="Stack Trace Disclosure",
            severity=Severity.MEDIUM,
            endpoint=endpoint,
            description=(
                "The response body contains what appears to be a raw "
                "application stack trace, which can reveal internal "
                "file paths, class names, and framework internals to "
                "an attacker."
            ),
            remediation=[
                "Disable debug/verbose error output in production.",
                "Return generic error pages to clients.",
                "Log full stack traces server-side only, never in the HTTP response.",
            ],
            evidence={"pattern": match, "snippet": self._snippet(body, match)},
            references=[_OWASP_REFERENCE, "https://cwe.mitre.org/data/definitions/209.html"],
            owasp=_OWASP_CATEGORY,
            cvss_score=5.3,
        )]

    def _check_verbose_errors(self, endpoint: Endpoint) -> list[Finding]:
        body = endpoint.response.body
        match = self._find_match(body, VERBOSE_ERROR_PATTERNS)
        if not match:
            return []

        return [Finding(
            title="Verbose Error Message Disclosure",
            severity=Severity.MEDIUM,
            endpoint=endpoint,
            description=(
                "The response body contains a verbose, application- or "
                "database-level error message. Such messages often leak "
                "query structure, table/column names, or internal logic "
                "that helps an attacker refine further attacks."
            ),
            remediation=[
                "Catch exceptions server-side and return a generic error message to the client.",
                "Log the verbose details internally instead of rendering them in the response.",
            ],
            evidence={"pattern": match, "snippet": self._snippet(body, match)},
            references=[_OWASP_REFERENCE, "https://cwe.mitre.org/data/definitions/209.html"],
            owasp=_OWASP_CATEGORY,
            cvss_score=5.3,
        )]

    def _check_server_info_leakage(self, endpoint: Endpoint) -> list[Finding]:
        headers = endpoint.response.headers
        leaked = {
            name: self._header_value(headers, name)
            for name in SERVER_INFO_HEADERS
            if self._header_present(headers, name)
        }
        if not leaked:
            return []

        return [Finding(
            title="Server/Technology Information Disclosure",
            severity=Severity.LOW,
            endpoint=endpoint,
            description=(
                "The response includes headers that disclose server "
                "software, framework, or runtime details, which can help "
                "an attacker fingerprint the stack and target known "
                "vulnerabilities for that specific technology."
            ),
            remediation=[
                "Remove or mask identifying headers (Server, X-Powered-By, "
                "X-AspNet-Version, X-Runtime, X-Generator) at the web "
                "server or reverse proxy layer.",
            ],
            evidence={"leaked_headers": leaked},
            references=[_OWASP_REFERENCE, "https://cwe.mitre.org/data/definitions/200.html"],
            owasp=_OWASP_CATEGORY,
            cvss_score=3.1,
        )]

    def _check_debug_headers(self, endpoint: Endpoint) -> list[Finding]:
        headers = endpoint.response.headers
        leaked = {
            name: self._header_value(headers, name)
            for name in DEBUG_HEADERS
            if self._header_present(headers, name)
        }
        if not leaked:
            return []

        return [Finding(
            title="Debug Header Exposed",
            severity=Severity.HIGH,
            endpoint=endpoint,
            description=(
                "The response includes one or more debug headers (e.g. "
                "X-Debug-Token) typically emitted by a framework's debug "
                "toolbar. These headers can expose or link to a debug "
                "profiler that reveals request internals, environment "
                "data, and sometimes credentials."
            ),
            remediation=[
                "Disable debug/profiler tooling in production environments.",
                "Ensure no X-Debug-* headers are ever emitted outside of local development.",
            ],
            evidence={"leaked_headers": leaked},
            references=[_OWASP_REFERENCE, "https://cwe.mitre.org/data/definitions/489.html"],
            owasp=_OWASP_CATEGORY,
            cvss_score=7.5,
        )]

    def _check_framework_disclosure(self, endpoint: Endpoint) -> list[Finding]:
        headers = endpoint.response.headers
        body = endpoint.response.body
        haystack = " ".join(headers.values()) + " " + body

        match = self._find_match(haystack, FRAMEWORK_DISCLOSURE_PATTERNS)
        if not match:
            return []

        return [Finding(
            title="Framework/Version Disclosure",
            severity=Severity.LOW,
            endpoint=endpoint,
            description=(
                "The response reveals the underlying web framework "
                "(and potentially its version), which can help an "
                "attacker target known, framework-specific "
                "vulnerabilities."
            ),
            remediation=[
                "Suppress framework identification banners/headers.",
                "Avoid rendering default framework error or debug pages in production.",
            ],
            evidence={"pattern": match, "snippet": self._snippet(haystack, match)},
            references=[_OWASP_REFERENCE],
            owasp=_OWASP_CATEGORY,
            cvss_score=3.1,
        )]

    def _check_verbose_500(self, endpoint: Endpoint) -> list[Finding]:
        if endpoint.response.status_code != 500:
            return []

        body = endpoint.response.body
        # A bare HTTP 500 with a generic body isn't itself a finding -
        # only flag it when the body also trips one of the detail-
        # leaking signals already defined above.
        match = self._find_match(body, STACK_TRACE_PATTERNS + VERBOSE_ERROR_PATTERNS)
        if not match:
            return []

        return [Finding(
            title="Verbose HTTP 500 Error Page",
            severity=Severity.MEDIUM,
            endpoint=endpoint,
            description=(
                "The server returned an HTTP 500 response whose body "
                "contains detailed internal error information rather "
                "than a generic error page."
            ),
            remediation=[
                "Configure the application/web server to return a generic 500 error page in production.",
                "Log the detailed error server-side only.",
            ],
            evidence={"pattern": match, "snippet": self._snippet(body, match), "status_code": 500},
            references=[_OWASP_REFERENCE],
            owasp=_OWASP_CATEGORY,
            cvss_score=5.3,
        )]

    # ------------------------------------------------------------------
    # Active checks - a small, fixed list of well-known path probes
    # ------------------------------------------------------------------

    async def _run_active_checks(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        for path in DEBUG_ENDPOINT_PATHS:
            finding = await self._probe_path(target.base_url, path, kind="debug")
            if finding:
                findings.append(finding)

        for path in LOG_PATHS:
            finding = await self._probe_path(target.base_url, path, kind="log")
            if finding:
                findings.append(finding)

        return findings

    async def _probe_path(self, base_url: str, path: str, kind: str) -> Optional[Finding]:
        """
        Probe a single fixed, well-known path via the existing HttpClient.

        Returns a Finding only if the path responds with HTTP 200 (i.e.
        appears to actually exist and be publicly accessible). Any
        transport-level failure (timeout, connection error, DNS failure)
        is treated as "not present" and silently skipped - this is a
        small fixed probe list, not a discovery crawl, so failures are
        not exceptional.
        """
        url = self._join_url(base_url, path)

        try:
            # NOTE - compatibility fix: core.http_client.HttpClient.get()
            # defaults timeout/follow_redirects to None and forwards them
            # to httpx unconditionally. httpx treats an explicit
            # timeout=None as "no timeout" (not "use the client's
            # configured default"), and an explicit follow_redirects=None
            # as falsy (not "use the client's configured default" either -
            # the AsyncClient was constructed with follow_redirects=True,
            # but that only applies when the per-call kwarg is left as
            # httpx's own sentinel, which this wrapper never passes
            # through). Left unspecified, every probe here would (a) be
            # able to hang forever on an unresponsive path, and (b) fail
            # to follow a redirect a probed path might legitimately issue
            # (e.g. /env -> /env/), producing a false negative. Both are
            # avoided by always passing explicit values on every call.
            response = await self._http_client.get(
                url,
                timeout=_PROBE_TIMEOUT_SECONDS,
                follow_redirects=True,
            )
        except Exception:
            return None

        status_code = getattr(response, "status_code", 0) or 0
        if status_code != 200:
            return None

        try:
            body = response.text
        except Exception:
            # httpx.Response.text can raise on an undecodable body (e.g.
            # a genuinely binary log/access file); treat that the same
            # as "nothing readable to report" rather than aborting the
            # whole active-check phase.
            body = ""

        headers = dict(getattr(response, "headers", {}) or {})
        content_type = self._header_value(headers, "Content-Type")

        # See module docstring: this Endpoint exists solely to carry the
        # one response this probe just received, so Finding.endpoint has
        # something valid to point at - it is not a discovered/crawled
        # page and nothing downstream should treat it as one.
        probed_endpoint = Endpoint(
            url=url,
            method="GET",
            response=ResponseData(
                status_code=status_code,
                content_type=content_type,
                headers=headers,
                body=body,
            ),
        )

        if kind == "debug":
            title = f"Exposed Debug Endpoint: {path}"
            description = (
                f"A debug/management endpoint at {path} responded with "
                "HTTP 200 and appears to be publicly accessible. Debug "
                "and actuator-style endpoints frequently expose "
                "environment variables, configuration, internal routes, "
                "or health/diagnostic internals."
            )
        else:
            title = f"Exposed Log File/Directory: {path}"
            description = (
                f"A log file or log directory at {path} responded with "
                "HTTP 200 and appears to be publicly accessible. Exposed "
                "logs can leak stack traces, credentials, session "
                "tokens, or other sensitive runtime data."
            )

        return Finding(
            title=title,
            severity=Severity.HIGH,
            endpoint=probed_endpoint,
            description=description,
            remediation=[
                "Restrict or remove public access to debug/management endpoints and log files/directories.",
                "Require authentication or bind them to an internal network only.",
                "Disable them entirely in production where not needed.",
            ],
            evidence={"status_code": status_code, "snippet": body[:200].strip()},
            references=[_OWASP_REFERENCE, "https://cwe.mitre.org/data/definitions/200.html"],
            owasp=_OWASP_CATEGORY,
            cvss_score=7.5,
        )

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _join_url(base_url: str, path: str) -> str:
        return base_url.rstrip("/") + "/" + path.lstrip("/")

    @staticmethod
    def _find_match(text: str, patterns: list[str]) -> Optional[str]:
        """Return the first pattern found in ``text`` (case-insensitive), or None."""
        lowered = text.lower()
        for pattern in patterns:
            if pattern.lower() in lowered:
                return pattern
        return None

    @staticmethod
    def _header_present(headers: dict[str, str], name: str) -> bool:
        return any(key.lower() == name.lower() for key in headers)

    @staticmethod
    def _header_value(headers: dict[str, str], name: str) -> str:
        for key, value in headers.items():
            if key.lower() == name.lower():
                return value
        return ""

    @staticmethod
    def _snippet(body: str, match: str, context: int = 40) -> str:
        """Return a short excerpt of ``body`` centered on ``match`` as evidence."""
        idx = body.lower().find(match.lower())
        if idx == -1:
            return match
        start = max(0, idx - context)
        end = min(len(body), idx + len(match) + context)
        return body[start:end].strip()