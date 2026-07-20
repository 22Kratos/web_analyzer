"""
a09_logging.py

OWASP Top 10 (2025 draft) - A09: Security Logging Failures scanner module.

Detects symptoms that usually indicate an application is NOT logging/handling
errors safely, which is what makes A09 exploitable in practice:

  1. Stack trace disclosure   - PHP / Java / Python tracebacks leaking to the client
  2. Debug endpoint exposure  - /debug, /actuator, /env and common variants
  3. Verbose error messages   - detailed internal error output on normal requests

Usage:
    from a09_logging import A09LoggingScanner

    scanner = A09LoggingScanner(base_url="https://target.example.com")
    report = scanner.scan()
    print(report.to_json())

CLI:
    python3 a09_logging.py https://target.example.com
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import List, Optional, TYPE_CHECKING
from urllib.parse import urljoin

if TYPE_CHECKING:
    # Only imported for type-checkers (Pyright/Pylance/mypy); never executed
    # at runtime, so it can't cause the "not a known attribute of None" or
    # "variable not allowed in type expression" warnings below.
    import requests
else:
    try:
        import requests
    except ImportError:  # pragma: no cover
        requests = None


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    check: str                # e.g. "stack_trace_disclosure"
    severity: str              # "info" | "low" | "medium" | "high" | "critical"
    url: str
    evidence: str              # short excerpt, truncated
    detail: str = ""
    status_code: Optional[int] = None


@dataclass
class ScanReport:
    module: str
    target: str
    findings: List[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "target": self.target,
            "finding_count": len(self.findings),
            "findings": [asdict(f) for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# --------------------------------------------------------------------------- #
# Signature sets
# --------------------------------------------------------------------------- #

# Stack trace signatures per-language. Kept as compiled regexes so the scanner
# can also report *which* stack was disclosed (useful for the report body).
STACK_TRACE_PATTERNS = {
    "php": [
        re.compile(r"Fatal error:.*?in\s+.+?\.php\s+on\s+line\s+\d+", re.I | re.S),
        re.compile(r"Warning:.*?in\s+.+?\.php\s+on\s+line\s+\d+", re.I | re.S),
        re.compile(r"Uncaught (Exception|Error):", re.I),
        re.compile(r"Stack trace:\s*#0", re.I),
    ],
    "java": [
        re.compile(r"(?:[a-zA-Z0-9_$]+\.)+[A-Za-z0-9_$]+Exception"),
        re.compile(r"at\s+[\w$.]+\([\w.]+\.java:\d+\)"),
        re.compile(r"Caused by:\s*[\w.$]+Exception"),
        re.compile(r"javax\.servlet\.ServletException"),
    ],
    "python": [
        re.compile(r"Traceback \(most recent call last\):"),
        re.compile(r"File \"[^\"]+\.py\", line \d+, in \w+"),
        re.compile(r"django\.core\.exceptions\.\w+"),
        re.compile(r"werkzeug\.exceptions\.\w+"),
    ],
    "dotnet": [
        re.compile(r"System\.[\w.]+Exception"),
        re.compile(r"at\s+System\.[\w.]+\(.*?\)"),
        re.compile(r"Server Error in '.*?' Application"),
    ],
    "nodejs": [
        re.compile(r"at\s+[\w./\\]+:\d+:\d+"),
        re.compile(r"\(node:\d+\)\s+\w+Error"),
        re.compile(r"UnhandledPromiseRejectionWarning"),
    ],
}

# Common debug / management / diagnostic endpoints across frameworks.
DEBUG_ENDPOINTS = [
    "/debug",
    "/debug/vars",
    "/debug/pprof",
    "/__debug__",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/mappings",
    "/actuator/heapdump",
    "/actuator/httptrace",
    "/env",
    "/env.php",
    "/.env",
    "/config/env",
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/server-info",
    "/console",
    "/_profiler",
    "/elmah.axd",
    "/trace.axd",
]

# Phrases that indicate a verbose / overly detailed error surfaced to the user
# instead of a generic, safely-logged message.
VERBOSE_ERROR_PHRASES = [
    r"SQL syntax.*?MySQL",
    r"Warning:\s+mysqli?_",
    r"ORA-\d{5}",
    r"Microsoft OLE DB Provider for ODBC Drivers",
    r"Unhandled exception",
    r"Internal Server Error.*?(version|build|debug)",
    r"DEBUG\s*=\s*True",
    r"You have an error in your SQL syntax",
    r"PostgreSQL.*?ERROR",
    r"pg_query\(\)",
    r"ODBC.*?Driver",
    r"Whitelabel Error Page",  # Spring Boot default verbose error page
]
VERBOSE_ERROR_RE = re.compile("|".join(VERBOSE_ERROR_PHRASES), re.I | re.S)

MAX_EVIDENCE_LEN = 220


def _clip(text: str, length: int = MAX_EVIDENCE_LEN) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= length else text[:length] + "..."


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #

class A09LoggingScanner:
    """
    Scans a target for symptoms of A09: Security Logging Failures.

    Note: this module tests for OBSERVABLE SYMPTOMS from the outside
    (stack traces, debug endpoints, verbose errors). It cannot verify that
    logging/alerting is actually happening server-side — that requires log
    access. It's a black-box proxy signal: apps that leak this much detail to
    clients are very unlikely to be logging/alerting correctly either.
    """

    MODULE_NAME = "A09-security-logging-failures"

    def __init__(
        self,
        base_url: str,
        session: Optional[requests.Session] = None,
        timeout: float = 10.0,
        verify_tls: bool = True,
        user_agent: str = "A09-Scanner/1.0",
    ):
        if requests is None:
            raise RuntimeError("The 'requests' package is required: pip install requests")
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", user_agent)
        self.timeout = timeout
        self.verify_tls = verify_tls

    # -- internal helpers --------------------------------------------------- #

    def _get(self, path: str):
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        try:
            return url, self.session.get(
                url, timeout=self.timeout, verify=self.verify_tls, allow_redirects=True
            )
        except requests.RequestException as exc:
            return url, exc

    def _check_stack_traces(self, url: str, body: str, report: ScanReport) -> None:
        for lang, patterns in STACK_TRACE_PATTERNS.items():
            for pattern in patterns:
                match = pattern.search(body)
                if match:
                    report.add(Finding(
                        check="stack_trace_disclosure",
                        severity="high",
                        url=url,
                        evidence=_clip(match.group(0)),
                        detail=f"{lang.upper()} stack trace / error detail exposed to client",
                    ))
                    break  # one hit per language is enough

    def _check_verbose_errors(self, url: str, body: str, status_code: int, report: ScanReport) -> None:
        match = VERBOSE_ERROR_RE.search(body)
        if match:
            report.add(Finding(
                check="verbose_error_message",
                severity="medium",
                url=url,
                evidence=_clip(match.group(0)),
                detail="Response contains detailed internal error/debug information",
                status_code=status_code,
            ))

    def _check_debug_endpoints(self, report: ScanReport) -> None:
        for path in DEBUG_ENDPOINTS:
            url, resp = self._get(path)
            if isinstance(resp, Exception):
                continue
            if resp.status_code < 400 or resp.status_code in (401, 403):
                # 2xx/3xx = accessible; 401/403 still confirms the endpoint exists
                severity = "high" if resp.status_code < 400 else "low"
                report.add(Finding(
                    check="debug_endpoint_exposed",
                    severity=severity,
                    url=url,
                    evidence=f"HTTP {resp.status_code}",
                    detail="Debug/management endpoint reachable" if resp.status_code < 400
                            else "Debug/management endpoint exists but access-restricted",
                    status_code=resp.status_code,
                ))

    def _probe_error_inducing_requests(self, report: ScanReport):
        """
        Send a handful of harmless-but-malformed requests designed to trip
        error handlers (not to exploit anything) so verbose-error / stack
        trace detectors above have something to inspect beyond the homepage.
        """
        probes = [
            ("/?id=1'", "single-quote in query param"),
            ("/?page=../../../../etc/passwd", "path traversal-shaped param"),
            ("/nonexistent-" + "a" * 40, "long unknown path"),
            ("/%00", "null byte in path"),
        ]
        for path, _label in probes:
            url, resp = self._get(path)
            if isinstance(resp, Exception):
                continue
            body = resp.text or ""
            self._check_stack_traces(url, body, report)
            self._check_verbose_errors(url, body, resp.status_code, report)

    # -- public API ----------------------------------------------------------- #

    def scan(self) -> ScanReport:
        report = ScanReport(module=self.MODULE_NAME, target=self.base_url)

        # 1. Baseline homepage check
        url, resp = self._get("/")
        if not isinstance(resp, Exception):
            self._check_stack_traces(url, resp.text or "", report)
            self._check_verbose_errors(url, resp.text or "", resp.status_code, report)

        # 2. Debug / actuator / env endpoints
        self._check_debug_endpoints(report)

        # 3. Lightweight error-inducing probes to surface hidden stack traces
        self._probe_error_inducing_requests(report)

        return report


# --------------------------------------------------------------------------- #
# CLI entry point
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("Usage: python3 a09_logging.py <base_url>", file=sys.stderr)
        return 1

    target = argv[0]
    scanner = A09LoggingScanner(base_url=target)
    report = scanner.scan()
    print(report.to_json())
    return 0 if not report.findings else 2


if __name__ == "__main__":
    sys.exit(main())
