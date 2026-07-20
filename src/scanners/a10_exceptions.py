"""
a10_exceptions.py

OWASP Top 10 (2025 draft) - A10: Mishandling of Exceptions scanner module.

Detects symptoms of exceptions being caught/surfaced incorrectly rather than
being handled safely and generically:

  1. NULL-reference hints     - "NULL pointer", "null value", NPE-style leaks
  2. Sensitive info in errors - file system paths, DB connection details,
                                 stack traces bleeding into responses

This is a companion module to a09_logging.py (A09: Security Logging Failures) —
the two OWASP categories overlap heavily in symptoms but focus on different
root causes: A09 is about *failing to log/alert safely*, A10 is about
*failing to catch/handle exceptions safely*, so this module specifically
concentrates on NULL-handling bugs and sensitive-data leakage patterns rather
than generic verbosity or debug endpoints.

Usage:
    from a10_exceptions import A10ExceptionScanner

    scanner = A10ExceptionScanner(base_url="https://target.example.com")
    report = scanner.scan()
    print(report.to_json())

CLI:
    python3 a10_exceptions.py https://target.example.com
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
    check: str
    severity: str
    url: str
    evidence: str
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

# NULL-reference / uninitialized-value error hints across languages.
NULL_HINT_PATTERNS = [
    re.compile(r"NULL pointer", re.I),
    re.compile(r"null value", re.I),
    re.compile(r"NullPointerException"),
    re.compile(r"NullReferenceException"),
    re.compile(r"Object reference not set to an instance of an object"),
    re.compile(r"Cannot read propert(?:y|ies) of (?:null|undefined)"),
    re.compile(r"Cannot read propert(?:y|ies) of undefined"),
    re.compile(r"TypeError:\s+.*?(?:is|of)\s+(?:null|None|undefined)", re.I),
    re.compile(r"AttributeError:\s+'NoneType'\s+object has no attribute"),
    re.compile(r"undefined index", re.I),
    re.compile(r"undefined variable", re.I),
    re.compile(r"undefined offset", re.I),
    re.compile(r"nil pointer dereference", re.I),
    re.compile(r"unwrap\(\)\s+on\s+a\s+None\s+value"),  # Rust
]

# Sensitive information disclosed via error output.
FILE_PATH_PATTERNS = [
    re.compile(r"[A-Za-z]:\\(?:[\w.\- ]+\\)+[\w.\-]+"),          # Windows paths e.g. C:\inetpub\...
    re.compile(r"/(?:var|home|etc|usr|opt|srv)/(?:[\w.\-]+/)+[\w.\-]+"),  # *nix paths
    re.compile(r"/var/www/[\w./\-]+"),
    re.compile(r"in\s+/[\w./\-]+\.(?:php|py|rb|js|java)\s+on\s+line\s+\d+", re.I),
]

DB_INFO_PATTERNS = [
    re.compile(r"jdbc:[\w:]+://[\w.\-:@/]+"),
    re.compile(r"(?:mysql|postgres(?:ql)?|mongodb|mssql|oracle)://[^\s\"']+", re.I),
    re.compile(r"SQLSTATE\[\w+\]"),
    re.compile(r"ORA-\d{5}"),
    re.compile(r"pg_(?:query|connect|exec)\(\)"),
    re.compile(r"Access denied for user '.*?'@'.*?'"),
    re.compile(r"Unknown database '.*?'"),
    re.compile(r"could not connect to server"),
    re.compile(r"Login failed for user '.*?'"),
    re.compile(r"ConnectionString", re.I),
]

STACK_TRACE_HINTS = [
    re.compile(r"Traceback \(most recent call last\):"),
    re.compile(r"Stack trace:\s*#0", re.I),
    re.compile(r"at\s+[\w$.]+\([\w.]+:\d+\)"),
    re.compile(r"Caused by:\s*[\w.$]+Exception"),
]

MAX_EVIDENCE_LEN = 220


def _clip(text: str, length: int = MAX_EVIDENCE_LEN) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= length else text[:length] + "..."


def _first_match(patterns, body: str):
    for pattern in patterns:
        m = pattern.search(body)
        if m:
            return m
    return None


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #

class A10ExceptionScanner:
    """
    Scans a target for symptoms of A10: Mishandling of Exceptions.

    Black-box approach: sends a set of harmless probe requests engineered to
    trigger edge-case/exception paths (missing params, unexpected types,
    boundary values) and inspects responses for:
      - NULL/None dereference hints (exception caught but message leaked raw)
      - Sensitive data leaking out of the exception (paths, DB info, stacks)
    """

    MODULE_NAME = "A10-mishandling-exceptions"

    # Requests designed to be harmless but likely to hit unguarded exception
    # paths: missing required params, wrong types, empty/None-ish values.
    PROBES = [
        ("/?id=", "empty id param"),
        ("/?id=null", "literal 'null' as param value"),
        ("/?id=undefined", "literal 'undefined' as param value"),
        ("/?page=NaN", "non-numeric where number expected"),
        ("/?user_id=-1", "boundary/negative id"),
        ("/?callback=", "empty callback param"),
        ("/api/user", "missing required path segment / no id"),
        ("/api/user/", "trailing slash, likely missing id"),
        ("/search?q=", "empty search query"),
    ]

    def __init__(
        self,
        base_url: str,
        session: Optional[requests.Session] = None,
        timeout: float = 10.0,
        verify_tls: bool = True,
        user_agent: str = "A10-Scanner/1.0",
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

    def _check_null_hints(self, url: str, body: str, report: ScanReport) -> None:
        match = _first_match(NULL_HINT_PATTERNS, body)
        if match:
            report.add(Finding(
                check="null_reference_hint",
                severity="medium",
                url=url,
                evidence=_clip(match.group(0)),
                detail="Response reveals an unhandled null/None dereference error",
            ))

    def _check_sensitive_in_errors(self, url: str, body: str, report: ScanReport) -> None:
        path_match = _first_match(FILE_PATH_PATTERNS, body)
        if path_match:
            report.add(Finding(
                check="sensitive_file_path_disclosure",
                severity="high",
                url=url,
                evidence=_clip(path_match.group(0)),
                detail="Exception output discloses server file-system path",
            ))

        db_match = _first_match(DB_INFO_PATTERNS, body)
        if db_match:
            report.add(Finding(
                check="sensitive_db_info_disclosure",
                severity="critical",
                url=url,
                evidence=_clip(db_match.group(0)),
                detail="Exception output discloses database connection/query details",
            ))

        stack_match = _first_match(STACK_TRACE_HINTS, body)
        if stack_match:
            report.add(Finding(
                check="sensitive_stack_trace_disclosure",
                severity="high",
                url=url,
                evidence=_clip(stack_match.group(0)),
                detail="Exception was not caught generically; raw stack trace exposed",
            ))

    def _run_probes(self, report: ScanReport) -> None:
        for path, _label in self.PROBES:
            url, resp = self._get(path)
            if isinstance(resp, Exception):
                continue
            body = resp.text or ""
            self._check_null_hints(url, body, report)
            self._check_sensitive_in_errors(url, body, report)

    # -- public API ----------------------------------------------------------- #

    def scan(self) -> ScanReport:
        report = ScanReport(module=self.MODULE_NAME, target=self.base_url)

        # Baseline homepage check as well, in case errors surface there
        url, resp = self._get("/")
        if not isinstance(resp, Exception):
            body = resp.text or ""
            self._check_null_hints(url, body, report)
            self._check_sensitive_in_errors(url, body, report)

        self._run_probes(report)
        return report


# --------------------------------------------------------------------------- #
# CLI entry point
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("Usage: python3 a10_exceptions.py <base_url>", file=sys.stderr)
        return 1

    target = argv[0]
    scanner = A10ExceptionScanner(base_url=target)
    report = scanner.scan()
    print(report.to_json())
    return 0 if not report.findings else 2


if __name__ == "__main__":
    sys.exit(main())
