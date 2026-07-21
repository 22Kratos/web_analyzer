#!/usr/bin/env python3
"""
a04_insecure_design.py — A04:2025 Insecure Design scanner

Limited scope, matching the project plan:
  1. Rate Limiting     — burst requests, check for lockout/throttling
  2. Mass Assignment   — inject unexpected params, see if server accepts them
  3. Integer Overflow  — send oversized numbers into numeric fields

Usage:
    python a06_insecure_design.py https://example.com/login
    python a06_insecure_design.py https://example.com/api/users?id=1 --json report.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import warnings
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests
from requests.exceptions import RequestException
import urllib3

warnings.filterwarnings("ignore", category=DeprecationWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT = 8
SEVERITY_COLOR = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[33m",
                   "LOW": "\033[94m", "INFO": "\033[90m"}
RESET = "\033[0m"


@dataclass
class Vulnerability:
    id: str
    category: str
    owasp: str
    name: str
    severity: str
    cvss_score: float
    location: Dict[str, Any]
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    poc: Dict[str, Any] = field(default_factory=dict)
    remediation: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class InsecureDesignScanner:
    """A06:2025 Insecure Design — rate limiting, mass assignment, integer overflow."""

    OWASP_ID = "A06:2025 Insecure Design"
    CATEGORY = "A06: Insecure Design"
    REFS = ["https://owasp.org/Top10/A06_2025-Insecure_Design/"]

    MASS_ASSIGNMENT_PARAMS = {"is_admin": "true", "role": "admin", "admin": "1"}
    OVERFLOW_VALUES = [2**31, 2**63, -2**31, 999999999999999999999]

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, burst_count: int = 15, verbose: bool = False):
        self.timeout = timeout
        self.burst_count = burst_count
        self.verbose = verbose
        self._id_counter = [0]
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "web_analyzer-a06-insecure-design/1.0"})

    def log(self, msg: str) -> None:
        if self.verbose:
            print(f"[*] {msg}", file=sys.stderr)

    def _next_id(self) -> str:
        self._id_counter[0] += 1
        return f"A06-{self._id_counter[0]:03d}"

    def scan(self, url: str) -> List[Vulnerability]:
        findings = []
        findings += self._check_rate_limiting(url)
        findings += self._check_mass_assignment(url)
        findings += self._check_integer_overflow(url)
        return findings

    # ---- 1. Rate limiting ----------------------------------------------

    def _check_rate_limiting(self, url: str) -> List[Vulnerability]:
        statuses = []
        try:
            for _ in range(self.burst_count):
                resp = self.session.get(url, timeout=self.timeout, verify=False)
                statuses.append(resp.status_code)
        except RequestException as e:
            self.log(f"Rate limit check failed: {e}")
            return []

        throttled = any(s in (429, 503) for s in statuses)
        if not throttled:
            return [Vulnerability(
                id=self._next_id(),
                category=self.CATEGORY,
                owasp=self.OWASP_ID,
                name="Missing Rate Limiting",
                severity="MEDIUM",
                cvss_score=5.3,
                location={"url": url, "method": "GET"},
                description=(
                    f"Sent {self.burst_count} rapid requests and received no "
                    "429/503 throttling response, suggesting no rate limiting "
                    "or lockout is enforced."
                ),
                evidence={"requests_sent": self.burst_count, "status_codes": statuses},
                remediation=[
                    "Implement per-IP/per-account rate limiting",
                    "Add account lockout or exponential backoff after repeated requests",
                ],
                references=self.REFS,
            )]
        return []

    # ---- 2. Mass assignment ---------------------------------------------

    def _check_mass_assignment(self, url: str) -> List[Vulnerability]:
        findings = []
        try:
            baseline = self.session.get(url, timeout=self.timeout, verify=False)
        except RequestException as e:
            self.log(f"Mass assignment baseline request failed: {e}")
            return findings

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for k, v in self.MASS_ASSIGNMENT_PARAMS.items():
            params[k] = v
        injected_query = urlencode(params, doseq=True)
        injected_url = urlunparse(parsed._replace(query=injected_query))

        try:
            resp = self.session.get(injected_url, timeout=self.timeout, verify=False)
        except RequestException as e:
            self.log(f"Mass assignment injection request failed: {e}")
            return findings

        if resp.status_code == baseline.status_code and len(resp.content) != len(baseline.content):
            findings.append(Vulnerability(
                id=self._next_id(),
                category=self.CATEGORY,
                owasp=self.OWASP_ID,
                name="Possible Mass Assignment",
                severity="HIGH",
                cvss_score=7.1,
                location={"url": injected_url, "method": "GET",
                          "parameter": ", ".join(self.MASS_ASSIGNMENT_PARAMS.keys())},
                description=(
                    "Injecting unexpected privileged-looking parameters "
                    "(e.g. is_admin, role) changed the response compared to "
                    "baseline, suggesting the server may bind extra fields "
                    "without an allowlist."
                ),
                evidence={"baseline_length": len(baseline.content),
                          "injected_length": len(resp.content),
                          "injected_params": self.MASS_ASSIGNMENT_PARAMS},
                poc={"request": f"GET {injected_url} HTTP/1.1"},
                remediation=[
                    "Use explicit allowlists for bindable fields (DTOs), never bind raw request bodies to models",
                    "Reject unknown/unexpected parameters instead of silently accepting them",
                ],
                references=self.REFS,
            ))
        return findings

    # ---- 3. Integer overflow ---------------------------------------------

    def _check_integer_overflow(self, url: str) -> List[Vulnerability]:
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        numeric_params = {k: v for k, v in params.items() if v and str(v[0]).lstrip("-").isdigit()}

        if not numeric_params:
            return findings

        for param_name in numeric_params:
            for overflow_val in self.OVERFLOW_VALUES:
                test_params = dict(params)
                test_params[param_name] = [str(overflow_val)]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))
                try:
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                except RequestException as e:
                    self.log(f"Integer overflow request failed: {e}")
                    continue

                if resp.status_code >= 500:
                    findings.append(Vulnerability(
                        id=self._next_id(),
                        category=self.CATEGORY,
                        owasp=self.OWASP_ID,
                        name="Unhandled Integer Overflow",
                        severity="MEDIUM",
                        cvss_score=5.3,
                        location={"url": test_url, "method": "GET", "parameter": param_name},
                        description=(
                            f"Submitting an oversized numeric value ({overflow_val}) "
                            f"in parameter '{param_name}' caused a server error, "
                            "suggesting the value isn't validated or bounds-checked."
                        ),
                        evidence={"parameter": param_name, "value_sent": overflow_val,
                                  "status_code": resp.status_code},
                        poc={"request": f"GET {test_url} HTTP/1.1"},
                        remediation=[
                            "Validate numeric input against expected ranges before use",
                            "Use appropriately sized/typed fields and reject out-of-range values",
                        ],
                        references=self.REFS,
                    ))
                    break  # one finding per param is enough
        return findings


# ---- Output ---------------------------------------------------------------

def print_table(vulns: List[Vulnerability], target: str, duration: float) -> None:
    print(f"\nA06 Insecure Design Scan — {target}")
    print("=" * 78)
    if not vulns:
        print("No insecure-design findings.")
    else:
        print(f"{'FINDING':<30} {'SEVERITY':<10} {'METHOD':<8} {'LOCATION'}")
        print("-" * 78)
        for v in vulns:
            color = SEVERITY_COLOR.get(v.severity, "")
            loc = v.location.get("parameter") or v.location.get("url", "")
            print(f"{v.name[:29]:<30} {color}{v.severity:<10}{RESET} "
                  f"{v.location.get('method',''):<8} {loc}")
    print("-" * 78)
    print(f"Summary: {len(vulns)} finding(s)")
    print(f"Duration: {duration:.2f}s")


def build_json_report(vulns: List[Vulnerability], target: str, duration: float) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        counts[v.severity.lower()] += 1
    return {
        "scan_info": {"target": target, "timestamp": datetime.now(timezone.utc).isoformat(),
                       "duration_seconds": round(duration, 2), "scanners_run": ["a06"]},
        "summary": counts,
        "vulnerabilities": [asdict(v) for v in vulns],
    }


def main():
    parser = argparse.ArgumentParser(description="A06:2025 Insecure Design scanner "
                                                   "(rate limiting, mass assignment, integer overflow).")
    parser.add_argument("target", help="Target URL, e.g. https://example.com/login?id=1")
    parser.add_argument("--json", dest="json_path", help="Write JSON report to this path")
    parser.add_argument("--burst", type=int, default=15, help="Requests to send for rate-limit check")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    scanner = InsecureDesignScanner(timeout=args.timeout, burst_count=args.burst, verbose=args.verbose)
    start = time.time()
    vulns = scanner.scan(args.target)
    duration = time.time() - start

    print_table(vulns, args.target, duration)

    if args.json_path:
        with open(args.json_path, "w") as f:
            json.dump(build_json_report(vulns, args.target, duration), f, indent=2)
        print(f"\nJSON report written to {args.json_path}")


if __name__ == "__main__":
    main()
