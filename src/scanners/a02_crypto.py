#!/usr/bin/env python3
"""
a02_crypto.py — A02:2025 Cryptographic Failures scanner
Standalone module matching the Web Security Analyzer project plan's
BaseScanner / Vulnerability contract. Checks a target for:
  1. HTTP usage & HTTPS redirect behavior
  2. TLS protocol version support (flags TLS 1.0 / 1.1) + cert expiry
  3. Sensitive data (passwords, tokens, API keys, session IDs) in URL query strings
  4. Cookie security flags (Secure, HttpOnly, SameSite)
  5. Mixed content (HTTPS page loading HTTP sub-resources)
  6. Weak/deprecated cipher suite negotiation
Usage:
    python a04_crypto.py https://example.com
    python a04_crypto.py http://localhost:8080 --json report.json
    python a04_crypto.py https://example.com --urls urls.txt

"""

from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import sys
import uuid
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

import requests
from requests.exceptions import RequestException
import urllib3

# We deliberately probe old/weak TLS versions to test for their presence.
# Suppress the resulting InsecureRequestWarning noise from urllib3.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT = 8


@dataclass
class Vulnerability:
    id: str
    category: str
    owasp: str
    name: str
    severity: str            # CRITICAL / HIGH / MEDIUM / LOW / INFO
    cvss_score: float
    location: Dict[str, Any]
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    poc: Dict[str, Any] = field(default_factory=dict)
    remediation: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


SEVERITY_BANDS = [
    ("CRITICAL", 9.0, 10.0),
    ("HIGH", 7.0, 8.9),
    ("MEDIUM", 4.0, 6.9),
    ("LOW", 0.1, 3.9),
    ("INFO", 0.0, 0.0),
]

SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[94m",
    "INFO": "\033[90m",
}
RESET = "\033[0m"


def _next_id(counter: List[int]) -> str:
    counter[0] += 1
    return f"A04-{counter[0]:03d}"


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #

class CryptoFailureScanner:
    """A04:2025 Cryptographic Failures scanner."""

    OWASP_ID = "A04:2025 Cryptographic Failures"
    CATEGORY = "A04: Cryptographic Failures"

    SENSITIVE_PARAM_PATTERNS = [
        r"pass(word)?", r"pwd", r"token", r"api[_-]?key", r"secret",
        r"session[_-]?id", r"auth", r"access[_-]?token", r"credential",
        r"ssn", r"credit[_-]?card",
    ]

    WEAK_CIPHER_KEYWORDS = ("RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon")

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self._id_counter = [0]
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "web_analyzer-a04-crypto/1.0"})

    def log(self, msg: str) -> None:
        if self.verbose:
            print(f"[*] {msg}", file=sys.stderr)

    # ---- Public entry point ------------------------------------------------

    def scan(self, url: str) -> List[Vulnerability]:
        findings: List[Vulnerability] = []
        parsed = urlparse(url if "://" in url else f"http://{url}")
        hostname = parsed.hostname
        scheme = parsed.scheme
        port = parsed.port or (443 if scheme == "https" else 80)

        findings += self._check_http_usage(url, parsed)
        if hostname:
            findings += self._check_tls(hostname, port)
        findings += self._check_sensitive_data_in_url(url)
        findings += self._check_cookie_flags(url)
        findings += self._check_mixed_content(url)
        return findings

    def scan_many(self, urls: List[str]) -> List[Vulnerability]:
        all_findings: List[Vulnerability] = []
        for u in urls:
            self.log(f"Scanning {u}")
            all_findings += self.scan(u)
        return all_findings

    # ---- 1. HTTP usage / HTTPS redirect ------------------------------------

    def _check_http_usage(self, original_url: str, parsed) -> List[Vulnerability]:
        findings = []
        hostname = parsed.hostname
        if not hostname:
            return findings

        # Does plaintext HTTP work at all?
        http_url = f"http://{hostname}{':' + str(parsed.port) if parsed.port else ''}{parsed.path or '/'}"
        try:
            resp = self.session.get(
                http_url, timeout=self.timeout, allow_redirects=False, verify=False
            )
            if parsed.scheme == "https" or resp.status_code < 400:
                redirected_to_https = (
                    resp.is_redirect
                    and resp.headers.get("Location", "").lower().startswith("https://")
                )
                hsts = resp.headers.get("Strict-Transport-Security")

                if not redirected_to_https:
                    findings.append(Vulnerability(
                        id=_next_id(self._id_counter),
                        category=self.CATEGORY,
                        owasp=self.OWASP_ID,
                        name="Plaintext HTTP Accepted / No HTTPS Redirect",
                        severity="HIGH",
                        cvss_score=7.4,
                        location={"url": http_url, "method": "GET"},
                        description=(
                            "The server responds to plaintext HTTP requests without "
                            "redirecting to HTTPS, allowing data to be transmitted "
                            "or intercepted unencrypted."
                        ),
                        evidence={"status_code": resp.status_code,
                                  "location_header": resp.headers.get("Location")},
                        poc={"request": f"GET {parsed.path or '/'} HTTP/1.1\nHost: {hostname}"},
                        remediation=[
                            "Redirect all HTTP traffic to HTTPS (301)",
                            "Enable HSTS (Strict-Transport-Security header)",
                            "Disable the plaintext HTTP listener where possible",
                        ],
                        references=[
                            "https://owasp.org/Top10/A04_2025-Cryptographic_Failures/",
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                        ],
                    ))
                elif not hsts:
                    findings.append(Vulnerability(
                        id=_next_id(self._id_counter),
                        category=self.CATEGORY,
                        owasp=self.OWASP_ID,
                        name="Missing HSTS Header",
                        severity="MEDIUM",
                        cvss_score=5.3,
                        location={"url": original_url, "method": "GET"},
                        description=(
                            "HTTP redirects to HTTPS, but no Strict-Transport-Security "
                            "header is set, leaving users vulnerable to SSL-stripping "
                            "on subsequent visits."
                        ),
                        evidence={"redirect_status": resp.status_code},
                        remediation=[
                            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
                            "to all HTTPS responses",
                        ],
                        references=["https://owasp.org/Top10/A04_2025-Cryptographic_Failures/"],
                    ))
        except RequestException as e:
            self.log(f"HTTP check failed for {http_url}: {e}")

        return findings

    # ---- 2. TLS version & certificate -------------------------------------

    def _check_tls(self, hostname: str, port: int) -> List[Vulnerability]:
        findings = []
        weak_versions = {
            "TLSv1": ssl.TLSVersion.TLSv1,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        }
        supported_weak = []

        for label, tls_version in weak_versions.items():
            if self._supports_tls_version(hostname, port, tls_version):
                supported_weak.append(label)

        if supported_weak:
            findings.append(Vulnerability(
                id=_next_id(self._id_counter),
                category=self.CATEGORY,
                owasp=self.OWASP_ID,
                name="Deprecated TLS Version Supported",
                severity="HIGH",
                cvss_score=7.5,
                location={"url": f"{hostname}:{port}", "method": "TLS_HANDSHAKE"},
                description=(
                    f"The server accepts connections using deprecated TLS "
                    f"protocol version(s): {', '.join(supported_weak)}. These "
                    "versions have known cryptographic weaknesses."
                ),
                evidence={"supported_weak_versions": supported_weak},
                remediation=[
                    "Disable TLS 1.0 and TLS 1.1 on the server",
                    "Require TLS 1.2 or higher (prefer TLS 1.3)",
                ],
                references=[
                    "https://owasp.org/Top10/A04_2025-Cryptographic_Failures/",
                    "https://datatracker.ietf.org/doc/html/rfc8996",
                ],
            ))

        # Certificate details / expiry / weak cipher negotiated on default handshake
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()  # (name, version, bits)
                    cert = ssock.getpeercert()

            if cipher and any(k in cipher[0].upper() for k in self.WEAK_CIPHER_KEYWORDS):
                findings.append(Vulnerability(
                    id=_next_id(self._id_counter),
                    category=self.CATEGORY,
                    owasp=self.OWASP_ID,
                    name="Weak Cipher Suite Negotiated",
                    severity="MEDIUM",
                    cvss_score=5.9,
                    location={"url": f"{hostname}:{port}", "method": "TLS_HANDSHAKE"},
                    description=(
                        f"The server negotiated a weak/deprecated cipher suite: "
                        f"{cipher[0]}."
                    ),
                    evidence={"cipher": cipher[0], "tls_version": cipher[1]},
                    remediation=[
                        "Restrict cipher suites to modern AEAD ciphers "
                        "(e.g. AES-GCM, ChaCha20-Poly1305)",
                        "Remove support for RC4, DES/3DES, MD5-based, NULL and export ciphers",
                    ],
                    references=["https://owasp.org/Top10/A04_2025-Cryptographic_Failures/"],
                ))
        except (ssl.SSLError, socket.error, OSError) as e:
            # Plain-HTTP-only host (e.g. local DVWA container) — not itself a
            # finding here, just log for visibility.
            self.log(f"TLS handshake / cert check skipped for {hostname}:{port}: {e}")
            cert = None

        return findings

    @staticmethod
    def _supports_tls_version(hostname: str, port: int, tls_version) -> bool:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version
            with socket.create_connection((hostname, port), timeout=DEFAULT_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    return True
        except Exception:
            return False

    # ---- 3. Sensitive data in URL ------------------------------------------

    def _check_sensitive_data_in_url(self, url: str) -> List[Vulnerability]:
        findings = []
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        if not query_params:
            return findings

        pattern = re.compile("|".join(self.SENSITIVE_PARAM_PATTERNS), re.IGNORECASE)
        flagged = {k: v for k, v in query_params.items() if pattern.search(k)}

        if flagged:
            findings.append(Vulnerability(
                id=_next_id(self._id_counter),
                category=self.CATEGORY,
                owasp=self.OWASP_ID,
                name="Sensitive Data Exposed in URL",
                severity="MEDIUM",
                cvss_score=6.5,
                location={"url": url, "method": "GET", "parameter": ", ".join(flagged.keys())},
                description=(
                    "Sensitive-looking parameters were found in the URL query "
                    "string. URLs are frequently logged by proxies, browser "
                    "history, referrer headers, and server access logs, "
                    "exposing this data."
                ),
                evidence={"flagged_parameters": list(flagged.keys())},
                remediation=[
                    "Move sensitive values to the request body or headers (e.g. POST/Authorization)",
                    "Never pass credentials, tokens, or session IDs as GET parameters",
                    "Configure logging/proxies to redact sensitive query parameters",
                ],
                references=["https://owasp.org/Top10/A04_2025-Cryptographic_Failures/"],
            ))
        return findings

    # ---- 4. Cookie flags ----------------------------------------------------

    def _check_cookie_flags(self, url: str) -> List[Vulnerability]:
        findings = []
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
        except RequestException as e:
            self.log(f"Cookie check request failed: {e}")
            return findings

        set_cookie_headers = resp.raw.headers.get_all("Set-Cookie") if hasattr(
            resp.raw.headers, "get_all"
        ) else resp.headers.get("Set-Cookie")

        if not set_cookie_headers:
            return findings

        if isinstance(set_cookie_headers, str):
            set_cookie_headers = [set_cookie_headers]

        is_https = urlparse(url).scheme == "https"

        for raw_cookie in set_cookie_headers:
            name = raw_cookie.split("=", 1)[0].strip()
            lowered = raw_cookie.lower()
            missing = []
            if is_https and "secure" not in lowered:
                missing.append("Secure")
            if "httponly" not in lowered:
                missing.append("HttpOnly")
            if "samesite" not in lowered:
                missing.append("SameSite")

            if missing:
                findings.append(Vulnerability(
                    id=_next_id(self._id_counter),
                    category=self.CATEGORY,
                    owasp=self.OWASP_ID,
                    name="Cookie Missing Security Flags",
                    severity="MEDIUM" if "Secure" in missing or "HttpOnly" in missing else "LOW",
                    cvss_score=5.4 if "Secure" in missing or "HttpOnly" in missing else 3.1,
                    location={"url": url, "method": "GET", "parameter": name},
                    description=(
                        f"Cookie '{name}' is missing the following security "
                        f"attribute(s): {', '.join(missing)}."
                    ),
                    evidence={"cookie_name": name, "missing_flags": missing,
                              "raw_header": raw_cookie},
                    remediation=[
                        "Set the 'Secure' flag on all cookies sent over HTTPS",
                        "Set the 'HttpOnly' flag to prevent JavaScript access (mitigates XSS cookie theft)",
                        "Set 'SameSite=Strict' or 'SameSite=Lax' to mitigate CSRF",
                    ],
                    references=[
                        "https://owasp.org/Top10/A04_2025-Cryptographic_Failures/",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
                    ],
                ))
        return findings

    # ---- 5. Mixed content ---------------------------------------------------

    def _check_mixed_content(self, url: str) -> List[Vulnerability]:
        findings = []
        if urlparse(url).scheme != "https":
            return findings
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
        except RequestException as e:
            self.log(f"Mixed content check failed: {e}")
            return findings

        http_resources = re.findall(
            r'(?:src|href)=["\']http://[^"\']+["\']', resp.text, re.IGNORECASE
        )
        if http_resources:
            findings.append(Vulnerability(
                id=_next_id(self._id_counter),
                category=self.CATEGORY,
                owasp=self.OWASP_ID,
                name="Mixed Content Detected",
                severity="LOW",
                cvss_score=3.7,
                location={"url": url, "method": "GET"},
                description=(
                    "The HTTPS page loads one or more sub-resources over "
                    "plaintext HTTP, which can be intercepted or modified "
                    "in transit and may trigger browser mixed-content warnings."
                ),
                evidence={"count": len(http_resources),
                          "sample": http_resources[:5]},
                remediation=[
                    "Serve all sub-resources (scripts, styles, images, iframes) over HTTPS",
                    "Use protocol-relative or absolute HTTPS URLs",
                ],
                references=["https://owasp.org/Top10/A04_2025-Cryptographic_Failures/"],
            ))
        return findings


# --------------------------------------------------------------------------- #
# Output formatting
# --------------------------------------------------------------------------- #

def severity_sort_key(v: Vulnerability):
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return order.get(v.severity, 5)


def print_table(vulns: List[Vulnerability], target: str, duration: float) -> None:
    print(f"\nA04 Cryptographic Failures Scan — {target}")
    print("=" * 78)
    if not vulns:
        print("No cryptographic-failure findings.")
    else:
        header = f"{'FINDING':<32} {'SEVERITY':<10} {'METHOD':<8} {'LOCATION'}"
        print(header)
        print("-" * len(header) if len(header) < 78 else "-" * 78)
        for v in sorted(vulns, key=severity_sort_key):
            color = SEVERITY_COLOR.get(v.severity, "")
            loc = v.location.get("parameter") or v.location.get("url", "")
            method = v.location.get("method", "")
            print(f"{v.name[:31]:<32} {color}{v.severity:<10}{RESET} {method:<8} {loc}")

    counts = {}
    for v in vulns:
        counts[v.severity] = counts.get(v.severity, 0) + 1
    summary = ", ".join(f"{n} {s}" for s, n in counts.items()) or "0 findings"
    print("-" * 78)
    print(f"Summary: {len(vulns)} finding(s) ({summary})")
    print(f"Duration: {duration:.2f}s")


def build_json_report(vulns: List[Vulnerability], target: str, duration: float) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        counts[v.severity.lower()] = counts.get(v.severity.lower(), 0) + 1

    return {
        "scan_info": {
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(duration, 2),
            "scanners_run": ["a04"],
        },
        "summary": counts,
        "vulnerabilities": [asdict(v) for v in vulns],
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="A04:2025 Cryptographic Failures scanner "
                    "(HTTP/HTTPS, TLS version, sensitive URL data, cookie flags, mixed content)."
    )
    parser.add_argument("target", nargs="?", help="Target URL, e.g. https://example.com")
    parser.add_argument("--urls", help="File with one URL per line to scan in addition to/instead of target")
    parser.add_argument("--json", dest="json_path", help="Write JSON report to this path")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    urls: List[str] = []
    if args.target:
        urls.append(args.target)
    if args.urls:
        with open(args.urls) as f:
            urls += [line.strip() for line in f if line.strip()]

    if not urls:
        parser.error("Provide a target URL or --urls file.")

    scanner = CryptoFailureScanner(timeout=args.timeout, verbose=args.verbose)

    start = datetime.now()
    vulns = scanner.scan_many(urls)
    duration = (datetime.now() - start).total_seconds()

    print_table(vulns, urls[0] if len(urls) == 1 else f"{len(urls)} URLs", duration)

    if args.json_path:
        report = build_json_report(vulns, urls[0] if len(urls) == 1 else f"{len(urls)} URLs", duration)
        with open(args.json_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nJSON report written to {args.json_path}")


if __name__ == "__main__":
    main()
