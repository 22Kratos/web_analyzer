import re

from web_analyzer.scanners.base import Scanner, Finding, Severity
from web_analyzer.core.models import Target, Endpoint
from web_analyzer.core.http_client import HttpClient
from web_analyzer.core import rate_limiter

# no idea what im doing btw
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
]

SERVER_BANNER_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]

RISKY_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT"]

ERROR_SIGNATURES = [
    "Traceback (most recent call last)",
    "Warning: include(",
    "Fatal error:",
    "at System.",
    "Whitelabel Error Page",
    "django.core.exceptions",
]

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/config.php.bak",
    "/backup.zip",
    "/wp-config.php.bak",
    "/.DS_Store",
    "/server-status",
]

DIRECTORY_LISTING_SIGNATURE = "Index of /"


class MisconfigScanner(Scanner):
    name = "Security Misconfiguration Scanner"

    def __init__(self, http_client: HttpClient):
        self.http = http_client

    async def scan(self, target: Target):
        findings = []
        for endpoint in target.endpoints:
            findings += await self.scan_endpoint(endpoint)

        findings += await self.check_sensitive_paths(target.base_url)
        return findings

    async def scan_endpoint(self, endpoint: Endpoint):
        findings = []
        response = await self.send_request(endpoint)
        if not response:
            return findings

        result = self.check_security_headers(endpoint, response)
        if result:
            findings.append(result)

        result = self.check_server_banner(endpoint, response)
        if result:
            findings.append(result)

        result = self.check_error_messages(endpoint, response)
        if result:
            findings.append(result)

        result = self.check_directory_listing(endpoint, response)
        if result:
            findings.append(result)

        result = await self.check_risky_methods(endpoint)
        if result:
            findings.append(result)

        return findings

    def check_security_headers(self, endpoint, response):
        missing = [h for h in SECURITY_HEADERS if h not in response.headers]
        if not missing:
            return None

        return Finding(
            title="Missing Security Headers",
            severity=Severity.MEDIUM,
            endpoint=endpoint.url,
            parameter=None,
            payload=None,
            evidence=f"Response is missing: {', '.join(missing)}",
            description="Important security headers are not set, which weakens protection against clickjacking, MIME sniffing, and similar attacks.",
            remediation="Add the missing headers at the server or framework level (e.g. helmet.js, django-security, Spring Security headers).",
        )

    def check_server_banner(self, endpoint, response):
        found = {}
        for header in SERVER_BANNER_HEADERS:
            value = response.headers.get(header)
            if value:
                found[header] = value

        if not found:
            return None

        details = ", ".join(f"{k}: {v}" for k, v in found.items())
        return Finding(
            title="Server Version Disclosure",
            severity=Severity.LOW,
            endpoint=endpoint.url,
            parameter=None,
            payload=None,
            evidence=details,
            description="The server is revealing software/version info in response headers, which helps attackers pick known exploits.",
            remediation="Disable or strip these headers in the web server / framework config.",
        )

    def check_error_messages(self, endpoint, response):
        for signature in ERROR_SIGNATURES:
            if signature in response.text:
                return Finding(
                    title="Verbose Error Message",
                    severity=Severity.MEDIUM,
                    endpoint=endpoint.url,
                    parameter=None,
                    payload=None,
                    evidence=f"Response contains: {signature}",
                    description="The app leaks stack traces or debug error pages, exposing internal details to users.",
                    remediation="Turn off debug mode in production and use generic error pages.",
                )
        return None

    def check_directory_listing(self, endpoint, response):
        if DIRECTORY_LISTING_SIGNATURE in response.text:
            return Finding(
                title="Directory Listing Enabled",
                severity=Severity.MEDIUM,
                endpoint=endpoint.url,
                parameter=None,
                payload=None,
                evidence="Response body looks like an auto-generated directory index page.",
                description="Directory listing is enabled, letting anyone browse files on this path.",
                remediation="Disable directory listing in the web server config (e.g. Options -Indexes in Apache).",
            )
        return None

    async def check_risky_methods(self, endpoint):
        allowed = await self.get_allowed_methods(endpoint)
        if not allowed:
            return None

        risky_found = [m for m in RISKY_METHODS if m in allowed]
        if not risky_found:
            return None

        return Finding(
            title="Unnecessary HTTP Methods Enabled",
            severity=Severity.LOW,
            endpoint=endpoint.url,
            parameter=None,
            payload=", ".join(risky_found),
            evidence=f"OPTIONS request reports allowed methods: {', '.join(allowed)}",
            description="The server accepts HTTP methods that are rarely needed and can be abused (e.g. TRACE for XST, PUT for file upload).",
            remediation="Restrict allowed methods to only what the app actually needs, usually GET, POST, HEAD.",
        )

    async def check_sensitive_paths(self, base_url):
        findings = []
        for path in SENSITIVE_PATHS:
            url = base_url.rstrip("/") + path
            response = await self.send_raw_request(url)
            if response and response.status_code == 200:
                findings.append(
                    Finding(
                        title="Exposed Sensitive File",
                        severity=Severity.HIGH,
                        endpoint=url,
                        parameter=None,
                        payload=None,
                        evidence=f"GET {path} returned status 200",
                        description="A sensitive file or config path is publicly accessible.",
                        remediation="Remove the file from the public directory or block access to it at the server level.",
                    )
                )
        return findings

    async def get_allowed_methods(self, endpoint):
        await rate_limiter.acquire()
        try:
            response = await self.http.request(
                method="OPTIONS",
                url=endpoint.url,
                headers=endpoint.headers,
            )
        except Exception:
            return None

        if not response:
            return None

        allow_header = response.headers.get("Allow", "")
        return [m.strip().upper() for m in allow_header.split(",") if m.strip()]

    async def send_request(self, endpoint):
        await rate_limiter.acquire()
        try:
            return await self.http.request(
                method=endpoint.method,
                url=endpoint.url,
                params=endpoint.params,
                data=endpoint.form_data,
                headers=endpoint.headers,
            )
        except Exception:
            return None

    async def send_raw_request(self, url):
        await rate_limiter.acquire()
        try:
            return await self.http.request(method="GET", url=url)
        except Exception:
            return None


# i suck at this, save me