"""
core/constants.py
-----------------

Global constants shared across the Web Analyzer project.

Only include constants that are reusable across multiple modules.

This file should NOT contain:

- Scanner payloads
- Scanner-specific regexes
- Vulnerability signatures
- Business logic

Those belong inside their respective scanner modules.
"""

from __future__ import annotations

# ============================================================================
# HTTP
# ============================================================================

HTTP_METHODS = (
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS",
)

DEFAULT_HEADERS = {
    "User-Agent": "WebAnalyzer/1.0",
    "Accept": "*/*",
}

REQUEST_TIMEOUT = 10  # seconds


# ============================================================================
# URL Normalization
# ============================================================================

DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
}

IGNORED_URL_SCHEMES = (
    "javascript:",
    "mailto:",
    "tel:",
    "data:",
)

# Static resources that should generally not be crawled or treated as endpoints
STATIC_ASSET_EXTENSIONS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".css",
    ".scss",
    ".less",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    ".mp4",
    ".mp3",
    ".wav",
    ".ogg",
    ".webm",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
)


# Pattern used by JSParser to detect likely API endpoints.
# Compile inside JSParser:
#
# API_HINT_RE = re.compile(API_HINT_PATTERN, re.IGNORECASE)
#
API_HINT_PATTERN = (
    r"(/api/|/v[0-9]+/|/graphql|/rest/|\.json(\?|$)|/rpc/)"
)


# ============================================================================
# Spider
# ============================================================================

DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_PAGES = 1000

FOLLOW_REDIRECTS = True
RESPECT_ROBOTS = True


# ============================================================================
# Content Types
# ============================================================================

HTML_CONTENT_TYPES = (
    "text/html",
    "application/xhtml+xml",
)

JAVASCRIPT_CONTENT_TYPES = (
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
)

JSON_CONTENT_TYPES = (
    "application/json",
    "application/ld+json",
)


# ============================================================================
# HTTP Status Codes
# ============================================================================

REDIRECT_STATUS_CODES = (
    301,
    302,
    303,
    307,
    308,
)

SUCCESS_STATUS_CODES = (
    200,
    201,
    202,
    203,
    204,
)

CLIENT_ERROR_STATUS_CODES = (
    400,
    401,
    403,
    404,
    405,
    408,
    429,
)

SERVER_ERROR_STATUS_CODES = (
    500,
    501,
    502,
    503,
    504,
)