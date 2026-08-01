"""
crawler/js_parser.py
---------------------
Crawler & Discovery Engine

Extracts API endpoints referenced inside JavaScript (both external .js files
and inline <script> blocks) so they can be added to the crawl queue and
handed off to scanners.

Conforms to the shared interface contract:
    Deliverable -> List[Endpoint]

Detection strategies (regex-based, no JS execution required):
    1. fetch("url", { method: "..." })
    2. axios.get/post/put/delete/patch("url", ...)
    3. axios({ url: "...", method: "..." })
    4. jQuery $.ajax({ url: "...", type: "..." }) / $.get / $.post
    5. XMLHttpRequest.open("METHOD", "url")
    6. WebSocket("ws://...") / new WebSocket("wss://...")
    7. Bare string literals that look like API paths or full URLs
       (used as a fallback net to catch endpoints built dynamically,
       e.g. const BASE = "/api/v2/orders")

All matches are normalized against the page's base URL, deduplicated,
and filtered to drop obvious static-asset noise (images, fonts, css...).

Endpoint is the single canonical model, owned by core.models - it is
imported here, never redefined. JSParser only ever sees raw JS source
text, never an actual HTTP response, so it can only honestly populate
url / method / request.params on the Endpoint it builds; every
response.* field and request.headers / request.cookies are left at
their model defaults for Spider to fill in once it actually performs
the request (see architecture rule 6 - Spider builds the canonical,
fully-populated Endpoint after crawling; this module only supplies the
part it can know from static analysis).

JSParser MUST NOT:
    - Download JavaScript      -> spider.py fetches, this module only parses
    - Execute JavaScript        -> purely regex/static analysis
    - Perform HTTP requests     -> no network I/O anywhere in this module
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse, parse_qsl

from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Extensions we don't care about when they show up as bare string literals -
# they're almost always static assets, not API endpoints.
STATIC_ASSET_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".scss", ".less",
    ".woff", ".woff2", ".ttf", ".eot",
    ".map", ".mp4", ".mp3", ".webm",
)

# Signals that a bare string literal is likely an API endpoint rather than
# some unrelated path/string in the code.
API_HINT_RE = re.compile(
    r"(/api/|/v[0-9]+/|/graphql|/rest/|\.json(\?|$)|/rpc/)", re.IGNORECASE
)

HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")

# A generic "quoted string" fragment reused across patterns below.
# NOTE: deliberately does not require the closing quote to match the
# opening one (no backreference) - backreferences break once other named
# groups appear earlier in the combined pattern, since \1 then points at
# the wrong group. In practice JS string literals essentially never
# contain an unescaped different quote char, so this trade-off is safe.
_STR = r"""["'`]((?:[^"'`])*?)["'`]"""


@dataclass
class JSDiscovery:
    """
    Represents an endpoint discovered inside JavaScript.

    This contains only discovery information.
    Spider is responsible for constructing the canonical Endpoint.
    """

    url: str
    method: str
    params: Dict[str, str]

class JSParser:
    """Extracts candidate API endpoints from a blob of JavaScript source."""

    def __init__(self, base_url: str, include_static_assets: bool = False):
        """
        Args:
            base_url: The URL the JS was retrieved from (or the page it was
                inlined in). Used to resolve relative paths.
            include_static_assets: If True, keep bare-string matches that
                point at static files (images, css, fonts...). Off by
                default to cut down noise.
        """
        self.base_url = base_url
        self.include_static_assets = include_static_assets

        self._patterns = self._build_patterns()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self, js_content: str) -> List[JSDiscovery]:
        """Parse js_content and return deduplicated JSDiscovery list.

        Deduplication here is strictly local to this single blob of JS -
        global, cross-document deduplication is CrawlQueue's job alone.
        """
        found: Dict[tuple, JSDiscovery] = {}
        seen_urls: set = set()

        # Pass 1: structured call sites (fetch/axios/$.ajax/xhr/websocket) -
        # these carry a reliable method, so they take priority.
        for method, url in self._find_structured_calls(js_content):
            discovery = self._to_discovery(url, method)
            if discovery is None:
                continue
            found[(discovery.method, discovery.url)] = discovery
            seen_urls.add(discovery.url)

        # Pass 2: bare string-literal fallback - skip anything already
        # captured above so we don't add a redundant "GET" duplicate for a
        # URL that was already seen with e.g. POST.
        for method, url in self._find_fallback_strings(js_content):
            discovery = self._to_discovery(url, method)
            if discovery is None or discovery.url in seen_urls:
                continue
            key = (discovery.method, discovery.url)
            if key not in found:
                found[key] = discovery
                seen_urls.add(discovery.url)

        return list(found.values())

    def extract_from_files(self, js_blobs: Dict[str, str]) -> List[JSDiscovery]:
        """
        Convenience helper for spider.py: parse multiple JS sources at once.

        Args:
            js_blobs: mapping of {source_url: js_content} - e.g. every
                external .js file plus each inline <script> block found by
                html_parser.py on a page.
        """
        all_results: Dict[tuple, JSDiscovery] = {}
        for source_url, content in js_blobs.items():
            parser = JSParser(base_url=source_url or self.base_url,
                               include_static_assets=self.include_static_assets)
            for ep in parser.extract(content):
                key = (ep.method, ep.url)
                all_results[key] = ep
        return list(all_results.values())

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _build_patterns(self):
        methods_alt = "|".join(HTTP_METHODS)

        return [
            # fetch("url", { method: "POST" })  /  fetch("url")
            re.compile(
                rf"""fetch\s*\(\s*{_STR}\s*(?:,\s*\{{[^}}]*?method\s*:\s*['"`](?P<method>{methods_alt})['"`])?""",
                re.IGNORECASE | re.DOTALL,
            ),
            # axios.get("url") / axios.post("url", data) / axios.delete(...)
            re.compile(
                rf"""axios\s*\.\s*(?P<amethod>get|post|put|delete|patch|head|options)\s*\(\s*{_STR}""",
                re.IGNORECASE,
            ),
            # axios({ url: "...", method: "POST" })
            re.compile(
                rf"""axios\s*\(\s*\{{[^}}]*?url\s*:\s*{_STR}(?:[^}}]*?method\s*:\s*['"`](?P<method2>{methods_alt})['"`])?""",
                re.IGNORECASE | re.DOTALL,
            ),
            # $.ajax({ url: "...", type: "POST" })
            re.compile(
                rf"""\$\.ajax\s*\(\s*\{{[^}}]*?url\s*:\s*{_STR}(?:[^}}]*?type\s*:\s*['"`](?P<method3>{methods_alt})['"`])?""",
                re.IGNORECASE | re.DOTALL,
            ),
            # $.get("url") / $.post("url", ...)
            re.compile(
                rf"""\$\.(?P<jqmethod>get|post)\s*\(\s*{_STR}""",
                re.IGNORECASE,
            ),
            # xhr.open("METHOD", "url")
            re.compile(
                rf"""\.open\s*\(\s*['"`](?P<xmethod>{methods_alt})['"`]\s*,\s*{_STR}""",
                re.IGNORECASE,
            ),
            # new WebSocket("ws://...") / WebSocket("wss://...")
            re.compile(
                rf"""(?:new\s+)?WebSocket\s*\(\s*{_STR}""",
                re.IGNORECASE,
            ),
        ]

    def _find_structured_calls(self, js_content: str):
        """Yield (method, url) tuples from fetch/axios/$.ajax/xhr/websocket call sites."""
        method_group_names = (
            "method", "method2", "method3", "amethod", "jqmethod", "xmethod",
        )
        for pattern in self._patterns:
            for m in pattern.finditer(js_content):
                gd = m.groupdict()
                # The url/path lives in one of the *unnamed* capture groups
                # (the quoted-string pattern); named groups only hold verbs.
                named_values = set(gd.values())
                url = next(
                    (g for g in m.groups()
                     if g and g not in named_values
                     and self._looks_like_url_or_path(g)),
                    None,
                )
                if not url:
                    continue
                method = next((gd[name] for name in method_group_names if gd.get(name)), "GET")
                yield method.upper(), url

    def _find_fallback_strings(self, js_content: str):
        """Yield (method, url) tuples from bare string literals that look
        like API endpoints, e.g. const BASE_URL = "/api/v2/orders"."""
        for m in re.finditer(_STR, js_content):
            candidate = m.group(1)
            if not self._looks_like_url_or_path(candidate):
                continue
            if API_HINT_RE.search(candidate) or candidate.lower().startswith(("http://", "https://")):
                if not self.include_static_assets and candidate.lower().endswith(STATIC_ASSET_EXT):
                    continue
                yield "GET", candidate

    @staticmethod
    def _looks_like_url_or_path(value: str) -> bool:
        if not value or len(value) > 2000:
            return False
        if value.startswith(("http://", "https://", "ws://", "wss://", "//")):
            return True
        if value.startswith("/") and not value.startswith("//"):
            return True
        return False

    def _to_discovery(self, url: str, method: str) -> Optional[JSDiscovery]:
        """
        Build a canonical JSDiscovery from a discovered (method, url) pair.

        Only url / method / request.params are populated here - this
        module has no HTTP response to draw the rest from. Spider is
        responsible for overwriting/enriching response.* and
        request.headers / request.cookies once it actually performs the
        request (architecture rule 6).
        """
        if not self.include_static_assets and url.lower().split("?")[0].endswith(STATIC_ASSET_EXT):
            return None

        resolved = urljoin(self.base_url, url)
        parsed = urlparse(resolved)

        if parsed.scheme not in ("http", "https", "ws", "wss"):
            return None

        params = dict(parse_qsl(parsed.query))

        return JSDiscovery(
        url=resolved,
        method=method.upper() if method.upper() in HTTP_METHODS else "GET",
        params=params,
    )


    # endpoint = self._to_endpoint(url, method)