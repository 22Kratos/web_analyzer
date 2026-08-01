"""
crawler/spider.py
------------------
Crawler Orchestrator

The single entry point that drives the whole crawl. Spider is the only
module in the crawler package that performs HTTP requests, manages the
queue, or talks to core.robots - HTMLParser and JSParser never see the
network, and neither of them builds Endpoint objects.

Conforms to the shared interface contract:
    Spider(start_url).crawl() -> Target

Pipeline (per architecture spec):

    Seed URL
        v
    Queue            (BFS ordering, dedup, depth)
        v
    HttpClient       (the only way Spider talks to the network)
        v
    HTMLParser       (parsing only - returns ParsedPage, never touches HTTP)
        v
    JSParser         (parsing only - returns Endpoint list, never touches HTTP)
        v
    Endpoint objects (built/enriched here, and only here)
        v
    Target(base_url, endpoints)

Spider MUST NOT:
    - Parse HTML directly            -> delegated entirely to HTMLParser
    - Inspect/parse JavaScript        -> delegated entirely to JSParser
    - Detect vulnerabilities           -> out of scope, belongs to the scanner layer

Spider IS responsible for:
    - Crawling (the BFS loop)
    - Every HTTP request, exclusively through core.http_client.HttpClient
      (httpx, requests, aiohttp, etc. are never imported here)
    - Queue management, including marking URLs visited
    - Calling HTMLParser and JSParser
    - Building the canonical Endpoint objects (core.models.Endpoint) -
      this is the only module that constructs them
    - Populating response metadata (status_code, content_type, headers)
      once a request actually completes
    - robots.txt policy checks, exclusively through core.robots - no
      other crawler module imports core.robots
    - Returning the final Target(base_url, endpoints)

Visited-marking contract (see queue.py):
    Queue.dequeue() does NOT mark a URL visited. Spider calls
    queue.mark_visited(url) itself, and only after that URL's crawl has
    actually succeeded - a failed fetch is simply skipped and left
    out of the visited set rather than silently blacklisted forever
    behind a phantom "visited" flag.

_fetch
"""

from __future__ import annotations

from email import parser
import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qsl

# NOTE: HttpClient's exact method signature is assumed per the task spec
# ("Assume HttpClient already exists"). This module calls it as:
#     await self._http_client.get(url, headers=..., timeout=...)
# returning an object exposing .status_code (int), .headers (mapping),
# and .text (str). Adjust the call sites below if the real signature
# differs - the rest of the pipeline is unaffected either way.
from ..core.http_client import HttpClient

# NOTE: core.robots's exact interface is assumed per the task spec
# ("Spider should be the only crawler module communicating with
# robots.py"). This module uses it as:
#     checker = RobotsChecker(http_client, user_agent)
#     allowed = await checker.is_allowed(url)
# Adjust construction/usage below if the real interface differs.
from ..core.robots import RobotsChecker

# from ..core.models import Endpoint, RequestData, ResponseData, FormInfo, Param, Target
# from ..core.models import RequestData, ResponseData, FormInfo, Target
from ..core.models import (
    Endpoint,
    RequestData,
    ResponseData,
    FormInfo,
    Target,
)
from .html_parser import HTMLParser, ParsedPage
from .js_parser import JSParser
from .queue import CrawlQueue
from .js_parser import JSParser, JSDiscovery

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DEFAULT_USER_AGENT = "OWASP-Crawler/1.0 (+security-scan)"
DEFAULT_TIMEOUT = 10          # seconds, per request
DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_PAGES = 500       # hard safety cap regardless of depth/dedupe


class Spider:
    """Orchestrates CrawlQueue, HTMLParser, and JSParser to crawl a site."""

    def __init__(
        self,
        start_url: str,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_pages: int = DEFAULT_MAX_PAGES,
        timeout: int = DEFAULT_TIMEOUT,
        same_domain_only: bool = True,
        respect_robots_txt: bool = False,
        user_agent: str = DEFAULT_USER_AGENT,
        include_static_assets: bool = False,
    ):
        """
        Args:
            start_url: Seed URL to begin crawling from.
            max_depth: Maximum BFS depth to follow links/endpoints to.
            max_pages: Hard cap on number of pages fetched, as a safety
                net independent of depth (protects against pathological
                sites with huge fan-out at a shallow depth).
            timeout: Per-request timeout in seconds, passed to HttpClient.
            same_domain_only: If True, only follow links whose host
                matches the seed URL's host (subdomains are treated as
                different hosts).
            respect_robots_txt: If True, consult robots.txt (via
                core.robots.RobotsChecker) before fetching each URL and
                skip disallowed paths. Off by default since this is a
                security-testing crawler, but the hook is fully wired up
                for callers who want it.
            user_agent: User-Agent header sent with every request, and
                the identity used for robots.txt evaluation.
            include_static_assets: Passed through to JSParser - if True,
                keep JS-discovered endpoints that look like static files.
        """
        self.start_url = start_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.same_domain_only = same_domain_only
        self.respect_robots_txt = respect_robots_txt
        self.user_agent = user_agent
        self.include_static_assets = include_static_assets

        self._start_domain = urlparse(start_url).netloc.lower()

        # Orchestrated collaborators - Spider is the only module allowed
        # to hold references to all three of these at once.
        self._queue = CrawlQueue(max_depth=max_depth)
        self._html_parser = HTMLParser(base_url=start_url)
        self._http_client = HttpClient(timeout=timeout)
        self._robots_checker = RobotsChecker(self._http_client, user_agent)

        self._default_headers: Dict[str, str] = {"User-Agent": user_agent}

        # Best-effort session cookie jar: updated from Set-Cookie response
        # headers and replayed as request.cookies on subsequent requests.
        # HttpClient may already manage cookies internally, in which case
        # this simply mirrors what it's doing for Endpoint reporting
        # purposes.
        self._cookie_jar: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def crawl(self) -> Target:
        """Run the crawl to completion and return the aggregated Target."""
        endpoints: List[Endpoint] = []
        pages_fetched = 0

        self._queue.enqueue(self.start_url, depth=0)

        try:
            while not self._queue.empty():
                if pages_fetched >= self.max_pages:
                    logger.info("max_pages limit (%d) reached, stopping crawl", self.max_pages)
                    break

                item = self._queue.dequeue()
                if item is None:
                    break

                if not self._in_scope(item.url):
                    continue

                if self.respect_robots_txt and not await self._robots_checker.is_allowed(item.url):
                    logger.debug("Skipping %s - disallowed by robots.txt", item.url)
                    continue

                page_endpoints = await self._process_url(item.url, item.depth)
                if page_endpoints is None:
                    # Fetch failed - do not mark_visited, so this URL is
                    # simply left out of the crawl rather than silently
                    # blacklisted; it can be retried by a future run.
                    continue

                endpoints.extend(page_endpoints)
                self._queue.mark_visited(item.url)
                pages_fetched += 1
        finally:
            await self._close_http_client()

        return Target(base_url=self.start_url, endpoints=endpoints)

    # ------------------------------------------------------------------
    # Per-URL pipeline
    # ------------------------------------------------------------------

    async def _process_url(self, url: str, depth: int) -> Optional[List[Endpoint]]:
        """
        Fetch one URL and run it through the full discovery pipeline,
        building every Endpoint that this page/response yields.

        Returns:
            The list of Endpoint objects discovered from this URL, or
            None if the fetch itself failed.
        """
        response = await self._fetch(url)
        if response is None:
            return None

        content_type = self._extract_content_type(response)
        self._update_cookie_jar(response)

        response_data = ResponseData(
            status_code=response.status_code,
            content_type=content_type,
            headers=dict(response.headers),
            body=response.text,
        )

        # Non-HTML responses (JSON APIs, binaries, etc.) still count as a
        # discovered endpoint, but there is nothing further to parse -
        # HTMLParser/JSParser are only ever invoked on HTML bodies.
        if "html" not in content_type.lower():
            return [self._build_page_endpoint(url, response_data)]

        page = self._html_parser.extract(response.text)

        endpoints: List[Endpoint] = [self._build_page_endpoint(url, response_data, page)]

        endpoints.extend(self._collect_form_endpoints(page.forms, depth))
        self._enqueue_links(page.links, depth)

        js_endpoints = await self._collect_js_endpoints(url, page, depth)
        endpoints.extend(js_endpoints)

        return endpoints

    
    def _build_js_endpoint(self, discovery: JSDiscovery) -> Endpoint:
        return Endpoint(
            url=discovery.url,
            method=discovery.method,
            request=RequestData(
                params=discovery.params,
                headers=dict(self._default_headers),
                cookies=dict(self._cookie_jar),
        ),
        response=ResponseData(),
        forms=[],
        links=[],
        is_form=False,
    )


    def _build_page_endpoint(
        self,
        url: str,
        response_data: ResponseData,
        page: Optional[ParsedPage] = None,
    ) -> Endpoint:
        """Build the canonical Endpoint representing the fetched page itself."""
        return Endpoint(
            url=url,
            method="GET",
            request=RequestData(
                params=self._parse_query_params(url),
                form_data={},     #None,
                headers=dict(self._default_headers),
                cookies=dict(self._cookie_jar),
            ),
            response=response_data,
            forms=page.forms if page else [],
            links=page.links if page else [],
            is_form=False,
        )

    def _collect_form_endpoints(self, forms: List[FormInfo], depth: int) -> List[Endpoint]:
        """
        Turn every parsed <form> into a canonical Endpoint and enqueue its
        action URL at depth + 1 (architecture rule 8).
        """
        endpoints: List[Endpoint] = []
        for form in forms:
            form_data = {f.name: (f.value if f.value is not None else "") for f in form.fields}

            endpoints.append(
                Endpoint(
                    url=form.action,
                    method=form.method,
                    request=RequestData(
                        params=self._parse_query_params(form.action),
                        form_data=form_data,
                        headers=dict(self._default_headers),
                        cookies=dict(self._cookie_jar),
                    ),
                    response=ResponseData(),
                    forms=[form],
                    links=[],
                    is_form=True,
                )
            )

            if self._in_scope(form.action):
                self._queue.enqueue(form.action, depth=depth + 1)

        return endpoints

    def _enqueue_links(self, links: List[str], depth: int) -> None:
        """Add every newly discovered link to the frontier at depth + 1."""
        for link in links:
            if self._in_scope(link):
                self._queue.enqueue(link, depth=depth + 1)

    async def _collect_js_endpoints(
        self, page_url: str, page: ParsedPage, depth: int
    ) -> List[Endpoint]:
        """
        Fetch every external script, hand it plus all inline scripts to
        JSParser, and enqueue every Endpoint it discovers at depth + 1.

        JSParser only ever parses text it's handed - downloading the
        external .js files is Spider's job, per the JSParser MUST NOT
        rules.
        """
        js_blobs: Dict[str, str] = {}

        for script_url in page.scripts:
            js_text = await self._fetch_text(script_url)
            if js_text is not None:
                js_blobs[script_url] = js_text

        for index, inline_body in enumerate(page.inline_scripts):
            # Inline scripts have no URL of their own; key them uniquely
            # so extract_from_files doesn't collapse multiple inline
            # blocks on the same page into one.
            js_blobs[f"{page_url}#inline-{index}"] = inline_body

        if not js_blobs:
            return []

        parser = JSParser(
            base_url=page_url,
            include_static_assets=self.include_static_assets,
        )

        discoveries = parser.extract_from_files(js_blobs)

        endpoints: List[Endpoint] = []

        for discovery in discoveries:
            endpoint = self._build_js_endpoint(discovery)
            endpoints.append(endpoint)

            if self._in_scope(endpoint.url):
                self._queue.enqueue(endpoint.url, depth=depth + 1)

        return endpoints

#       parser = JSParser(base_url=page_url, include_static_assets=self.include_static_assets)
#       js_endpoints = parser.extract_from_files(js_blobs)
#
#        for endpoint in js_endpoints:
#            if self._in_scope(endpoint.url):
#                self._queue.enqueue(endpoint.url, depth=depth + 1)
#        return js_endpoints

    # ------------------------------------------------------------------
    # HTTP helpers - the only place in the crawler package that performs
    # network I/O, and always through HttpClient.
    # ------------------------------------------------------------------

    async def _fetch(self, url: str):
        """GET a page via HttpClient, handling exceptions safely.

        Returns None instead of raising on failure, so a single bad URL
        never aborts the whole crawl.
        """
        try:
            return await self._http_client.get(
                url, headers=self._default_headers, timeout=self.timeout, follow_redirects=True,
            )
        except Exception as exc:  # noqa: BLE001 - HttpClient's exception
            # type isn't specified by the architecture spec; caught
            # broadly here so any transport-level failure degrades to a
            # skipped URL rather than crashing the crawl.
            logger.warning("Failed to fetch %s: %s", url, exc)
            return None

    async def _fetch_text(self, url: str) -> Optional[str]:
        """GET an external resource (e.g. a .js file) and return its body text."""
        response = await self._fetch(url)
        if response is None:
            return None
        if getattr(response, "status_code", 200) >= 400:
            return None
        return response.text

    async def _close_http_client(self) -> None:
        """Best-effort cleanup of HttpClient's underlying connections."""
        close = getattr(self._http_client, "aclose", None) or getattr(self._http_client, "close", None)
        if close is None:
            return
        try:
            result = close()
            if hasattr(result, "__await__"):
                await result
        except Exception as exc:  # noqa: BLE001 - cleanup must never raise
            logger.debug("Error closing HttpClient: %s", exc)

    # ------------------------------------------------------------------
    # Response bookkeeping helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_content_type(response) -> str:
        """Pull the Content-Type header off a response in a case-insensitive way."""
        headers = dict(response.headers)
        for key, value in headers.items():
            if key.lower() == "content-type":
                return value
        return ""

    def _update_cookie_jar(self, response) -> None:
        """
        Best-effort parse of Set-Cookie response header(s) into the
        session cookie jar, so subsequent Endpoint request.cookies
        reflect what would actually be sent on the next request.
        """
        headers = dict(response.headers)
        set_cookie = headers.get("Set-Cookie") or headers.get("set-cookie")
        if not set_cookie:
            return

        for cookie_str in set_cookie.split(","):
            # Each cookie is "name=value; Path=...; HttpOnly; ..." - we
            # only care about the leading name=value pair.
            pair = cookie_str.split(";", 1)[0].strip()
            if "=" not in pair:
                continue
            name, _, value = pair.partition("=")
            name = name.strip()
            if name:
                self._cookie_jar[name] = value.strip()

    @staticmethod
    def _parse_query_params(url: str) -> dict[str, str]:
        """Extract query-string parameters from a URL as canonical Param objects."""
        parsed = urlparse(url)
        return dict(parse_qsl(parsed.query))
#        return [
 #           Param(name=name, value=value, source="url")
  #          for name, value in parse_qsl(parsed.query)]


    # ------------------------------------------------------------------
    # Scope helper
    # ------------------------------------------------------------------

    def _in_scope(self, url: str) -> bool:
        """Return True if ``url`` should be crawled at all."""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if self.same_domain_only and parsed.netloc.lower() != self._start_domain:
            return False
        return True