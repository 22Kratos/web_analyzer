"""
crawler/html_parser.py
-----------------------
HTML Extraction Layer

Parses a single HTML document and pulls out everything the crawler needs
to keep going and everything a scanner needs to attack: hyperlinks, forms
(with their inputs), external script sources, inline script bodies, and a
handful of secondary attack-surface / navigation hints (iframes, images,
stylesheets, <base href>, meta-refresh redirects, canonical links).

Conforms to the shared interface contract:
    HTMLParser(base_url).extract(html) -> ParsedPage

This module performs no network I/O, no crawling, and no queueing of its
own - it is a pure function of "HTML text in, structured data out".
Discovered URLs are resolved to absolute form (respecting an in-document
<base href> if present) so spider.py can hand them straight to the queue
without further processing.

FormInfo and FormField are the single canonical form models, owned by
core.models - they are imported, never redefined here.

Deduplication performed in this module is strictly document-local (e.g.
the same href appearing twice on one page collapses to one link). Global,
cross-page deduplication belongs exclusively to crawler.queue.CrawlQueue.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urljoin, urlparse
import re

from bs4 import BeautifulSoup
from bs4.element import Tag

from ..core.models import (
    FormInfo,
    FormField,
)

# URI schemes that are never crawlable pages/endpoints and should be
# dropped rather than resolved and queued.
_IGNORED_SCHEMES = ("javascript:", "mailto:", "tel:", "data:")

# Matches the content attribute of <meta http-equiv="refresh" content="...">
# e.g. "5;url=/next", "0; URL='/login'", "3;url=https://example.com/x"
_META_REFRESH_RE = re.compile(
    r"""^\s*(?P<delay>\d+)\s*;\s*url\s*=\s*['"]?(?P<url>[^'"]+)['"]?\s*$""",
    re.IGNORECASE,
)


@dataclass
class MetaRefresh:
    """A <meta http-equiv="refresh"> redirect found on the page."""
    delay: int
    url: str

@dataclass
class ParsedPage:
    """Structured result of parsing one HTML document."""

    links: List[str] = field(default_factory=list)
    forms: List[FormInfo] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)          # external JS URLs
    inline_scripts: List[str] = field(default_factory=list)   # raw JS bodies
    iframes: List[str] = field(default_factory=list)
    images: List[str] = field(default_factory=list)
    stylesheets: List[str] = field(default_factory=list)
    base_href: Optional[str] = None
    canonical_url: Optional[str] = None
    meta_refresh: Optional[MetaRefresh] = None


class HTMLParser:
    """Extracts links, forms, scripts, and navigation hints from an HTML document."""

    def __init__(self, base_url: str):
        """
        Args:
            base_url: The URL the HTML was fetched from. Used to resolve
                every relative href/src/action into an absolute URL,
                unless the document itself declares a <base href> that
                overrides it (per standard browser resolution rules).
        """
        self.base_url = base_url

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self, html: str) -> ParsedPage:
        """Parse ``html`` and return a ParsedPage with every extracted field."""
        soup = BeautifulSoup(html or "", "html.parser")

        # <base href> (if present) supersedes self.base_url as the
        # resolution root for every other relative URL on the page.
        effective_base = self._extract_base_href(soup)

        return ParsedPage(
            links=self._extract_links(soup, effective_base),
            forms=self._extract_forms(soup, effective_base),
            scripts=self._extract_scripts(soup, effective_base),
            inline_scripts=self._extract_inline_scripts(soup),
            iframes=self._extract_iframes(soup, effective_base),
            images=self._extract_images(soup, effective_base),
            stylesheets=self._extract_stylesheets(soup, effective_base),
            base_href=effective_base if effective_base != self.base_url else None,
            canonical_url=self._extract_canonical(soup, effective_base),
            meta_refresh=self._extract_meta_refresh(soup, effective_base),
        )

    # ------------------------------------------------------------------
    # Internals - each extractor is intentionally small and single-purpose
    # ------------------------------------------------------------------

    def _extract_base_href(self, soup: BeautifulSoup) -> str:
        """
        Return the effective base URL for resolving every other relative
        URL on the page: the document's <base href> if present and valid,
        otherwise the URL the page was fetched from.
        """
        base_tag = soup.find("base", href=True)
        if base_tag:
            resolved = self._resolve(base_tag["href"], self.base_url)
            if resolved:
                return resolved
        return self.base_url

    def _extract_links(self, soup: BeautifulSoup, base: str) -> List[str]:
        links: List[str] = []
        for tag in soup.find_all("a", href=True):
            resolved = self._resolve(tag["href"], base)
            if resolved:
                links.append(resolved)
        return self._dedupe(links)

    def _extract_forms(self, soup: BeautifulSoup, base: str) -> List[FormInfo]:
        forms: List[FormInfo] = []
        for tag in soup.find_all("form"):
            action_attr = tag.get("action", "").strip()
            action = self._resolve(action_attr, base) if action_attr else base
            if action is None:
                # action pointed at an ignored scheme (e.g. javascript:) -
                # fall back to the page URL, which is what the browser
                # would actually submit to in that case.
                action = base

            method = tag.get("method", "GET").strip().upper() or "GET"
            enctype = tag.get("enctype", "application/x-www-form-urlencoded").strip()

            forms.append(
                FormInfo(
                    action=action,
                    method=method,
                    enctype=enctype,
                    fields=self._extract_form_fields(tag),
                )
            )
        return forms

    def _extract_form_fields(self, form_tag: Tag) -> List[FormField]:
        fields: List[FormField] = []

        for input_tag in form_tag.find_all(("input", "textarea")):
            name = input_tag.get("name")
            if not name:
                continue
            fields.append(
                FormField(
                    name=name,
                    type=input_tag.get("type", "text").strip().lower() or "text",
                    value=input_tag.get("value"),
                    required=input_tag.has_attr("required"),
                )
            )

        for select_tag in form_tag.find_all("select"):
            fields.extend(self._extract_select_fields(select_tag))

        return fields

    def _extract_select_fields(self, select_tag: Tag) -> List[FormField]:
        """
        Turn a <select> into one or more FormField entries.

        A single-value <select> yields one field carrying the selected (or
        first) option's value. A <select multiple> yields one field per
        selected <option>, all sharing the same name - this mirrors how a
        browser actually serializes a multi-select on form submission
        (the field name repeats once per selected value), so it works
        with the canonical FormField model as-is without needing a
        list-typed value.
        """
        name = select_tag.get("name")
        if not name:
            return []

        is_multiple = select_tag.has_attr("multiple")
        required = select_tag.has_attr("required")
        selected_options = select_tag.find_all("option", selected=True)

        if is_multiple and selected_options:
            return [
                FormField(name=name, type="select", value=option.get("value"),
                           required=required)
                for option in selected_options
            ]

        # Single-value select: use the selected option, or fall back to
        # the first <option> (browsers default to the first option when
        # none is explicitly marked selected).
        chosen = selected_options[0] if selected_options else select_tag.find("option")
        value = chosen.get("value") if chosen else None
        return [FormField(name=name, type="select", value=value, required=required)]

    def _extract_scripts(self, soup: BeautifulSoup, base: str) -> List[str]:
        scripts: List[str] = []
        for tag in soup.find_all("script", src=True):
            resolved = self._resolve(tag["src"], base)
            if resolved:
                scripts.append(resolved)
        return self._dedupe(scripts)

    def _extract_inline_scripts(self, soup: BeautifulSoup) -> List[str]:
        inline: List[str] = []
        for tag in soup.find_all("script", src=False):
            body = tag.string or tag.get_text()
            if body and body.strip():
                inline.append(body)
        return inline

    def _extract_iframes(self, soup: BeautifulSoup, base: str) -> List[str]:
        iframes: List[str] = []
        for tag in soup.find_all("iframe", src=True):
            resolved = self._resolve(tag["src"], base)
            if resolved:
                iframes.append(resolved)
        return self._dedupe(iframes)

    def _extract_images(self, soup: BeautifulSoup, base: str) -> List[str]:
        images: List[str] = []
        for tag in soup.find_all("img", src=True):
            resolved = self._resolve(tag["src"], base)
            if resolved:
                images.append(resolved)
        return self._dedupe(images)

    def _extract_stylesheets(self, soup: BeautifulSoup, base: str) -> List[str]:
        sheets: List[str] = []
        for tag in soup.find_all("link", href=True):
            rel = " ".join(tag.get("rel", [])).lower()
            if "stylesheet" not in rel:
                continue
            resolved = self._resolve(tag["href"], base)
            if resolved:
                sheets.append(resolved)
        return self._dedupe(sheets)

    def _extract_canonical(self, soup: BeautifulSoup, base: str) -> Optional[str]:
        """Return the resolved <link rel="canonical" href="..."> URL, if any."""
        canonical_tag = soup.find("link", rel=lambda r: r and "canonical" in r, href=True)
        if not canonical_tag:
            return None
        return self._resolve(canonical_tag["href"], base)

    def _extract_meta_refresh(self, soup: BeautifulSoup, base: str) -> Optional[MetaRefresh]:
        """
        Return the page's <meta http-equiv="refresh"> redirect, if any.

        Only refresh directives that include a target URL are reported -
        a bare "content='5'" (refresh the same page after 5s, no
        navigation) carries no new endpoint to discover, so it's ignored.
        """
        meta_tag = soup.find(
            "meta",
            attrs={"http-equiv": lambda v: v and v.lower() == "refresh"},
        )
        if not meta_tag or not meta_tag.get("content"):
            return None

        match = _META_REFRESH_RE.match(meta_tag["content"])
        if not match:
            return None

        resolved = self._resolve(match.group("url"), base)
        if not resolved:
            return None

        return MetaRefresh(delay=int(match.group("delay")), url=resolved)

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _resolve(self, raw_url: str, base: str) -> Optional[str]:
        """
        Resolve a raw href/src/action against ``base``, filtering out
        non-crawlable schemes and fragment-only links.

        Args:
            raw_url: The raw attribute value as found in the markup.
            base: The base URL to resolve relative references against -
                normally the page's effective base (self.base_url or an
                in-document <base href>).

        Returns:
            An absolute URL, or None if ``raw_url`` should be ignored.
        """
        if not raw_url:
            return None

        candidate = raw_url.strip()
        if not candidate:
            return None

        lowered = candidate.lower()
        if lowered.startswith(_IGNORED_SCHEMES):
            return None
        if candidate.startswith("#"):
            return None

        resolved = urljoin(base, candidate)
        parsed = urlparse(resolved)

        if parsed.scheme not in ("http", "https"):
            return None

        return resolved

    @staticmethod
    def _dedupe(items: List[str]) -> List[str]:
        """Deduplicate while preserving first-seen order (document-local only)."""
        seen = set()
        result = []
        for item in items:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result