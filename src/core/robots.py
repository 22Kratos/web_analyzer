from __future__ import annotations

from typing import Dict
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser


class RobotsChecker:
    """
    Fetches, caches and evaluates robots.txt rules for a website.

    Spider is the only crawler component that communicates with this class.
    """

    def __init__(self, http_client, user_agent: str):
        self._http_client = http_client
        self._user_agent = user_agent
        self._cache: Dict[str, RobotFileParser] = {}

    async def is_allowed(self, url: str) -> bool:
        """
        Returns True if the supplied URL may be crawled according to
        robots.txt. If robots.txt cannot be retrieved or parsed, the URL
        is treated as allowed.
        """
        parsed = urlparse(url)

        base = f"{parsed.scheme}://{parsed.netloc}"

        parser = self._cache.get(base)

        if parser is None:
            parser = await self._load_parser(base)
            self._cache[base] = parser

        return parser.can_fetch(self._user_agent, url)

    async def _load_parser(self, base_url: str) -> RobotFileParser:
        """
        Downloads robots.txt and builds a RobotFileParser.

        Any download/parsing failure results in an empty parser,
        which effectively allows crawling.
        """
        parser = RobotFileParser()

        robots_url = urljoin(base_url, "/robots.txt")

        try:
            response = await self._http_client.get(robots_url)

            if response is None or response.status_code >= 400:
                parser.parse([])
                return parser

            parser.parse(response.text.splitlines())

        except Exception:
            parser.parse([])

        return parser