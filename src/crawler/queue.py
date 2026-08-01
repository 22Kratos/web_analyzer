"""
crawler/queue.py
-----------------
Crawl Frontier / URL Queue

Manages the breadth-first traversal order of the crawler: which URLs are
still waiting to be visited, which are currently in flight, which have
already been fully crawled, and how deep in the crawl tree each one sits.

Conforms to the shared interface contract:
    Spider hands URLs in, Queue hands normalized, deduplicated URLs back
    out in BFS order, one crawl-depth level at a time. Spider alone
    decides when a URL counts as "visited" (see mark_visited below).

Responsibilities (and only these):
    - BFS ordering via collections.deque
    - URL deduplication (global - this is the ONLY module in the crawler
      package that owns cross-page deduplication; HTMLParser/JSParser may
      only dedupe *within* a single document)
    - Depth tracking / max-depth enforcement
    - Basic queue bookkeeping (size, empty check, seen check)

Explicitly NOT this module's job:
    - Performing HTTP requests            -> spider.py (via core.http_client)
    - Parsing HTML/JS                     -> html_parser.py / js_parser.py
    - URL normalization logic             -> core.url_parser.normalize_url
    - Vulnerability scanning               -> scanner layer, out of scope
    - Knowing anything about scanners

Visited-marking contract:
    dequeue() does NOT mark a URL as visited. It only removes the URL from
    the pending frontier and moves it into an "in-progress" bucket so it
    can't be re-enqueued while Spider is still fetching/parsing it. Spider
    is responsible for calling mark_visited(url) once the crawl of that
    URL has actually succeeded. This lets Spider re-enqueue a URL that
    failed to fetch (e.g. transient network error) instead of the queue
    silently and permanently blacklisting it after a single dequeue.

Thread-safety note:
    A single re-entrant lock guards every mutation/read of internal state.
    The crawler is asynchronous (single event loop) rather than
    multi-threaded, but every public method remains lock-protected so this
    class stays safe to share across worker tasks or threads later without
    touching its internals.
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass
from typing import Deque, Optional, Set

from ..core.url_parser import normalize_url


@dataclass(frozen=True)
class QueueItem:
    """A single unit of crawl work: a normalized URL and its BFS depth."""

    url: str
    depth: int


class CrawlQueue:
    """BFS frontier with normalization-aware deduplication and depth limits."""

    def __init__(self, max_depth: Optional[int] = None):
        """
        Args:
            max_depth: Maximum crawl depth to allow. ``enqueue`` silently
                rejects any URL deeper than this. ``None`` means unlimited.
        """
        self.max_depth = max_depth

        self._pending: Deque[QueueItem] = deque()
        self._queued_urls: Set[str] = set()
        self._in_progress_urls: Set[str] = set()
        self._visited_urls: Set[str] = set()

        # Re-entrant so a method can safely call another locked method
        # on the same object without deadlocking itself.
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enqueue(self, url: str, depth: int = 0) -> bool:
        """
        Add a URL to the frontier if it hasn't been seen and is within
        the configured max depth.

        Args:
            url: Raw URL as discovered by the parser layer.
            depth: BFS depth of this URL relative to the seed URL. Callers
                (Spider) are expected to pass ``current_depth + 1`` for
                every newly discovered URL.

        Returns:
            True if the URL was accepted and queued, False if it was
            rejected (already seen, or exceeds max_depth).
        """
        with self._lock:
            if self.max_depth is not None and depth > self.max_depth:
                return False

            normalized = normalize_url(url)
            if not normalized:
                return False
            if (
                normalized in self._queued_urls
                or normalized in self._in_progress_urls
                or normalized in self._visited_urls
            ):
                return False

            self._queued_urls.add(normalized)
            self._pending.append(QueueItem(url=normalized, depth=depth))
            return True

    def dequeue(self) -> Optional[QueueItem]:
        """
        Pop the next item in BFS order and move it into the in-progress
        bucket. Does NOT mark it visited - call mark_visited(url) once the
        crawl of this URL has actually succeeded.

        Returns:
            The next QueueItem, or None if the queue is empty.
        """
        with self._lock:
            if not self._pending:
                return None

            item = self._pending.popleft()
            self._queued_urls.discard(item.url)
            self._in_progress_urls.add(item.url)
            return item

    def mark_visited(self, url: str) -> None:
        """
        Record a URL as fully, successfully crawled. Called by Spider
        after a successful fetch + parse, never automatically by dequeue.

        Safe to call even if the URL was never dequeued through this
        queue instance (e.g. marking the seed URL) - it will simply be
        normalized and added to the visited set.
        """
        with self._lock:
            normalized = normalize_url(url)
            if not normalized:
                return
            self._in_progress_urls.discard(normalized)
            self._visited_urls.add(normalized)

    def empty(self) -> bool:
        """Return True if there is no pending work left."""
        with self._lock:
            return len(self._pending) == 0

    def already_seen(self, url: str) -> bool:
        """
        Return True if ``url`` (after normalization) has already been
        queued, is currently in progress, or has been visited - i.e.
        enqueueing it again would be a duplicate.
        """
        with self._lock:
            normalized = normalize_url(url)
            if not normalized:
                return False
            return (
                normalized in self._queued_urls
                or normalized in self._in_progress_urls
                or normalized in self._visited_urls
            )

    def size(self) -> int:
        """Return the number of items currently pending (not yet dequeued)."""
        with self._lock:
            return len(self._pending)

    def visited_count(self) -> int:
        """Return how many unique normalized URLs have been marked visited."""
        with self._lock:
            return len(self._visited_urls)

    def reset(self) -> None:
        """Clear all queue state. Mainly useful for tests / reusing an instance."""
        with self._lock:
            self._pending.clear()
            self._queued_urls.clear()
            self._in_progress_urls.clear()
            self._visited_urls.clear()