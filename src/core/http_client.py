from __future__ import annotations

import httpx


class HttpClient:
    """
    Thin asynchronous HTTP client wrapper.

    This is the only component responsible for making HTTP requests.
    Spider communicates exclusively with this class.
    """

    def __init__(self, timeout: int = 10):
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
        )

    async def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: int | None = None,
        follow_redirects: bool | None = None,

    ):
        """
        Perform an HTTP GET request.

        Returns the raw httpx.Response object.
        """
        return await self._client.get(
            url,
            headers=headers,
            timeout=timeout,
            follow_redirects=follow_redirects,
        )

    async def post(
        self,
        url: str,
        data: dict | None = None,
        headers: dict[str, str] | None = None,
        timeout: int | None = None,
    ):
        """
        Perform an HTTP POST request.
        """
        return await self._client.post(
            url,
            data=data,
            headers=headers,
            timeout=timeout,
        )

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict | None = None,
        data: dict | None = None,
        json: dict | None = None,
        timeout: int | None = None,
    ):
        """
        Perform an arbitrary HTTP request.
        """
        return await self._client.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            data=data,
            json=json,
            timeout=timeout,
        )

    async def close(self):
        """
        Close the underlying HTTP session.
        """
        await self._client.aclose()

    async def aclose(self):
        """
        Alias for compatibility with Spider.
        """
        await self.close()