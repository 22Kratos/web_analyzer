from urllib.parse import urlparse, urlunparse


def normalize_url(url: str) -> str:
    if not url:
        return ""

    parsed = urlparse(url.strip())

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    path = parsed.path or "/"

    if path != "/" and path.endswith("/"):
        path = path[:-1]

    return urlunparse(
        (
            scheme,
            netloc,
            path,
            "",
            parsed.query,
            "",
        )
    )