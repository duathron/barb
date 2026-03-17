"""URL decomposition using urllib.parse."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from phishing_analyzer.models import ParsedURL

_MAX_URL_LEN = 2048


def parse_url(url: str) -> ParsedURL:
    """Decompose a URL into its components.

    Raises ValueError if the URL exceeds the length cap or is unparseable.
    """
    url = url.strip().rstrip("\x00")
    if len(url) > _MAX_URL_LEN:
        raise ValueError(f"URL exceeds maximum length of {_MAX_URL_LEN} characters")

    # Add scheme if missing for proper parsing
    parse_target = url if "://" in url else f"http://{url}"
    parsed = urlparse(parse_target)

    host = parsed.hostname or ""
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    is_punycode = host.startswith("xn--") or ".xn--" in host

    return ParsedURL(
        original=url,
        scheme=parsed.scheme,
        userinfo=parsed.username,
        host=host,
        port=parsed.port,
        path=parsed.path or "/",
        query=parsed.query or None,
        fragment=parsed.fragment or None,
        is_ip=is_ip,
        is_punycode=is_punycode,
    )
