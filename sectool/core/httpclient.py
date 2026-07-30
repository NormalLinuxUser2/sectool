from __future__ import annotations

from typing import Dict, Iterable, Optional
from urllib.parse import urlparse, urlunparse

import requests

DEFAULT_USER_AGENT = "sectool/1.1 (+https://github.com/NormalLinuxUser2/sectool)"


def normalize_url(target: str, default_scheme: str = "https") -> str:
    value = target.strip()
    if "://" not in value:
        value = f"{default_scheme}://{value}"
    parsed = urlparse(value)
    if not parsed.netloc:
        raise ValueError(f"could not parse a host from '{target}'")
    return urlunparse(parsed)


def parse_headers(values: Optional[Iterable[str]]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for item in values or ():
        if ":" not in item:
            raise ValueError(f"invalid header (expected 'Name: value'): {item}")
        name, _, value = item.partition(":")
        headers[name.strip()] = value.strip()
    return headers


def build_session(
    user_agent: str = DEFAULT_USER_AGENT,
    headers: Optional[Dict[str, str]] = None,
    verify: bool = True,
) -> requests.Session:
    session = requests.Session()
    session.headers["User-Agent"] = user_agent
    if headers:
        session.headers.update(headers)
    session.verify = verify
    return session
