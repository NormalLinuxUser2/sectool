from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import requests

from ..core.context import Context
from ..core.errors import SectoolError
from ..core.findings import Finding, Severity
from ..core.httpclient import DEFAULT_USER_AGENT, build_session, normalize_url, parse_headers

NAME = "probe"
HELP = "Probe a URL: redirect chain, title, server and technology fingerprint"

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_GENERATOR_RE = re.compile(
    r"<meta[^>]+name=['\"]generator['\"][^>]+content=['\"]([^'\"]+)", re.IGNORECASE
)
MAX_TITLE = 120
MAX_REDIRECTS = 10
REDIRECT_CODES = (301, 302, 303, 307, 308)


@dataclass
class Hop:
    url: str
    status: int
    location: Optional[str] = None


@dataclass
class ProbeInfo:
    url: str
    final_url: str
    status: int
    chain: List[Hop] = field(default_factory=list)
    title: Optional[str] = None
    server: Optional[str] = None
    powered_by: Optional[str] = None
    content_type: Optional[str] = None
    size: int = 0
    elapsed_ms: Optional[float] = None
    technologies: List[str] = field(default_factory=list)
    error: Optional[str] = None


# (label, header name, substring or None) header-based fingerprints
_HEADER_SIGNATURES = [
    ("Nginx", "Server", "nginx"),
    ("Apache", "Server", "apache"),
    ("Microsoft IIS", "Server", "iis"),
    ("LiteSpeed", "Server", "litespeed"),
    ("Caddy", "Server", "caddy"),
    ("Cloudflare", "Server", "cloudflare"),
    ("Cloudflare", "CF-RAY", None),
    ("Amazon CloudFront", "X-Amz-Cf-Id", None),
    ("Vercel", "X-Vercel-Id", None),
    ("Fastly", "X-Served-By", "fastly"),
    ("PHP", "X-Powered-By", "php"),
    ("ASP.NET", "X-Powered-By", "asp.net"),
    ("ASP.NET", "X-AspNet-Version", None),
    ("Express", "X-Powered-By", "express"),
    ("Next.js", "X-Powered-By", "next.js"),
    ("Drupal", "X-Generator", "drupal"),
    ("Drupal", "X-Drupal-Cache", None),
    ("Varnish", "Via", "varnish"),
]

# (label, Set-Cookie name fragment)
_COOKIE_SIGNATURES = [
    ("PHP", "phpsessid"),
    ("Java", "jsessionid"),
    ("ASP.NET", "asp.net_sessionid"),
    ("Laravel", "laravel_session"),
    ("Django", "csrftoken"),
    ("Django", "sessionid"),
    ("Ruby on Rails", "_rails"),
    ("Flask", "session="),
]

# (label, body substring, case-insensitive)
_BODY_SIGNATURES = [
    ("WordPress", "wp-content"),
    ("WordPress", "wp-includes"),
    ("Drupal", "drupal.settings"),
    ("Joomla", "/media/jui/"),
    ("Next.js", "__next_data__"),
    ("Nuxt.js", "__nuxt__"),
    ("React", "data-reactroot"),
    ("Angular", "ng-version"),
    ("Vue.js", "data-v-app"),
    ("Shopify", "cdn.shopify.com"),
    ("Gatsby", "___gatsby"),
]


def _header(headers, name: str) -> Optional[str]:
    if headers is None:
        return None
    getter = getattr(headers, "get", None)
    if callable(getter):
        value = headers.get(name)
        if value is not None:
            return value
    for key, value in dict(headers).items():
        if key.lower() == name.lower():
            return value
    return None


def _cookies(headers) -> List[str]:
    getter = getattr(headers, "get_all", None)
    if callable(getter):
        values = getter("Set-Cookie")
        if values:
            return list(values)
    single = _header(headers, "Set-Cookie")
    return [single] if single else []


def _body(response) -> str:
    text = getattr(response, "text", None)
    if text is not None:
        return text
    content = getattr(response, "content", b"") or b""
    if isinstance(content, bytes):
        return content.decode("utf-8", "replace")
    return str(content)


def _title(body: str) -> Optional[str]:
    match = _TITLE_RE.search(body or "")
    if not match:
        return None
    title = " ".join(match.group(1).split())
    return title[:MAX_TITLE] or None


def fingerprint(headers, body: str) -> List[str]:
    found: List[str] = []
    for label, name, needle in _HEADER_SIGNATURES:
        value = _header(headers, name)
        if value is None:
            continue
        if needle is None or needle in value.lower():
            found.append(label)
    cookie_blob = " ".join(_cookies(headers)).lower()
    for label, needle in _COOKIE_SIGNATURES:
        if needle in cookie_blob:
            found.append(label)
    lowered = (body or "").lower()
    for label, needle in _BODY_SIGNATURES:
        if needle in lowered:
            found.append(label)
    generator = _GENERATOR_RE.search(body or "")
    if generator:
        found.append(generator.group(1).strip()[:60])
    seen = set()
    unique = []
    for label in found:
        key = label.lower()
        if key not in seen:
            seen.add(key)
            unique.append(label)
    return unique


def probe_url(session, url: str, timeout: float, max_redirects: int = MAX_REDIRECTS) -> ProbeInfo:
    info = ProbeInfo(url=url, final_url=url, status=0)
    current = url
    response = None
    for _ in range(max_redirects + 1):
        try:
            response = session.request("GET", current, timeout=timeout, allow_redirects=False)
        except requests.RequestException as exc:
            info.error = str(exc)
            return info
        status = int(getattr(response, "status_code", 0))
        location = _header(getattr(response, "headers", {}), "Location")
        info.chain.append(Hop(url=current, status=status, location=location))
        if status in REDIRECT_CODES and location:
            current = urljoin(current, location)
            continue
        break

    info.final_url = current
    info.status = int(getattr(response, "status_code", 0)) if response is not None else 0
    headers = getattr(response, "headers", {}) if response is not None else {}
    body = _body(response) if response is not None else ""
    info.server = _header(headers, "Server")
    info.powered_by = _header(headers, "X-Powered-By")
    ctype = _header(headers, "Content-Type")
    info.content_type = ctype.split(";")[0].strip().lower() if ctype else None
    info.size = len(getattr(response, "content", b"") or b"") if response is not None else 0
    elapsed = getattr(response, "elapsed", None) if response is not None else None
    if elapsed is not None:
        try:
            info.elapsed_ms = round(elapsed.total_seconds() * 1000, 1)
        except AttributeError:
            info.elapsed_ms = None
    if not info.content_type or "html" in info.content_type or "xml" in info.content_type:
        info.title = _title(body)
    info.technologies = fingerprint(headers, body)
    return info


def probe_to_findings(info: ProbeInfo) -> List[Finding]:
    if info.error:
        raise SectoolError(f"request to {info.url} failed: {info.error}")

    findings: List[Finding] = []
    final_scheme = urlparse(info.final_url).scheme.lower()
    start_scheme = urlparse(info.url).scheme.lower()

    if final_scheme == "http":
        findings.append(Finding(
            Severity.MEDIUM, "Service served over cleartext HTTP",
            f"The final response for {info.final_url} is plain HTTP.",
            location=info.final_url,
            recommendation="Serve the site over HTTPS and redirect HTTP to HTTPS.",
            category="transport",
        ))
    elif start_scheme == "http" and final_scheme == "https":
        findings.append(Finding(
            Severity.INFO, "HTTP redirects to HTTPS",
            "The target upgrades cleartext HTTP requests to HTTPS.",
            location=info.url, category="transport",
        ))

    if info.title and info.title.lower().startswith("index of"):
        findings.append(Finding(
            Severity.MEDIUM, "Directory listing enabled",
            f"The server returned an autoindex page (title: {info.title!r}).",
            location=info.final_url,
            recommendation="Disable automatic directory listing on the web server.",
            category="content", evidence=info.title,
        ))

    for name, value in (("Server", info.server), ("X-Powered-By", info.powered_by)):
        if value and re.search(r"\d+\.\d+", value):
            findings.append(Finding(
                Severity.INFO, f"Version disclosure via {name}",
                f"The '{name}' header reveals '{value}'.",
                location=info.final_url,
                recommendation=f"Suppress or genericize the {name} header.",
                category="disclosure", evidence=value[:120],
            ))

    if info.status >= 500:
        findings.append(Finding(
            Severity.LOW, f"Server error status {info.status}",
            f"{info.final_url} responded with {info.status}.",
            location=info.final_url,
            recommendation="Investigate the server-side error.",
            category="availability",
        ))

    if info.technologies:
        findings.append(Finding(
            Severity.INFO, "Technology fingerprint",
            "Detected: " + ", ".join(info.technologies) + ".",
            location=info.final_url,
            recommendation="Keep detected components patched; avoid leaking versions.",
            category="fingerprint",
            metadata={"technologies": info.technologies},
        ))

    return findings


def _print_summary(reporter, info: ProbeInfo) -> None:
    if len(info.chain) > 1:
        reporter.message("Redirect chain:")
        for hop in info.chain:
            arrow = f" -> {hop.location}" if hop.location else ""
            reporter.message(f"  [{hop.status}] {hop.url}{arrow}")
    timing = f"  {info.elapsed_ms:.0f} ms" if info.elapsed_ms is not None else ""
    reporter.message(f"{info.status} {info.final_url}  ({info.size} bytes){timing}")
    if info.title:
        reporter.message(f"  title: {info.title}")
    if info.server:
        reporter.message(f"  server: {info.server}")
    if info.technologies:
        reporter.message(f"  tech: {', '.join(info.technologies)}")


def configure_parser(parser) -> None:
    parser.add_argument("target", nargs="?", help="URL or host to probe (e.g. https://example.com)")
    parser.add_argument("--list", metavar="FILE", help="File of additional URLs to probe (one per line)")
    parser.add_argument(
        "--header", action="append", dest="headers", default=[], metavar="H",
        help="Extra request header 'Name: value' (repeatable)",
    )
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="Override the User-Agent")
    parser.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout in seconds")
    parser.add_argument("--max-redirects", type=int, default=MAX_REDIRECTS, help="Maximum redirects to follow")
    parser.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates")


def _collect_targets(args) -> List[str]:
    targets: List[str] = []
    if args.target:
        targets.append(args.target)
    if args.list:
        try:
            with open(args.list, "r", encoding="utf-8", errors="replace") as handle:
                for raw in handle:
                    line = raw.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except OSError as exc:
            raise SectoolError(f"could not read target list '{args.list}': {exc}")
    if not targets:
        raise SectoolError("provide a target URL or --list FILE")
    return list(dict.fromkeys(targets))


def run(args, context: Context) -> List[Finding]:
    try:
        extra_headers = parse_headers(args.headers)
    except ValueError as exc:
        raise SectoolError(str(exc))

    session = build_session(
        user_agent=args.user_agent,
        headers=extra_headers,
        verify=not args.insecure,
    )

    targets = _collect_targets(args)
    findings: List[Finding] = []
    for raw_target in targets:
        target = normalize_url(raw_target, default_scheme="https")
        context.logger.info("probing %s", target)
        info = probe_url(session, target, args.timeout, args.max_redirects)
        if info.error:
            context.logger.warning("probe of %s failed: %s", target, info.error)
            findings.append(Finding(
                Severity.INFO, "Probe failed",
                f"Could not reach {target}: {info.error}",
                location=target, category="availability",
            ))
            continue
        _print_summary(context.reporter, info)
        findings.extend(probe_to_findings(info))

    if not findings:
        findings.append(Finding(
            Severity.INFO, "No noteworthy observations",
            "The probe completed without flagging anything.",
            category="summary",
        ))
    context.reporter.report(findings, title="HTTP probe")
    return findings
