from __future__ import annotations

import re
from typing import Dict, List, Optional

import requests

from ..core.context import Context
from ..core.errors import SectoolError
from ..core.findings import Finding, Severity
from ..core.httpclient import DEFAULT_USER_AGENT, build_session, normalize_url, parse_headers

NAME = "headers"
HELP = "Audit a URL's HTTP response security headers"

OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"


def _get(headers: Dict[str, str], name: str) -> Optional[str]:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _all(headers, name: str) -> List[str]:
    getter = getattr(headers, "get_all", None)
    if callable(getter):
        values = getter(name)
        if values:
            return list(values)
    single = _get(dict(headers), name)
    return [single] if single is not None else []


def check_hsts(headers: Dict[str, str], is_https: bool) -> List[Finding]:
    value = _get(headers, "Strict-Transport-Security")
    if not is_https:
        return []
    if value is None:
        return [Finding(
            Severity.MEDIUM, "Missing Strict-Transport-Security header",
            "HSTS is not set, so browsers may connect over plaintext HTTP.",
            recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            category="transport", reference=OWASP_HEADERS,
        )]
    findings: List[Finding] = []
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    if not match or int(match.group(1)) < 15552000:
        findings.append(Finding(
            Severity.LOW, "Weak HSTS max-age",
            f"HSTS max-age is low or missing ('{value}').",
            recommendation="Use a max-age of at least 15552000 (180 days).",
            category="transport", reference=OWASP_HEADERS,
        ))
    if "includesubdomains" not in value.lower():
        findings.append(Finding(
            Severity.INFO, "HSTS without includeSubDomains",
            "HSTS does not cover subdomains.",
            recommendation="Add includeSubDomains once all subdomains support HTTPS.",
            category="transport", reference=OWASP_HEADERS,
        ))
    return findings


def check_csp(headers: Dict[str, str]) -> List[Finding]:
    value = _get(headers, "Content-Security-Policy")
    if value is None:
        return [Finding(
            Severity.MEDIUM, "Missing Content-Security-Policy header",
            "No CSP is set, removing a key defense against XSS and data injection.",
            recommendation="Define a restrictive Content-Security-Policy for the app.",
            category="content", reference=OWASP_HEADERS,
        )]
    findings: List[Finding] = []
    lowered = value.lower()
    if "unsafe-inline" in lowered:
        findings.append(Finding(
            Severity.LOW, "CSP allows 'unsafe-inline'",
            "The CSP permits inline scripts/styles, weakening XSS protection.",
            recommendation="Remove 'unsafe-inline'; use nonces or hashes instead.",
            category="content", reference=OWASP_HEADERS, evidence=value[:200],
        ))
    if "unsafe-eval" in lowered:
        findings.append(Finding(
            Severity.LOW, "CSP allows 'unsafe-eval'",
            "The CSP permits eval-like constructs.",
            recommendation="Remove 'unsafe-eval' from the policy.",
            category="content", reference=OWASP_HEADERS, evidence=value[:200],
        ))
    if "default-src" not in lowered and "script-src" not in lowered:
        findings.append(Finding(
            Severity.LOW, "CSP lacks default-src/script-src",
            "The CSP does not restrict script sources.",
            recommendation="Set a restrictive default-src and script-src.",
            category="content", reference=OWASP_HEADERS, evidence=value[:200],
        ))
    return findings


def check_frame_options(headers: Dict[str, str]) -> List[Finding]:
    xfo = _get(headers, "X-Frame-Options")
    csp = _get(headers, "Content-Security-Policy") or ""
    if xfo is None and "frame-ancestors" not in csp.lower():
        return [Finding(
            Severity.MEDIUM, "Missing clickjacking protection",
            "Neither X-Frame-Options nor CSP frame-ancestors is set.",
            recommendation="Add 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
            category="content", reference=OWASP_HEADERS,
        )]
    return []


def check_content_type_options(headers: Dict[str, str]) -> List[Finding]:
    value = _get(headers, "X-Content-Type-Options")
    if value is None or value.strip().lower() != "nosniff":
        return [Finding(
            Severity.LOW, "Missing X-Content-Type-Options: nosniff",
            "Browsers may MIME-sniff responses, enabling some content-type attacks.",
            recommendation="Add 'X-Content-Type-Options: nosniff'.",
            category="content", reference=OWASP_HEADERS,
        )]
    return []


def check_referrer_policy(headers: Dict[str, str]) -> List[Finding]:
    if _get(headers, "Referrer-Policy") is None:
        return [Finding(
            Severity.INFO, "Missing Referrer-Policy header",
            "No Referrer-Policy is set; full URLs may leak to third parties.",
            recommendation="Add e.g. 'Referrer-Policy: strict-origin-when-cross-origin'.",
            category="privacy", reference=OWASP_HEADERS,
        )]
    return []


def check_permissions_policy(headers: Dict[str, str]) -> List[Finding]:
    if _get(headers, "Permissions-Policy") is None:
        return [Finding(
            Severity.INFO, "Missing Permissions-Policy header",
            "No Permissions-Policy is set to restrict powerful browser features.",
            recommendation="Add a Permissions-Policy limiting features like geolocation and camera.",
            category="privacy", reference=OWASP_HEADERS,
        )]
    return []


def check_cors(headers: Dict[str, str]) -> List[Finding]:
    origin = _get(headers, "Access-Control-Allow-Origin")
    creds = _get(headers, "Access-Control-Allow-Credentials")
    findings: List[Finding] = []
    if origin == "*" and creds and creds.strip().lower() == "true":
        findings.append(Finding(
            Severity.HIGH, "Insecure CORS: wildcard origin with credentials",
            "Access-Control-Allow-Origin '*' combined with credentials exposes user data.",
            recommendation="Echo a validated, specific origin instead of '*' when using credentials.",
            category="cors", reference=OWASP_HEADERS,
        ))
    elif origin == "*":
        findings.append(Finding(
            Severity.LOW, "Permissive CORS policy",
            "Access-Control-Allow-Origin is '*'.",
            recommendation="Restrict allowed origins to a trusted allowlist where possible.",
            category="cors", reference=OWASP_HEADERS,
        ))
    return findings


def check_cookies(headers) -> List[Finding]:
    findings: List[Finding] = []
    for raw in _all(headers, "Set-Cookie"):
        cookie = raw or ""
        name = cookie.split("=", 1)[0].strip() or "cookie"
        lowered = cookie.lower()
        missing = []
        if "secure" not in lowered:
            missing.append("Secure")
        if "httponly" not in lowered:
            missing.append("HttpOnly")
        if "samesite" not in lowered:
            missing.append("SameSite")
        if missing:
            findings.append(Finding(
                Severity.MEDIUM, f"Cookie '{name}' missing {', '.join(missing)}",
                f"Set-Cookie for '{name}' lacks: {', '.join(missing)}.",
                recommendation="Set Secure, HttpOnly and SameSite on session cookies.",
                category="cookies", reference=OWASP_HEADERS, evidence=cookie[:200],
            ))
    return findings


def check_banner(headers: Dict[str, str]) -> List[Finding]:
    findings: List[Finding] = []
    version = re.compile(r"\d+\.\d+")
    for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        value = _get(headers, name)
        if value and (version.search(value) or name.startswith("X-")):
            findings.append(Finding(
                Severity.INFO, f"Version/technology disclosure via {name}",
                f"The '{name}' header reveals '{value}'.",
                recommendation=f"Suppress or genericize the {name} header to reduce fingerprinting.",
                category="disclosure", reference=OWASP_HEADERS, evidence=value[:120],
            ))
    return findings


def audit_headers(headers, is_https: bool) -> List[Finding]:
    as_dict = dict(headers)
    findings: List[Finding] = []
    findings.extend(check_hsts(as_dict, is_https))
    findings.extend(check_csp(as_dict))
    findings.extend(check_frame_options(as_dict))
    findings.extend(check_content_type_options(as_dict))
    findings.extend(check_referrer_policy(as_dict))
    findings.extend(check_permissions_policy(as_dict))
    findings.extend(check_cors(as_dict))
    findings.extend(check_cookies(headers))
    findings.extend(check_banner(as_dict))
    return findings


def configure_parser(parser) -> None:
    parser.add_argument("target", help="URL or host to audit (e.g. https://example.com)")
    parser.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    parser.add_argument(
        "--header", action="append", dest="headers", default=[], metavar="H",
        help="Extra request header 'Name: value' (repeatable)",
    )
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="Override the User-Agent")
    parser.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout in seconds")
    parser.add_argument("--no-redirect", action="store_true", help="Do not follow redirects")
    parser.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates")


def run(args, context: Context) -> List[Finding]:
    target = normalize_url(args.target, default_scheme="https")
    is_https = target.lower().startswith("https://")

    try:
        extra_headers = parse_headers(args.headers)
    except ValueError as exc:
        raise SectoolError(str(exc))

    session = build_session(
        user_agent=args.user_agent,
        headers=extra_headers,
        verify=not args.insecure,
    )

    context.logger.info("requesting %s", target)
    try:
        response = session.request(
            args.method.upper(),
            target,
            timeout=args.timeout,
            allow_redirects=not args.no_redirect,
        )
    except requests.RequestException as exc:
        raise SectoolError(f"request to {target} failed: {exc}")

    final_url = getattr(response, "url", target) or target
    is_https = str(final_url).lower().startswith("https://")
    context.reporter.message(f"{args.method.upper()} {final_url} -> {getattr(response, 'status_code', '?')}")

    findings = audit_headers(response.headers, is_https)
    if not findings:
        findings.append(Finding(
            Severity.INFO, "No missing security headers detected",
            "All checked security headers are present and reasonable.",
            category="summary",
        ))
    context.reporter.report(findings, title=f"Header audit: {final_url}")
    return findings
