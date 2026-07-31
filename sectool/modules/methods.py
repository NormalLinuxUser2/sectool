from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

from ..core.context import Context
from ..core.errors import SectoolError
from ..core.findings import Finding, Severity
from ..core.httpclient import DEFAULT_USER_AGENT, build_session, normalize_url, parse_headers

NAME = "methods"
HELP = "Enumerate allowed HTTP methods and flag dangerous ones"

PROBE_METHODS = (
    "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "PROPFIND",
)

# method -> (severity, title, recommendation, reference)
DANGEROUS = {
    "PUT": (Severity.HIGH, "HTTP PUT method enabled",
            "PUT may allow uploading or overwriting files on the server.",
            "https://cwe.mitre.org/data/definitions/650.html"),
    "DELETE": (Severity.HIGH, "HTTP DELETE method enabled",
               "DELETE may allow removing resources on the server.",
               "https://cwe.mitre.org/data/definitions/650.html"),
    "TRACE": (Severity.MEDIUM, "HTTP TRACE method enabled (Cross-Site Tracing)",
              "TRACE echoes the request and can enable Cross-Site Tracing (XST).",
              "https://owasp.org/www-community/attacks/Cross_Site_Tracing"),
    "CONNECT": (Severity.MEDIUM, "HTTP CONNECT method enabled",
                "CONNECT can let the server be abused as a proxy.",
                None),
    "PATCH": (Severity.LOW, "HTTP PATCH method enabled",
              "PATCH allows partial modification of resources; confirm it is intended.",
              None),
    "PROPFIND": (Severity.MEDIUM, "WebDAV (PROPFIND) enabled",
                 "WebDAV methods expand the attack surface and may expose files.",
                 None),
}

SUCCESSISH = set(range(200, 300)) | {207}


@dataclass
class MethodProbe:
    method: str
    status: int = 0
    error: Optional[str] = None


@dataclass
class MethodReport:
    url: str
    probes: List[MethodProbe] = field(default_factory=list)
    advertised: List[str] = field(default_factory=list)

    def enabled(self) -> List[str]:
        return [p.method for p in self.probes if p.status in SUCCESSISH]


def _parse_allow(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [m.strip().upper() for m in value.split(",") if m.strip()]


def audit_methods(session, url: str, timeout: float,
                  methods=PROBE_METHODS) -> MethodReport:
    report = MethodReport(url=url)
    for method in methods:
        try:
            response = session.request(method, url, timeout=timeout, allow_redirects=False)
        except requests.RequestException as exc:
            report.probes.append(MethodProbe(method=method, error=str(exc)))
            continue
        status = int(getattr(response, "status_code", 0))
        report.probes.append(MethodProbe(method=method, status=status))
        if method == "OPTIONS":
            allow = None
            headers = getattr(response, "headers", {}) or {}
            for key, val in dict(headers).items():
                if key.lower() == "allow":
                    allow = val
                    break
            report.advertised = _parse_allow(allow)
    return report


def methods_to_findings(report: MethodReport) -> List[Finding]:
    findings: List[Finding] = []
    enabled = set(report.enabled())

    if report.advertised:
        findings.append(Finding(
            Severity.INFO, "Server advertises HTTP methods",
            "OPTIONS Allow header lists: " + ", ".join(report.advertised) + ".",
            location=report.url, category="methods",
            metadata={"allow": report.advertised},
        ))

    # A method is treated as active if it responded success-ish, or is advertised
    # in Allow while not clearly rejected.
    candidates = enabled | {m for m in report.advertised if m in DANGEROUS}
    for method in sorted(candidates):
        if method not in DANGEROUS:
            continue
        severity, title, recommendation, reference = DANGEROUS[method]
        probe = next((p for p in report.probes if p.method == method), None)
        status = probe.status if probe else 0
        how = f"active probe returned {status}" if method in enabled else "advertised via Allow header"
        findings.append(Finding(
            severity, title,
            f"{method} appears enabled ({how}).",
            location=report.url,
            recommendation=recommendation + " Disable it if not required.",
            category="methods", reference=reference,
            metadata={"method": method, "status": status},
        ))

    if not findings:
        findings.append(Finding(
            Severity.INFO, "No dangerous HTTP methods detected",
            "Only standard, safe methods appear to be enabled.",
            location=report.url, category="methods",
        ))
    return findings


def _print_summary(reporter, report: MethodReport) -> None:
    reporter.message(f"Method probe: {report.url}")
    for probe in report.probes:
        state = probe.error if probe.error else str(probe.status)
        reporter.message(f"  {probe.method:<9} {state}")


def configure_parser(parser) -> None:
    parser.add_argument("target", help="URL or host to test (e.g. https://example.com)")
    parser.add_argument(
        "--header", action="append", dest="headers", default=[], metavar="H",
        help="Extra request header 'Name: value' (repeatable)",
    )
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="Override the User-Agent")
    parser.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout in seconds")
    parser.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates")


def run(args, context: Context) -> List[Finding]:
    target = normalize_url(args.target, default_scheme="https")

    try:
        extra_headers = parse_headers(args.headers)
    except ValueError as exc:
        raise SectoolError(str(exc))

    session = build_session(
        user_agent=args.user_agent,
        headers=extra_headers,
        verify=not args.insecure,
    )

    context.logger.info("probing HTTP methods on %s", target)
    report = audit_methods(session, target, args.timeout)
    if all(p.error for p in report.probes):
        raise SectoolError(f"request to {target} failed: {report.probes[0].error}")

    _print_summary(context.reporter, report)
    findings = methods_to_findings(report)
    context.reporter.report(findings, title=f"HTTP methods: {target}")
    return findings
