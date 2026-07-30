from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

import requests

from ..core.context import Context
from ..core.errors import SectoolError
from ..core.findings import Finding, Severity

NAME = "deps"
HELP = "Check declared dependencies against the OSV vulnerability database"

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

_REQ_PINNED = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9._\-+]*)")
_REQ_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)")
_NPM_VERSION = re.compile(r"(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?)")

_SEVERITY_LABELS = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


@dataclass
class Dependency:
    name: str
    version: Optional[str]
    ecosystem: str
    source: str


def parse_requirements(path: str) -> List[Tuple[str, Optional[str], str]]:
    results: List[Tuple[str, Optional[str], str]] = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            line = line.split(";")[0].split(" #")[0].strip()
            pinned = _REQ_PINNED.match(line)
            if pinned:
                results.append((pinned.group(1), pinned.group(2), "PyPI"))
                continue
            name = _REQ_NAME.match(line)
            if name:
                results.append((name.group(1), None, "PyPI"))
    return results


def parse_package_json(path: str) -> List[Tuple[str, Optional[str], str]]:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        data = json.load(handle)
    results: List[Tuple[str, Optional[str], str]] = []
    sections = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
    for section in sections:
        block = data.get(section) or {}
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            results.append((name, _clean_npm_version(spec), "npm"))
    return results


def _clean_npm_version(spec) -> Optional[str]:
    if not isinstance(spec, str):
        return None
    match = _NPM_VERSION.search(spec)
    return match.group(1) if match else None


def _parser_for(path: str) -> Optional[Callable[[str], List[Tuple[str, Optional[str], str]]]]:
    base = os.path.basename(path).lower()
    if base == "package.json":
        return parse_package_json
    if base.startswith("requirements") and base.endswith(".txt"):
        return parse_requirements
    if base.endswith(".txt"):
        return parse_requirements
    return None


def _resolve_targets(path: str) -> List[Tuple[str, Callable]]:
    targets: List[Tuple[str, Callable]] = []
    if os.path.isdir(path):
        for name, parser in (
            ("requirements.txt", parse_requirements),
            ("package.json", parse_package_json),
        ):
            candidate = os.path.join(path, name)
            if os.path.isfile(candidate):
                targets.append((candidate, parser))
        return targets
    if os.path.isfile(path):
        parser = _parser_for(path)
        if parser is not None:
            targets.append((path, parser))
    return targets


def query_osv(dependencies: List[Dependency], timeout: float) -> Dict[Tuple[str, str, str], List[str]]:
    queries = []
    index = []
    for dependency in dependencies:
        if not dependency.version:
            continue
        queries.append({
            "version": dependency.version,
            "package": {"name": dependency.name, "ecosystem": dependency.ecosystem},
        })
        index.append((dependency.name, dependency.version, dependency.ecosystem))
    if not queries:
        return {}

    response = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=timeout)
    response.raise_for_status()
    results = response.json().get("results", [])

    mapping: Dict[Tuple[str, str, str], List[str]] = {}
    for key, result in zip(index, results):
        vulns = result.get("vulns") or []
        if vulns:
            mapping[key] = [vuln["id"] for vuln in vulns]
    return mapping


def fetch_vuln(vuln_id: str, cache: Dict[str, dict], timeout: float) -> dict:
    if vuln_id in cache:
        return cache[vuln_id]
    response = requests.get(OSV_VULN_URL + vuln_id, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    cache[vuln_id] = data
    return data


def _severity_from_vuln(data: dict) -> Severity:
    database_specific = data.get("database_specific") or {}
    label = str(database_specific.get("severity") or "").upper()
    if label in _SEVERITY_LABELS:
        return _SEVERITY_LABELS[label]
    score = _max_cvss_score(data.get("severity") or [])
    if score is not None:
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score > 0:
            return Severity.LOW
    return Severity.MEDIUM


def _max_cvss_score(entries) -> Optional[float]:
    best: Optional[float] = None
    for entry in entries:
        raw = entry.get("score")
        try:
            value = float(raw)
        except (TypeError, ValueError):
            continue
        if best is None or value > best:
            best = value
    return best


def _fixed_versions(data: dict, name: str) -> List[str]:
    fixes = set()
    for affected in data.get("affected") or []:
        package = affected.get("package") or {}
        if str(package.get("name", "")).lower() != name.lower():
            continue
        for entry in affected.get("ranges") or []:
            for event in entry.get("events") or []:
                if "fixed" in event:
                    fixes.add(event["fixed"])
    return sorted(fixes)


def configure_parser(parser) -> None:
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Manifest file or project directory (default: current directory)",
    )
    parser.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout in seconds")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Parse manifests without querying the OSV database",
    )


def run(args, context: Context) -> List[Finding]:
    targets = _resolve_targets(args.path)
    if not targets:
        raise SectoolError(f"no supported manifest (requirements.txt, package.json) found at: {args.path}")

    dependencies: List[Dependency] = []
    for source, parser in targets:
        context.logger.info("parsing %s", source)
        try:
            for name, version, ecosystem in parser(source):
                dependencies.append(Dependency(name, version, ecosystem, source))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            context.logger.warning("could not parse %s: %s", source, exc)

    context.logger.info("parsed %d dependencies", len(dependencies))

    findings: List[Finding] = []
    for dependency in dependencies:
        if not dependency.version:
            findings.append(Finding(
                Severity.INFO, f"Unpinned dependency: {dependency.name}",
                "Version is not pinned, so it cannot be checked reliably for known vulnerabilities.",
                location=dependency.source,
                recommendation="Pin to an exact version for reproducible, auditable builds.",
                category="hygiene",
            ))

    if args.offline:
        context.reporter.report(findings, title="Dependency check (offline)")
        return findings

    pinned = [dependency for dependency in dependencies if dependency.version]
    try:
        vuln_map = query_osv(pinned, args.timeout)
    except requests.RequestException as exc:
        context.logger.error("OSV query failed: %s", exc)
        findings.append(Finding(
            Severity.INFO, "Vulnerability lookup skipped",
            "Could not reach the OSV database; only manifest hygiene was checked.",
            category="hygiene",
        ))
        context.reporter.report(findings, title="Dependency check")
        return findings

    cache: Dict[str, dict] = {}
    vulnerable = 0
    for dependency in pinned:
        ids = vuln_map.get((dependency.name, dependency.version, dependency.ecosystem))
        if not ids:
            continue
        for vuln_id in ids:
            try:
                data = fetch_vuln(vuln_id, cache, args.timeout)
            except requests.RequestException as exc:
                context.logger.warning("could not fetch %s: %s", vuln_id, exc)
                continue
            severity = _severity_from_vuln(data)
            fixes = _fixed_versions(data, dependency.name)
            summary = data.get("summary") or (data.get("details") or "")[:160]
            if fixes:
                recommendation = f"Upgrade {dependency.name} to {fixes[-1]} or later."
            else:
                recommendation = f"Review advisory {vuln_id} and upgrade {dependency.name}."
            findings.append(Finding(
                severity,
                f"{dependency.name} {dependency.version} is vulnerable ({vuln_id})",
                summary or f"{dependency.name} {dependency.version} is affected by {vuln_id}.",
                location=dependency.source,
                recommendation=recommendation,
                category="vulnerable-dependency",
                reference=f"https://osv.dev/vulnerability/{vuln_id}",
                metadata={
                    "id": vuln_id,
                    "ecosystem": dependency.ecosystem,
                    "aliases": data.get("aliases") or [],
                    "fixed": fixes,
                },
            ))
            vulnerable += 1

    if vulnerable == 0:
        findings.append(Finding(
            Severity.INFO, "No known vulnerabilities found",
            f"Checked {len(pinned)} pinned dependencies against OSV.",
            category="summary",
        ))

    context.reporter.report(findings, title="Dependency check")
    return findings
