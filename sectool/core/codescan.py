from __future__ import annotations

import logging
import math
import os
import re
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, List, Optional, Tuple

from .findings import Finding, Severity

DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".env", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", ".idea", ".vscode", "site-packages", ".eggs", "target",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".class", ".jar",
    ".pyc", ".pyo", ".o", ".a", ".bin", ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".avi", ".mov", ".webp", ".db", ".sqlite", ".lock",
}

IGNORE_MARKER = "sectool:ignore"
MAX_FILE_BYTES = 2 * 1024 * 1024
EVIDENCE_LIMIT = 180

Matcher = Callable[[str], Optional[str]]


@dataclass
class Rule:
    id: str
    severity: Severity
    category: str
    title: str
    recommendation: str
    pattern: Optional[re.Pattern] = None
    matcher: Optional[Matcher] = None
    extensions: Tuple[str, ...] = ()
    reference: Optional[str] = None

    def applies_to(self, extension: str) -> bool:
        return not self.extensions or extension in self.extensions

    def matches(self, line: str) -> bool:
        if self.matcher is not None:
            return self.matcher(line) is not None
        if self.pattern is not None:
            return self.pattern.search(line) is not None
        return False


def compile_rule(
    rule_id: str,
    severity: Severity,
    category: str,
    title: str,
    recommendation: str,
    regex: Optional[str] = None,
    matcher: Optional[Matcher] = None,
    extensions: Iterable[str] = (),
    flags: int = re.IGNORECASE,
    reference: Optional[str] = None,
) -> Rule:
    pattern = re.compile(regex, flags) if regex is not None else None
    return Rule(
        id=rule_id,
        severity=severity,
        category=category,
        title=title,
        recommendation=recommendation,
        pattern=pattern,
        matcher=matcher,
        extensions=tuple(extensions),
        reference=reference,
    )


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def truncate(text: str, limit: int = EVIDENCE_LIMIT) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "..."


def algorithm_pattern(*names: str) -> str:
    alternation = "|".join(names)
    return (
        rf"(?:hashlib|hmac)\.(?:{alternation})\b"
        rf"|\b(?:{alternation})\.(?:new|MODE_)"
        rf"|\b(?:{alternation})\s*\("
        rf"|(?:getInstance|createHash|createHmac|createCipher(?:iv)?|createDecipher(?:iv)?)\s*\(\s*['\"]\s*(?:{alternation})"
        rf"|['\"](?:{alternation})(?:with|/)"
        rf"|['\"](?:{alternation})['\"]"
    )


def is_probably_binary(path: str) -> bool:
    if os.path.splitext(path)[1].lower() in BINARY_EXTENSIONS:
        return True
    try:
        with open(path, "rb") as handle:
            return b"\x00" in handle.read(2048)
    except OSError:
        return True


def iter_files(
    root: str,
    exclude_dirs: Optional[Iterable[str]] = None,
    include_extensions: Optional[Iterable[str]] = None,
) -> Iterator[str]:
    excluded = set(DEFAULT_EXCLUDE_DIRS)
    if exclude_dirs:
        excluded.update(exclude_dirs)
    extensions = {e.lower() for e in include_extensions} if include_extensions else None

    if os.path.isfile(root):
        yield root
        return

    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in excluded]
        for name in files:
            if extensions and os.path.splitext(name)[1].lower() not in extensions:
                continue
            yield os.path.join(current, name)


def scan_file(path: str, rules: List[Rule], display_path: Optional[str] = None) -> List[Finding]:
    extension = os.path.splitext(path)[1].lower()
    applicable = [rule for rule in rules if rule.applies_to(extension)]
    if not applicable:
        return []

    location_base = display_path or path
    findings: List[Finding] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for number, raw in enumerate(handle, start=1):
                line = raw.rstrip("\n")
                if IGNORE_MARKER in line:
                    continue
                for rule in applicable:
                    if rule.matches(line):
                        findings.append(
                            Finding(
                                severity=rule.severity,
                                title=rule.title,
                                description=f"{rule.category} pattern matched ({rule.id}).",
                                location=f"{location_base}:{number}",
                                recommendation=rule.recommendation,
                                category=rule.category,
                                evidence=truncate(line),
                                reference=rule.reference,
                                metadata={"rule": rule.id},
                            )
                        )
    except OSError:
        return findings
    return findings


def scan_tree(
    root: str,
    rules: List[Rule],
    exclude_dirs: Optional[Iterable[str]] = None,
    include_extensions: Optional[Iterable[str]] = None,
    max_bytes: int = MAX_FILE_BYTES,
    logger: Optional[logging.Logger] = None,
) -> List[Finding]:
    root = os.path.abspath(root)
    base = root if os.path.isdir(root) else os.path.dirname(root)
    findings: List[Finding] = []
    for path in iter_files(root, exclude_dirs, include_extensions):
        try:
            if os.path.getsize(path) > max_bytes:
                continue
        except OSError:
            continue
        if is_probably_binary(path):
            continue
        display = os.path.relpath(path, base) if base else path
        if logger is not None:
            logger.debug("scanning %s", display)
        findings.extend(scan_file(path, rules, display_path=display))
    return findings


def add_scan_arguments(parser) -> None:
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument(
        "--exclude",
        action="append",
        dest="excludes",
        default=[],
        metavar="DIR",
        help="Directory name to exclude (repeatable)",
    )
    parser.add_argument(
        "--ext",
        action="append",
        dest="extensions",
        default=[],
        metavar="EXT",
        help="Restrict to file extensions, e.g. --ext .py (repeatable)",
    )


def normalize_extensions(values: Iterable[str]) -> Optional[set]:
    normalized = {value if value.startswith(".") else "." + value for value in values}
    return normalized or None
