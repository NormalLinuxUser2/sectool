from __future__ import annotations

import logging
import re
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set, Tuple

import requests

from ..core.context import Context
from ..core.errors import SectoolError
from ..core.findings import Finding, Severity
from ..core.httpclient import DEFAULT_USER_AGENT, build_session, normalize_url, parse_headers

NAME = "fuzz"
HELP = "Fuzz a web target for hidden content and unexpected responses"

FUZZ_KEYWORD = "FUZZ"

DEFAULT_WORDLIST = (
    "admin", "administrator", "login", "logout", "dashboard", "config", "config.php",
    "configuration", "settings", "setup", "install", "backup", "backups", "old", "new",
    "test", "tests", "tmp", "temp", "dev", "staging", "api", "api/v1", "api/v2", "graphql",
    "server-status", "status", "health", "healthz", "metrics", "debug", "console",
    "phpinfo.php", "info.php", "robots.txt", "sitemap.xml", "security.txt", ".well-known",
    ".git/config", ".git/HEAD", ".gitignore", ".env", ".env.local", ".env.production",
    ".htaccess", ".htpasswd", ".svn/entries", ".DS_Store", ".aws/credentials", ".npmrc",
    "wp-admin", "wp-login.php", "wp-config.php", "wp-config.php.bak", "xmlrpc.php",
    "phpmyadmin", "adminer.php", "manager/html", "actuator", "actuator/env", "actuator/health",
    "web.config", "app.config", "docker-compose.yml", "Dockerfile", "package.json",
    "composer.json", "composer.lock", "yarn.lock", "id_rsa", "id_rsa.pub", "server.key",
    "private.key", "cert.pem", "db.sql", "dump.sql", "database.sql", "backup.sql",
    "backup.zip", "backup.tar.gz", "site.zip", "www.zip", "logs", "log", "error.log",
    "access.log", "uploads", "files", "download", "downloads", "images", "static", "assets",
    "js", "css", "vendor", "node_modules", "storage", "cache", "private", "secret", "secrets",
    "internal", "hidden", "user", "users", "account", "accounts", "register", "signup",
    "reset", "forgot", "token", "tokens", "swagger", "swagger-ui.html", "openapi.json",
    "readme.md", "README.md", "CHANGELOG.md", "LICENSE", "TODO", "notes.txt",
)


@dataclass
class SensitiveRule:
    pattern: re.Pattern
    severity: Severity
    title: str
    recommendation: str


def _rule(regex: str, severity: Severity, title: str, recommendation: str) -> SensitiveRule:
    return SensitiveRule(re.compile(regex, re.IGNORECASE), severity, title, recommendation)


SENSITIVE_RULES: List[SensitiveRule] = [
    _rule(r"(?:^|/)\.git(?:/|$)", Severity.CRITICAL, "Exposed .git repository",
          "Block access to .git/ at the web server; the full source history may be recoverable."),
    _rule(r"(?:^|/)\.svn(?:/|$)", Severity.CRITICAL, "Exposed .svn metadata",
          "Deny access to version-control directories on the web server."),
    _rule(r"(?:^|/)\.env", Severity.CRITICAL, "Exposed environment file",
          "Remove the .env file from the web root and rotate any secrets it contained."),
    _rule(r"(?:id_rsa|\.pem|\.p12|\.pfx|server\.key|private\.key)(?:$|\?)", Severity.CRITICAL,
          "Exposed private key material",
          "Remove the key from the web root and rotate it immediately."),
    _rule(r"\.(?:sql|db|sqlite|dump)(?:$|\?)", Severity.HIGH, "Exposed database dump",
          "Remove database exports from public paths; they may contain full data."),
    _rule(r"\.(?:bak|old|orig|backup|swp|save|~)(?:$|\?)", Severity.HIGH, "Exposed backup file",
          "Delete backup artifacts from the web root."),
    _rule(r"(?:^|/)(?:backup|backups|dump)(?:$|/|\.)", Severity.HIGH, "Exposed backup path",
          "Remove backup archives from public paths."),
    _rule(r"wp-config\.php|web\.config|app\.config|\.htpasswd", Severity.HIGH,
          "Exposed configuration file",
          "Restrict access to configuration files and rotate embedded credentials."),
    _rule(r"\.(?:log)(?:$|\?)|(?:^|/)logs?(?:$|/)", Severity.MEDIUM, "Exposed log file",
          "Logs can leak internal details; restrict access."),
    _rule(r"(?:phpmyadmin|adminer|wp-admin|wp-login|manager/html|actuator)", Severity.MEDIUM,
          "Exposed administrative interface",
          "Restrict admin panels by network/auth; do not expose them publicly."),
    _rule(r"(?:swagger|openapi|graphql|/api(?:/|$))", Severity.LOW, "Exposed API surface",
          "Ensure API docs/endpoints require authentication where appropriate."),
    _rule(r"(?:^|/)(?:admin|dashboard|console|debug|phpinfo|info\.php)", Severity.MEDIUM,
          "Sensitive endpoint discovered",
          "Verify the endpoint requires authentication and is intended to be public."),
]

MAX_SENSITIVE_EVIDENCE = 200


@dataclass
class FuzzHit:
    word: str
    url: str
    status: int
    size: int
    words: int = 0
    redirect: Optional[str] = None


@dataclass
class FuzzResult:
    hits: List[FuzzHit] = field(default_factory=list)
    requested: int = 0
    errors: int = 0
    bases_scanned: int = 0
    baseline_size: Optional[int] = None
    baseline_status: Optional[int] = None


def load_words(path: Optional[str]) -> List[str]:
    if not path:
        return list(DEFAULT_WORDLIST)
    words: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                word = raw.strip()
                if word and not word.startswith("#"):
                    words.append(word)
    except OSError as exc:
        raise SectoolError(f"could not read wordlist '{path}': {exc}")
    if not words:
        raise SectoolError(f"wordlist '{path}' is empty")
    return words


def expand_words(words: Iterable[str], extensions: Iterable[str]) -> List[str]:
    suffixes = [e if e.startswith(".") else "." + e for e in extensions]
    if not suffixes:
        return list(dict.fromkeys(words))
    expanded: List[str] = []
    for word in words:
        expanded.append(word)
        for suffix in suffixes:
            expanded.append(word + suffix)
    return list(dict.fromkeys(expanded))


def build_url(target: str, word: str) -> str:
    if FUZZ_KEYWORD in target:
        return target.replace(FUZZ_KEYWORD, word)
    if target.endswith("/"):
        return target + word
    return target + "/" + word


def _response_size(response) -> int:
    content = getattr(response, "content", None)
    if content is not None:
        return len(content)
    text = getattr(response, "text", "") or ""
    return len(text)


def _response_words(response) -> int:
    text = getattr(response, "text", None)
    if text is None:
        content = getattr(response, "content", b"") or b""
        if isinstance(content, bytes):
            text = content.decode("utf-8", "replace")
        else:
            text = str(content)
    return len(text.split())


def _parse_code_set(value: Optional[str]) -> Optional[Set[int]]:
    if not value:
        return None
    codes: Set[int] = set()
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            codes.add(int(token))
        except ValueError:
            raise SectoolError(f"invalid status code in filter: '{token}'")
    return codes or None


def _parse_size_set(value: Optional[str]) -> Optional[Set[int]]:
    if not value:
        return None
    sizes: Set[int] = set()
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            sizes.add(int(token))
        except ValueError:
            raise SectoolError(f"invalid size in filter: '{token}'")
    return sizes or None


@dataclass
class FuzzFilters:
    match_codes: Optional[Set[int]] = None
    filter_codes: Optional[Set[int]] = None
    match_sizes: Optional[Set[int]] = None
    filter_sizes: Optional[Set[int]] = None
    match_words: Optional[Set[int]] = None
    filter_words: Optional[Set[int]] = None

    def accepts(self, status: int, size: int, words: int = 0) -> bool:
        if self.match_codes is not None and status not in self.match_codes:
            return False
        if self.filter_codes is not None and status in self.filter_codes:
            return False
        if self.match_sizes is not None and size not in self.match_sizes:
            return False
        if self.filter_sizes is not None and size in self.filter_sizes:
            return False
        if self.match_words is not None and words not in self.match_words:
            return False
        if self.filter_words is not None and words in self.filter_words:
            return False
        return True


def _request(session, method: str, url: str, timeout: float, data: Optional[str]):
    return session.request(
        method,
        url,
        timeout=timeout,
        data=data,
        allow_redirects=False,
    )


def _calibrate(session, target: str, method: str, timeout: float, data: Optional[str],
               logger) -> Tuple[Optional[int], Optional[int]]:
    probe = build_url(target, "sectool-nonexistent-a8f3c1d9e7")
    try:
        response = _request(session, method, probe, timeout, data)
    except requests.RequestException as exc:
        logger.debug("baseline calibration failed: %s", exc)
        return None, None
    status = int(getattr(response, "status_code", 0))
    if status in (200, 302, 301, 403):
        logger.debug("baseline: server answers %s for random paths", status)
        return status, _response_size(response)
    return None, None


def _is_directory(hit: FuzzHit) -> bool:
    if hit.redirect:
        location = hit.redirect.split("?")[0].split("#")[0]
        if location.endswith("/"):
            return True
    leaf = hit.word.rstrip("/").rsplit("/", 1)[-1]
    if hit.status == 200 and "." not in leaf:
        return True
    return False


def _child_base(base: str, word: str) -> str:
    child = build_url(base, word)
    if not child.endswith("/"):
        child += "/"
    return child


def _fuzz_base(
    pool, session, base, words, method, timeout, data, filters,
    base_status, base_size, result,
) -> List[FuzzHit]:
    def probe(word: str) -> Optional[FuzzHit]:
        url = build_url(base, word)
        try:
            response = _request(session, method, url, timeout, data)
        except requests.RequestException:
            result.errors += 1
            return None
        status = int(getattr(response, "status_code", 0))
        size = _response_size(response)
        word_count = _response_words(response)
        if not filters.accepts(status, size, word_count):
            return None
        if base_status is not None and status == base_status and size == base_size:
            return None
        redirect = None
        if status in (301, 302, 303, 307, 308):
            redirect = (getattr(response, "headers", {}) or {}).get("Location")
        return FuzzHit(word=word, url=url, status=status, size=size,
                       words=word_count, redirect=redirect)

    hits: List[FuzzHit] = []
    futures = {pool.submit(probe, word): word for word in words}
    for future in as_completed(futures):
        result.requested += 1
        hit = future.result()
        if hit is not None:
            hits.append(hit)
    return hits


def run_fuzz(
    session,
    target: str,
    words: List[str],
    method: str = "GET",
    timeout: float = 10.0,
    data: Optional[str] = None,
    threads: int = 8,
    filters: Optional[FuzzFilters] = None,
    calibrate: bool = True,
    recursion_depth: int = 0,
    logger=None,
) -> FuzzResult:
    filters = filters or FuzzFilters()
    logger = logger or logging.getLogger("sectool.fuzz")
    result = FuzzResult()

    keyword_mode = FUZZ_KEYWORD in target
    if keyword_mode:
        recursion_depth = 0

    worker_count = max(1, min(threads, len(words))) if words else 1
    visited: Set[str] = set()
    queue: deque = deque([(target, 0)])

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        while queue:
            base, depth = queue.popleft()
            if base in visited:
                continue
            visited.add(base)
            result.bases_scanned += 1

            base_status = base_size = None
            if calibrate and not keyword_mode:
                base_status, base_size = _calibrate(session, base, method, timeout, data, logger)
                if base == target:
                    result.baseline_status, result.baseline_size = base_status, base_size

            hits = _fuzz_base(pool, session, base, words, method, timeout, data,
                              filters, base_status, base_size, result)
            result.hits.extend(hits)

            if depth < recursion_depth:
                for hit in hits:
                    if _is_directory(hit):
                        child = _child_base(base, hit.word)
                        if child not in visited:
                            logger.debug("recursing into %s (depth %d)", child, depth + 1)
                            queue.append((child, depth + 1))

    result.hits.sort(key=lambda h: (h.status, h.url))
    return result


def _classify(hit: FuzzHit) -> Optional[SensitiveRule]:
    for rule in SENSITIVE_RULES:
        if rule.pattern.search(hit.url) or rule.pattern.search(hit.word):
            return rule
    return None


def hits_to_findings(result: FuzzResult) -> List[Finding]:
    findings: List[Finding] = []
    for hit in result.hits:
        location = hit.url
        if hit.redirect:
            location = f"{hit.url} -> {hit.redirect}"
        meta = {"status": hit.status, "size": hit.size, "words": hit.words, "word": hit.word}
        rule = _classify(hit)
        if rule is not None:
            findings.append(Finding(
                rule.severity,
                f"{rule.title} ({hit.status})",
                f"Reachable at status {hit.status}, {hit.size} bytes, {hit.words} words.",
                location=location,
                recommendation=rule.recommendation,
                category="content-discovery",
                evidence=hit.word[:MAX_SENSITIVE_EVIDENCE],
                metadata=meta,
            ))
            continue
        severity = Severity.LOW if hit.status < 400 else Severity.INFO
        findings.append(Finding(
            severity,
            f"Discovered path '{hit.word}' ({hit.status})",
            f"The path responded with status {hit.status}, {hit.size} bytes, {hit.words} words.",
            location=location,
            recommendation="Confirm the resource is intended to be publicly reachable.",
            category="content-discovery",
            metadata=meta,
        ))
    return findings


def configure_parser(parser) -> None:
    parser.add_argument(
        "target",
        help="Target URL. Use the FUZZ keyword for the injection point, "
             "or provide a base URL to brute-force paths (e.g. http://host/).",
    )
    parser.add_argument("--wordlist", metavar="FILE", help="Wordlist file (default: built-in list)")
    parser.add_argument(
        "--ext", action="append", dest="extensions", default=[], metavar="EXT",
        help="Append extension(s) to each word, e.g. --ext .php (repeatable)",
    )
    parser.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    parser.add_argument("--data", help="Request body; may contain the FUZZ keyword")
    parser.add_argument(
        "--header", action="append", dest="headers", default=[], metavar="H",
        help="Extra request header 'Name: value' (repeatable)",
    )
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="Override the User-Agent")
    parser.add_argument("--threads", type=int, default=8, help="Concurrent requests (default: 8)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds")
    parser.add_argument("--match-code", metavar="CODES", help="Only report these status codes, e.g. 200,204,301")
    parser.add_argument("--filter-code", metavar="CODES", help="Drop these status codes, e.g. 404,400")
    parser.add_argument("--match-size", metavar="SIZES", help="Only report these byte sizes")
    parser.add_argument("--filter-size", metavar="SIZES", help="Drop these byte sizes")
    parser.add_argument("--match-word", metavar="COUNTS", help="Only report these response word counts")
    parser.add_argument("--filter-word", metavar="COUNTS", help="Drop these response word counts")
    parser.add_argument("--recursion", action="store_true", help="Recurse into discovered directories")
    parser.add_argument("--recursion-depth", type=int, default=1, metavar="N",
                        help="Maximum recursion depth when --recursion is set (default: 1)")
    parser.add_argument("--no-calibrate", action="store_true", help="Disable wildcard/baseline auto-filtering")
    parser.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates")


def run(args, context: Context) -> List[Finding]:
    context.reporter.message(
        "Only fuzz targets you own or are explicitly authorized to test."
    )

    if FUZZ_KEYWORD in args.target:
        target = args.target
    else:
        target = normalize_url(args.target, default_scheme="http")

    words = expand_words(load_words(args.wordlist), args.extensions)

    filters = FuzzFilters(
        match_codes=_parse_code_set(args.match_code),
        filter_codes=_parse_code_set(args.filter_code),
        match_sizes=_parse_size_set(args.match_size),
        filter_sizes=_parse_size_set(args.filter_size),
        match_words=_parse_size_set(args.match_word),
        filter_words=_parse_size_set(args.filter_word),
    )
    if filters.filter_codes is None and filters.match_codes is None:
        filters.filter_codes = {404}

    try:
        extra_headers = parse_headers(args.headers)
    except ValueError as exc:
        raise SectoolError(str(exc))

    session = build_session(
        user_agent=args.user_agent,
        headers=extra_headers,
        verify=not args.insecure,
    )

    recursion_depth = args.recursion_depth if args.recursion else 0
    if recursion_depth < 0:
        raise SectoolError("--recursion-depth must be zero or positive")

    context.logger.info("fuzzing %s with %d candidates", target, len(words))
    result = run_fuzz(
        session,
        target,
        words,
        method=args.method.upper(),
        timeout=args.timeout,
        data=args.data,
        threads=args.threads,
        filters=filters,
        calibrate=not args.no_calibrate,
        recursion_depth=recursion_depth,
        logger=context.logger,
    )

    if result.baseline_status is not None:
        context.reporter.message(
            f"Baseline: server returns {result.baseline_status} "
            f"({result.baseline_size} bytes) for random paths; matching hits filtered."
        )
    scope = f", {result.bases_scanned} directories" if result.bases_scanned > 1 else ""
    context.reporter.message(
        f"Sent {result.requested} requests, {result.errors} errors, "
        f"{len(result.hits)} hits{scope}."
    )

    findings = hits_to_findings(result)
    if not findings:
        findings.append(Finding(
            Severity.INFO, "No noteworthy responses",
            f"Tried {result.requested} paths without any interesting response.",
            category="summary",
        ))
    context.reporter.report(findings, title=f"Fuzz: {target}")
    return findings
