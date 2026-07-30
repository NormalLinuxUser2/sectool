from __future__ import annotations

import os
import re
from typing import List, Optional

from ..core.codescan import (
    Rule,
    add_scan_arguments,
    algorithm_pattern,
    compile_rule,
    normalize_extensions,
    scan_tree,
    shannon_entropy,
)
from ..core.context import Context
from ..core.errors import SectoolError
from ..core.findings import Finding, Severity

NAME = "scan"
HELP = "Scan source code for insecure patterns"

PY = (".py",)
WEB = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".html", ".htm", ".vue", ".php")

CWE_SQLI = "https://cwe.mitre.org/data/definitions/89.html"
CWE_XSS = "https://cwe.mitre.org/data/definitions/79.html"
CWE_CMD = "https://cwe.mitre.org/data/definitions/78.html"
CWE_SECRET = "https://cwe.mitre.org/data/definitions/798.html"
CWE_CRYPTO = "https://cwe.mitre.org/data/definitions/327.html"

CATEGORIES = (
    "sql-injection",
    "xss",
    "secret",
    "command-injection",
    "weak-crypto",
)

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|"
    r"client[_-]?secret|token|auth[_-]?token|credential|private[_-]?key)"
    r"\s*[:=]\s*['\"]([^'\"]{8,})['\"]"
)
_HIGH_ENTROPY_SHAPE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
_PLACEHOLDERS = (
    "changeme", "example", "your_", "your-", "xxxx", "placeholder", "<", "{{",
    "redacted", "dummy", "sample", "none", "null", "todo", "fixme", "...",
    "env[", "os.environ", "getenv", "process.env",
)


def _secret_matcher(line: str) -> Optional[str]:
    match = _SECRET_ASSIGNMENT.search(line)
    if not match:
        return None
    value = match.group(2)
    lowered = value.lower()
    if any(token in lowered for token in _PLACEHOLDERS):
        return None
    if shannon_entropy(value) >= 3.2 or _HIGH_ENTROPY_SHAPE.search(value):
        return value
    return None


RULES: List[Rule] = [
    compile_rule(
        "PY-SQLI-FSTRING", Severity.HIGH, "sql-injection",
        "Possible SQL injection via f-string",
        "Use parameterized queries: cursor.execute(sql, params).",
        regex=r"\b(execute|executemany|executescript)\s*\(\s*f['\"]",
        extensions=PY, reference=CWE_SQLI,
    ),
    compile_rule(
        "PY-SQLI-CONCAT", Severity.HIGH, "sql-injection",
        "Possible SQL injection via concatenation or format",
        "Use parameterized queries instead of building SQL with %, + or .format().",
        regex=r"\b(execute|executemany|executescript)\s*\([^)]*(%[^)]|\+|\.format\()",
        extensions=PY, reference=CWE_SQLI,
    ),
    compile_rule(
        "SQL-INTERP-GENERIC", Severity.MEDIUM, "sql-injection",
        "SQL statement combined with interpolation",
        "Validate and parameterize every value placed into a SQL statement.",
        regex=r"(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b.*(\$\{|\+\s*\w|%s\b.*%|f['\"])",
        reference=CWE_SQLI,
    ),
    compile_rule(
        "PY-CMD-OSSYSTEM", Severity.HIGH, "command-injection",
        "Use of os.system()",
        "Avoid os.system(); use subprocess with an argument list and shell=False.",
        regex=r"\bos\.system\s*\(",
        extensions=PY, reference=CWE_CMD,
    ),
    compile_rule(
        "PY-CMD-SHELL-TRUE", Severity.HIGH, "command-injection",
        "subprocess called with shell=True",
        "Pass arguments as a list and use shell=False to avoid shell injection.",
        regex=r"\bsubprocess\.(call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True",
        extensions=PY, reference=CWE_CMD,
    ),
    compile_rule(
        "PY-OS-POPEN", Severity.MEDIUM, "command-injection",
        "Use of os.popen()",
        "Use subprocess with argument lists instead of os.popen().",
        regex=r"\bos\.popen\s*\(",
        extensions=PY, reference=CWE_CMD,
    ),
    compile_rule(
        "PY-EVAL-EXEC", Severity.HIGH, "command-injection",
        "Use of eval() or exec()",
        "Avoid eval()/exec() on dynamic input; prefer ast.literal_eval for data.",
        regex=r"\b(eval|exec)\s*\(",
        extensions=PY, reference=CWE_CMD,
    ),
    compile_rule(
        "JS-CHILD-EXEC", Severity.HIGH, "command-injection",
        "Use of child_process.exec()",
        "Prefer execFile/spawn with an argument array over exec() with a string.",
        regex=r"child_process\.(exec|execSync)\s*\(",
        extensions=WEB, reference=CWE_CMD,
    ),
    compile_rule(
        "JS-EVAL", Severity.HIGH, "command-injection",
        "Use of eval()",
        "Avoid eval(); use JSON.parse or explicit logic instead.",
        regex=r"\beval\s*\(",
        extensions=WEB, reference=CWE_CMD,
    ),
    compile_rule(
        "JS-INNERHTML", Severity.MEDIUM, "xss",
        "Assignment to innerHTML/outerHTML",
        "Use textContent or sanitize with DOMPurify before inserting HTML.",
        regex=r"\.(inner|outer)HTML\s*=",
        extensions=WEB, reference=CWE_XSS,
    ),
    compile_rule(
        "JS-DOC-WRITE", Severity.MEDIUM, "xss",
        "Use of document.write()",
        "Avoid document.write(); build and append DOM nodes safely.",
        regex=r"document\.write(ln)?\s*\(",
        extensions=WEB, reference=CWE_XSS,
    ),
    compile_rule(
        "JS-DANGEROUS-HTML", Severity.MEDIUM, "xss",
        "Use of dangerouslySetInnerHTML",
        "Sanitize untrusted HTML before rendering with dangerouslySetInnerHTML.",
        regex=r"dangerouslySetInnerHTML",
        extensions=WEB, reference=CWE_XSS,
    ),
    compile_rule(
        "PY-MARK-SAFE", Severity.MEDIUM, "xss",
        "Use of mark_safe()/Markup()",
        "Do not mark untrusted content safe; rely on template auto-escaping.",
        regex=r"\b(mark_safe|Markup)\s*\(",
        extensions=PY, reference=CWE_XSS,
    ),
    compile_rule(
        "PY-RENDER-STRING", Severity.HIGH, "xss",
        "Use of render_template_string()",
        "Never build templates from user input (SSTI/XSS risk); use static templates.",
        regex=r"render_template_string\s*\(",
        extensions=PY, reference=CWE_XSS,
    ),
    compile_rule(
        "SECRET-AWS-AKID", Severity.CRITICAL, "secret",
        "Hardcoded AWS access key id",
        "Remove and rotate the key; load credentials from env or a secret manager.",
        regex=r"\bAKIA[0-9A-Z]{16}\b", flags=0, reference=CWE_SECRET,
    ),
    compile_rule(
        "SECRET-PRIVATE-KEY", Severity.CRITICAL, "secret",
        "Private key material committed",
        "Never commit private keys; rotate immediately and use a secret store.",
        regex=r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        flags=0, reference=CWE_SECRET,
    ),
    compile_rule(
        "SECRET-SLACK-TOKEN", Severity.CRITICAL, "secret",
        "Slack token committed",
        "Rotate the token and load it from the environment.",
        regex=r"xox[baprs]-[0-9A-Za-z\-]{10,}", flags=0, reference=CWE_SECRET,
    ),
    compile_rule(
        "SECRET-GH-TOKEN", Severity.CRITICAL, "secret",
        "GitHub token committed",
        "Revoke the token immediately and store secrets outside the codebase.",
        regex=r"\bgh[pousr]_[0-9A-Za-z]{36,}\b", flags=0, reference=CWE_SECRET,
    ),
    compile_rule(
        "SECRET-GENERIC", Severity.HIGH, "secret",
        "Hardcoded credential or API key",
        "Move secrets to environment variables or a managed secret store.",
        matcher=_secret_matcher, reference=CWE_SECRET,
    ),
    compile_rule(
        "WEAK-HASH", Severity.MEDIUM, "weak-crypto",
        "Weak hash function (MD5/SHA1)",
        "Use SHA-256+ for integrity; use bcrypt/argon2/scrypt for passwords.",
        regex=algorithm_pattern("md5", "sha1", "sha-1"),
        reference=CWE_CRYPTO,
    ),
    compile_rule(
        "WEAK-RANDOM", Severity.MEDIUM, "weak-crypto",
        "Insecure randomness in a likely security context",
        "Use the secrets module or os.urandom() for security-sensitive values.",
        regex=r"\brandom\.(random|randint|randrange|choice|getrandbits)\s*\(",
        extensions=PY, reference=CWE_CRYPTO,
    ),
]


def configure_parser(parser) -> None:
    add_scan_arguments(parser)
    parser.add_argument(
        "--category",
        action="append",
        dest="categories",
        metavar="NAME",
        help="Limit to a category (repeatable): " + ", ".join(CATEGORIES),
    )


def run(args, context: Context) -> List[Finding]:
    if not os.path.exists(args.path):
        raise SectoolError(f"path does not exist: {args.path}")

    rules = RULES
    if args.categories:
        wanted = set(args.categories)
        unknown = wanted - set(CATEGORIES)
        if unknown:
            raise SectoolError("unknown categories: " + ", ".join(sorted(unknown)))
        rules = [rule for rule in RULES if rule.category in wanted]

    context.logger.info("scanning %s with %d rules", args.path, len(rules))
    findings = scan_tree(
        args.path,
        rules,
        exclude_dirs=args.excludes,
        include_extensions=normalize_extensions(args.extensions),
        logger=context.logger,
    )
    context.reporter.report(findings, title=f"Code scan: {args.path}")
    return findings
