from __future__ import annotations

import os
from typing import List

from ..core.codescan import (
    Rule,
    add_scan_arguments,
    algorithm_pattern,
    compile_rule,
    normalize_extensions,
    scan_tree,
)
from ..core.context import Context
from ..core.errors import SectoolError
from ..core.findings import Finding, Severity

NAME = "crypto"
HELP = "Audit code for weak cryptographic primitives and misuse"

PY = (".py",)
JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
C = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")

CWE = "https://cwe.mitre.org/data/definitions/327.html"
CWE_RNG = "https://cwe.mitre.org/data/definitions/338.html"
CWE_KEY = "https://cwe.mitre.org/data/definitions/326.html"
CWE_CERT = "https://cwe.mitre.org/data/definitions/295.html"

CATEGORIES = (
    "weak-hash",
    "weak-cipher",
    "weak-mode",
    "weak-random",
    "weak-keysize",
    "static-iv",
    "weak-protocol",
    "cert-validation",
)

RULES: List[Rule] = [
    compile_rule(
        "CRYPTO-MD5", Severity.HIGH, "weak-hash",
        "MD5 is cryptographically broken",
        "Replace MD5 with SHA-256+; for passwords use argon2/bcrypt/scrypt.",
        regex=algorithm_pattern("md5"),
        reference=CWE,
    ),
    compile_rule(
        "CRYPTO-MD4", Severity.HIGH, "weak-hash",
        "MD4 is broken",
        "Do not use MD4; migrate to SHA-256 or SHA-3.",
        regex=algorithm_pattern("md4"), reference=CWE,
    ),
    compile_rule(
        "CRYPTO-SHA1", Severity.MEDIUM, "weak-hash",
        "SHA-1 is deprecated for security use",
        "Use SHA-256 or the SHA-3 family.",
        regex=algorithm_pattern("sha1", "sha-1"),
        reference=CWE,
    ),
    compile_rule(
        "CRYPTO-DES", Severity.HIGH, "weak-cipher",
        "DES/3DES is weak",
        "Use AES-256-GCM or ChaCha20-Poly1305.",
        regex=algorithm_pattern("des", "des3", "3des", "tripledes", "desede"),
        reference=CWE,
    ),
    compile_rule(
        "CRYPTO-RC4", Severity.HIGH, "weak-cipher",
        "RC4 stream cipher is insecure",
        "Use AES-GCM or ChaCha20-Poly1305.",
        regex=algorithm_pattern("rc4", "arc4", "arcfour"), reference=CWE,
    ),
    compile_rule(
        "CRYPTO-BLOWFISH", Severity.MEDIUM, "weak-cipher",
        "Blowfish uses a 64-bit block",
        "Use AES for new designs to avoid birthday-bound attacks.",
        regex=algorithm_pattern("blowfish"), reference=CWE,
    ),
    compile_rule(
        "CRYPTO-ECB", Severity.HIGH, "weak-mode",
        "ECB mode leaks plaintext structure",
        "Use an authenticated mode such as GCM.",
        regex=r"MODE_ECB|modes\.ECB|['\"][A-Za-z0-9]+/ECB", reference=CWE,
    ),
    compile_rule(
        "CRYPTO-RANDOM-PY", Severity.MEDIUM, "weak-random",
        "Insecure PRNG used in a likely security context",
        "Use the secrets module or os.urandom().",
        regex=r"\brandom\.(random|randint|randrange|choice|getrandbits|sample|shuffle)\s*\(",
        extensions=PY, reference=CWE_RNG,
    ),
    compile_rule(
        "CRYPTO-RANDOM-JS", Severity.MEDIUM, "weak-random",
        "Math.random() is not cryptographically secure",
        "Use crypto.getRandomValues() or crypto.randomBytes().",
        regex=r"Math\.random\s*\(", extensions=JS, reference=CWE_RNG,
    ),
    compile_rule(
        "CRYPTO-RANDOM-C", Severity.MEDIUM, "weak-random",
        "rand()/srand() is predictable",
        "Use a CSPRNG such as getrandom() or /dev/urandom.",
        regex=r"\b(rand|srand|random|srandom)\s*\(", extensions=C, reference=CWE_RNG,
    ),
    compile_rule(
        "CRYPTO-RSA-KEYSIZE", Severity.HIGH, "weak-keysize",
        "RSA key smaller than 2048 bits",
        "Use RSA >= 2048 bits or an EC curve like P-256.",
        regex=r"key_size\s*=\s*(512|768|1024)\b|RSA\.generate\(\s*(512|768|1024)\b|genrsa\b.*\b(512|768|1024)\b",
        reference=CWE_KEY,
    ),
    compile_rule(
        "CRYPTO-DH-KEYSIZE", Severity.MEDIUM, "weak-keysize",
        "Diffie-Hellman parameters smaller than 2048 bits",
        "Use DH/DSA parameters of at least 2048 bits.",
        regex=r"generate_parameters\([^)]*key_size\s*=\s*(512|768|1024)\b",
        extensions=PY, reference=CWE_KEY,
    ),
    compile_rule(
        "CRYPTO-STATIC-IV", Severity.MEDIUM, "static-iv",
        "Possible hardcoded IV or nonce",
        "Generate a fresh random IV/nonce for every encryption.",
        regex=r"\b(iv|nonce)\s*=\s*(b?['\"][^'\"]+['\"])",
        extensions=PY, reference=CWE,
    ),
    compile_rule(
        "CRYPTO-WEAK-PROTOCOL", Severity.HIGH, "weak-protocol",
        "Weak SSL/TLS protocol constant",
        "Require TLS 1.2+ (PROTOCOL_TLS_CLIENT with minimum_version TLSv1_2).",
        regex=r"PROTOCOL_(SSLv2|SSLv3|TLSv1)\b|SSLv2|SSLv3|TLSv1_1|TLSv1\.0|TLSv1\.1",
        reference=CWE,
    ),
    compile_rule(
        "CRYPTO-VERIFY-OFF", Severity.HIGH, "cert-validation",
        "Certificate verification disabled",
        "Never disable certificate verification in production code.",
        regex=r"verify\s*=\s*False|CERT_NONE|rejectUnauthorized\s*:\s*false|check_hostname\s*=\s*False|InsecureSkipVerify\s*:\s*true",
        reference=CWE_CERT,
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

    context.logger.info("auditing crypto usage in %s with %d rules", args.path, len(rules))
    findings = scan_tree(
        args.path,
        rules,
        exclude_dirs=args.excludes,
        include_extensions=normalize_extensions(args.extensions),
        logger=context.logger,
    )
    context.reporter.report(findings, title=f"Crypto audit: {args.path}")
    return findings
