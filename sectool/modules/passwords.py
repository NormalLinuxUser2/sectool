from __future__ import annotations

import getpass
import hashlib
import math
import re
import sys
from typing import List, Optional

import requests

from ..core.context import Context
from ..core.errors import SectoolError
from ..core.findings import Finding, Severity

NAME = "pass"
HELP = "Audit password strength and check breach exposure via HaveIBeenPwned"

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"
USER_AGENT = "sectool-password-auditor"

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "abc123",
    "football", "monkey", "letmein", "111111", "iloveyou", "admin", "welcome",
    "login", "princess", "dragon", "passw0rd", "master", "hello", "freedom",
    "whatever", "qazwsx", "trustno1", "000000", "sunshine", "123123", "superman",
    "password1", "1234567890", "qwerty123", "1q2w3e4r", "654321", "123321",
}

KEYBOARD_SEQUENCES = ("qwerty", "asdfgh", "zxcvbn", "qazwsx", "qwertz", "1qaz2wsx")


def character_pool(password: str) -> int:
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool += 33
    return pool


def entropy_bits(password: str) -> float:
    pool = character_pool(password)
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def strength_label(entropy: float) -> str:
    if entropy < 28:
        return "very weak"
    if entropy < 36:
        return "weak"
    if entropy < 60:
        return "reasonable"
    if entropy < 128:
        return "strong"
    return "very strong"


def _has_run(text: str) -> bool:
    for i in range(len(text) - 2):
        a, b, c = text[i], text[i + 1], text[i + 2]
        if not (a.isalnum() and b.isalnum() and c.isalnum()):
            continue
        if ord(b) - ord(a) == 1 and ord(c) - ord(b) == 1:
            return True
        if ord(a) - ord(b) == 1 and ord(b) - ord(c) == 1:
            return True
    return False


def detect_patterns(password: str) -> List[str]:
    issues: List[str] = []
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        issues.append("appears in the common-password list")
    if re.search(r"(.)\1{2,}", password):
        issues.append("contains 3+ repeated characters")
    if _has_run(lowered):
        issues.append("contains sequential characters")
    for sequence in KEYBOARD_SEQUENCES:
        if sequence in lowered:
            issues.append(f"contains keyboard sequence '{sequence}'")
            break
    if password.isdigit():
        issues.append("digits only")
    elif password.isalpha():
        issues.append("letters only")
    if re.search(r"(19|20)\d{2}", password):
        issues.append("contains a 4-digit year")
    return issues


def check_hibp(password: str, timeout: float = 10.0) -> int:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    response = requests.get(
        HIBP_RANGE_URL + prefix,
        headers={"Add-Padding": "true", "User-Agent": USER_AGENT},
        timeout=timeout,
    )
    response.raise_for_status()
    for line in response.text.splitlines():
        parts = line.split(":")
        if len(parts) != 2:
            continue
        candidate, count = parts
        if candidate.strip().upper() == suffix:
            return int(count.strip())
    return 0


def _obtain_password(args, context: Context) -> Optional[str]:
    if args.stdin:
        return sys.stdin.readline().rstrip("\n")
    if args.password is not None:
        context.logger.warning(
            "passing a password as an argument can leak it via shell history; "
            "prefer the interactive prompt or --stdin"
        )
        return args.password
    try:
        return getpass.getpass("Password to audit: ")
    except (EOFError, KeyboardInterrupt):
        return None


def configure_parser(parser) -> None:
    parser.add_argument(
        "password",
        nargs="?",
        help="Password to audit (omit to be prompted securely)",
    )
    parser.add_argument("--stdin", action="store_true", help="Read the password from stdin")
    parser.add_argument(
        "--no-hibp",
        action="store_true",
        help="Skip the HaveIBeenPwned breach lookup",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")


def run(args, context: Context) -> List[Finding]:
    password = _obtain_password(args, context)
    if not password:
        raise SectoolError("no password provided")

    findings: List[Finding] = []
    entropy = entropy_bits(password)
    rating = strength_label(entropy)
    length = len(password)
    context.reporter.message(
        f"Length: {length}   Estimated entropy: {entropy:.1f} bits   Strength: {rating}"
    )

    if entropy < 60:
        severity = Severity.HIGH if entropy < 36 else Severity.MEDIUM
        findings.append(Finding(
            severity, f"Low password entropy ({entropy:.1f} bits)",
            f"Estimated entropy is {entropy:.1f} bits, rated '{rating}'.",
            recommendation="Use a longer passphrase (16+ characters) mixing character classes.",
            category="strength",
        ))

    if length < 12:
        findings.append(Finding(
            Severity.MEDIUM, "Password shorter than 12 characters",
            f"The password is {length} characters long.",
            recommendation="Use at least 12-16 characters.",
            category="strength",
        ))

    for issue in detect_patterns(password):
        findings.append(Finding(
            Severity.MEDIUM, "Predictable pattern detected",
            f"The password {issue}.",
            recommendation="Avoid dictionary words, sequences, repeats and predictable patterns.",
            category="pattern",
        ))

    if not args.no_hibp:
        try:
            count = check_hibp(password, args.timeout)
        except requests.RequestException as exc:
            context.logger.warning("HIBP lookup failed: %s", exc)
            findings.append(Finding(
                Severity.INFO, "Breach check skipped",
                "Could not reach the HaveIBeenPwned API.",
                category="breach",
            ))
        else:
            if count > 0:
                findings.append(Finding(
                    Severity.CRITICAL, "Password found in known breaches",
                    f"This password appears {count:,} times in breach corpora "
                    "(checked with k-anonymity; the password was never sent).",
                    recommendation="Stop using this password everywhere and rotate it now.",
                    category="breach",
                    reference="https://haveibeenpwned.com/Passwords",
                ))
            else:
                findings.append(Finding(
                    Severity.INFO, "Not found in known breaches",
                    "No match in the HaveIBeenPwned k-anonymity range.",
                    category="breach",
                ))

    context.reporter.report(findings, title="Password audit")
    return findings
