from __future__ import annotations

import datetime
import socket
import ssl
from typing import List, Optional, Tuple

from ..core.context import Context
from ..core.errors import SectoolError
from ..core.findings import Finding, Severity

NAME = "ssl"
HELP = "Audit a host's SSL/TLS certificate and configuration"

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

PROTOCOL_VERSIONS = [
    ("SSLv3", "SSLv3", Severity.CRITICAL),
    ("TLSv1.0", "TLSv1", Severity.HIGH),
    ("TLSv1.1", "TLSv1_1", Severity.HIGH),
    ("TLSv1.2", "TLSv1_2", None),
    ("TLSv1.3", "TLSv1_3", None),
]

WEAK_CIPHER_SPEC = "RC4:3DES:DES:IDEA:SEED:MD5:NULL:eNULL:aNULL:EXPORT:LOW:DES-CBC3-SHA"
WEAK_CIPHER_TOKENS = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "RC2", "IDEA", "SEED", "ADH", "AECDH")


def _unverified_context(minimum=None, maximum=None, ciphers: Optional[str] = None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if minimum is not None:
        try:
            context.minimum_version = minimum
        except (ValueError, OSError):
            return None
    if maximum is not None:
        try:
            context.maximum_version = maximum
        except (ValueError, OSError):
            return None
    if ciphers is not None:
        try:
            context.set_ciphers(ciphers)
        except ssl.SSLError:
            return None
    return context


def _clean_host(value: str) -> str:
    value = value.strip()
    for scheme in ("https://", "http://"):
        if value.lower().startswith(scheme):
            value = value[len(scheme):]
    value = value.split("/")[0]
    if value.count(":") == 1:
        value = value.split(":")[0]
    return value


def _fetch_certificate(host: str, port: int, timeout: float) -> Tuple[bytes, str, tuple]:
    attempts = (
        _unverified_context(),
        _unverified_context(minimum=ssl.TLSVersion.TLSv1, ciphers="DEFAULT@SECLEVEL=0"),
    )
    last_error: Optional[Exception] = None
    for context in attempts:
        if context is None:
            continue
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    return tls.getpeercert(binary_form=True), tls.version(), tls.cipher()
        except socket.gaierror:
            raise
        except (ssl.SSLError, OSError) as exc:
            last_error = exc
    raise last_error if last_error is not None else OSError("TLS handshake failed")


def _supports_protocol(host: str, port: int, version_name: str, timeout: float):
    version = getattr(ssl.TLSVersion, version_name, None)
    if version is None:
        return None
    context = _unverified_context(minimum=version, maximum=version, ciphers="DEFAULT@SECLEVEL=0")
    if context is None:
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                return tls.version()
    except (ssl.SSLError, socket.timeout, OSError):
        return False


def _accepts_weak_ciphers(host: str, port: int, timeout: float):
    context = _unverified_context(maximum=ssl.TLSVersion.TLSv1_2, ciphers=WEAK_CIPHER_SPEC)
    if context is None:
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                negotiated = tls.cipher()
    except (ssl.SSLError, socket.timeout, OSError):
        return False
    if negotiated and any(token in negotiated[0].upper() for token in WEAK_CIPHER_TOKENS):
        return negotiated
    return False


def _verify_trust(host: str, port: int, timeout: float) -> Tuple[bool, Optional[str]]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True, None
    except ssl.SSLCertVerificationError as exc:
        return False, exc.verify_message or str(exc)
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        return False, str(exc)


def _utc(value: datetime.datetime) -> datetime.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value


def _not_after(cert) -> datetime.datetime:
    return _utc(getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after)


def _not_before(cert) -> datetime.datetime:
    return _utc(getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before)


def _check_certificate(der: bytes, args, findings: List[Finding]) -> None:
    if not HAS_CRYPTOGRAPHY:
        findings.append(Finding(
            Severity.INFO, "Certificate deep-parse skipped",
            "Install the 'cryptography' package to analyze key size and signature algorithm.",
            category="tls",
        ))
        return

    cert = x509.load_der_x509_certificate(der)
    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = _not_after(cert)
    not_before = _not_before(cert)
    days_left = (not_after - now).days

    if not_after < now:
        findings.append(Finding(
            Severity.CRITICAL, "Certificate has expired",
            f"The certificate expired on {not_after.date().isoformat()}.",
            recommendation="Renew and deploy a valid certificate immediately.",
            category="tls",
        ))
    elif days_left <= 7:
        findings.append(Finding(
            Severity.HIGH, "Certificate expires within 7 days",
            f"The certificate expires on {not_after.date().isoformat()} ({days_left} days).",
            recommendation="Renew the certificate now to avoid an outage.",
            category="tls",
        ))
    elif days_left <= args.expiry_warning_days:
        findings.append(Finding(
            Severity.MEDIUM, "Certificate expiring soon",
            f"The certificate expires on {not_after.date().isoformat()} ({days_left} days).",
            recommendation="Schedule certificate renewal.",
            category="tls",
        ))
    else:
        findings.append(Finding(
            Severity.INFO, "Certificate validity period",
            f"Valid until {not_after.date().isoformat()} ({days_left} days remaining).",
            category="tls",
        ))

    if not_before > now:
        findings.append(Finding(
            Severity.HIGH, "Certificate is not yet valid",
            f"The certificate becomes valid on {not_before.date().isoformat()}.",
            recommendation="Check the system clock and the certificate issuance date.",
            category="tls",
        ))

    if cert.issuer == cert.subject:
        findings.append(Finding(
            Severity.MEDIUM, "Self-signed certificate",
            "Issuer and subject are identical; the certificate is self-signed.",
            recommendation="Use a certificate from a trusted CA for public services.",
            category="tls",
        ))

    _check_public_key(cert, findings)
    _check_signature(cert, findings)


def _check_public_key(cert, findings: List[Finding]) -> None:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        bits = key.key_size
        if bits < 2048:
            findings.append(Finding(
                Severity.HIGH, "Weak RSA public key",
                f"The certificate uses a {bits}-bit RSA key.",
                recommendation="Reissue with at least a 2048-bit RSA key or an EC key.",
                category="tls",
            ))
        else:
            findings.append(Finding(
                Severity.INFO, "RSA key size",
                f"Public key is {bits}-bit RSA.", category="tls",
            ))
    elif isinstance(key, ec.EllipticCurvePublicKey):
        bits = key.curve.key_size
        severity = Severity.HIGH if bits < 256 else Severity.INFO
        findings.append(Finding(
            severity, "Elliptic curve public key",
            f"Public key uses curve {key.curve.name} ({bits}-bit).",
            recommendation=None if bits >= 256 else "Use a curve of at least 256 bits (e.g. P-256).",
            category="tls",
        ))
    elif isinstance(key, dsa.DSAPublicKey):
        findings.append(Finding(
            Severity.MEDIUM, "DSA public key",
            "DSA keys are discouraged for modern TLS.",
            recommendation="Migrate to RSA-2048+ or an EC key.",
            category="tls",
        ))


def _check_signature(cert, findings: List[Finding]) -> None:
    algorithm = cert.signature_hash_algorithm
    if algorithm is None:
        return
    name = algorithm.name.lower()
    if name in ("md5", "sha1", "md2"):
        findings.append(Finding(
            Severity.HIGH, "Weak certificate signature algorithm",
            f"The certificate is signed using {name.upper()}.",
            recommendation="Reissue the certificate with a SHA-256+ signature.",
            category="tls",
        ))


def _check_trust(host: str, args, findings: List[Finding]) -> None:
    trusted, error = _verify_trust(host, args.port, args.timeout)
    if trusted:
        findings.append(Finding(
            Severity.INFO, "Certificate chain trusted",
            "The chain validated against the system trust store and matched the hostname.",
            category="tls",
        ))
    else:
        findings.append(Finding(
            Severity.HIGH, "Certificate chain validation failed",
            f"Validation against the system trust store failed: {error}",
            recommendation="Serve a certificate from a trusted CA that covers this hostname.",
            category="tls",
        ))


def _check_protocols(host: str, args, findings: List[Finding], logger) -> None:
    modern_supported = False
    for label, version_name, insecure_severity in PROTOCOL_VERSIONS:
        result = _supports_protocol(host, args.port, version_name, args.timeout)
        if result is None:
            logger.debug("protocol %s could not be tested locally", label)
            continue
        if not result:
            continue
        if insecure_severity is not None:
            findings.append(Finding(
                insecure_severity, f"Legacy protocol enabled: {label}",
                f"The server negotiated {label}, which is deprecated and insecure.",
                recommendation="Disable legacy protocols and require TLS 1.2 or higher.",
                category="tls-protocol",
            ))
        else:
            modern_supported = True
            findings.append(Finding(
                Severity.INFO, f"Protocol supported: {label}",
                "A modern, recommended protocol version is available.",
                category="tls-protocol",
            ))
    if not modern_supported:
        findings.append(Finding(
            Severity.HIGH, "No modern TLS protocol detected",
            "Neither TLS 1.2 nor TLS 1.3 appeared to be available.",
            recommendation="Enable TLS 1.2 and TLS 1.3 on the server.",
            category="tls-protocol",
        ))


def _check_ciphers(host: str, args, negotiated_version, cipher, findings: List[Finding]) -> None:
    weak = _accepts_weak_ciphers(host, args.port, args.timeout)
    if weak:
        findings.append(Finding(
            Severity.HIGH, "Weak cipher suite accepted",
            f"The server accepted the weak cipher {weak[0]}.",
            recommendation="Restrict the server to strong AEAD cipher suites (e.g. AES-GCM, ChaCha20).",
            category="tls-cipher",
        ))
    if cipher:
        name, protocol, bits = cipher
        severity = Severity.MEDIUM if (bits or 0) < 128 else Severity.INFO
        findings.append(Finding(
            severity, "Negotiated cipher suite",
            f"Default handshake negotiated {name} ({bits}-bit) over {negotiated_version}.",
            recommendation=None if severity is Severity.INFO else "Disable cipher suites weaker than 128-bit.",
            category="tls-cipher",
        ))


def configure_parser(parser) -> None:
    parser.add_argument("host", help="Hostname or domain to audit")
    parser.add_argument("--port", type=int, default=443, help="Port to connect to (default: 443)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Connection timeout in seconds")
    parser.add_argument(
        "--expiry-warning-days",
        type=int,
        default=30,
        help="Warn when the certificate expires within this many days (default: 30)",
    )


def run(args, context: Context) -> List[Finding]:
    host = _clean_host(args.host)
    if not host:
        raise SectoolError("a hostname is required")

    context.logger.info("auditing %s:%s", host, args.port)
    try:
        der, negotiated_version, cipher = _fetch_certificate(host, args.port, args.timeout)
    except socket.gaierror as exc:
        raise SectoolError(f"could not resolve host '{host}': {exc}")
    except (ssl.SSLError, socket.timeout, ConnectionError, OSError) as exc:
        raise SectoolError(f"could not connect to {host}:{args.port}: {exc}")

    findings: List[Finding] = []
    _check_certificate(der, args, findings)
    _check_trust(host, args, findings)
    _check_protocols(host, args, findings, context.logger)
    _check_ciphers(host, args, negotiated_version, cipher, findings)

    context.reporter.report(findings, title=f"SSL/TLS audit: {host}:{args.port}")
    return findings
