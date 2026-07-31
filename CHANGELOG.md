# Changelog

All notable changes to `sectool` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0]

### Added
- **`probe` command** — an HTTP prober/fingerprinter that traces the redirect
  chain hop by hop and reports final status, page title, `Server`/`X-Powered-By`
  banners, response time and a technology fingerprint (from headers, cookies and
  body markers). Flags cleartext HTTP, directory listing, version disclosure and
  server errors. Supports probing many hosts via `--list`.
- **`methods` command** — enumerates accepted HTTP methods (`OPTIONS` + active
  probing) and flags dangerous verbs: `PUT`/`DELETE` (high), `TRACE`/`CONNECT`/
  WebDAV `PROPFIND` (medium). Reports the advertised `Allow` header.
- **Fuzzer enhancements**: body-content filtering (`--match-regex`/
  `--filter-regex`), transient-error retries (`--retries`), rate limiting
  (`--delay`), multiple wordlists (repeatable `--wordlist`), session cookies
  (`--cookie`), redirect following (`--follow-redirects`), and per-hit page
  title, content-type and response-time capture.

### Changed
- Bumped version to 1.2.0.

## [1.1.0]

### Added
- **`fuzz` command** — a threaded web fuzzer for content discovery and
  fault injection. Supports the `FUZZ` keyword injection point or base-URL path
  brute-forcing, a built-in wordlist plus `--wordlist` files, extension
  mutation (`--ext`), wildcard/soft-404 baseline auto-calibration, and
  classification of sensitive hits (`.git`, `.env`, private keys, database
  dumps, backups, admin panels).
  - Recursive directory descent (`--recursion`, `--recursion-depth`).
  - Response filtering by status code, byte size and word count
    (`--match-code`/`--filter-code`, `--match-size`/`--filter-size`,
    `--match-word`/`--filter-word`).
- **`headers` command** — an HTTP response security-header auditor covering
  HSTS, CSP (including `unsafe-inline`/`unsafe-eval`), clickjacking protection,
  `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, insecure
  CORS, missing `Secure`/`HttpOnly`/`SameSite` cookie flags, and version
  disclosure via `Server`/`X-Powered-By`.
- **SARIF 2.1.0 output** via the global `--sarif` flag, for GitHub code scanning
  and CI ingestion.
- Shared HTTP helper (`core/httpclient.py`) for URL normalization and session
  building across the network modules.

### Changed
- Bumped version to 1.1.0 and expanded the package description and keywords.

## [1.0.0]

### Added
- Initial release with the `scan`, `ssl`, `deps`, `packets`, `pass` and
  `crypto` commands, severity-ranked color/JSON output, and a network-free test
  suite.
