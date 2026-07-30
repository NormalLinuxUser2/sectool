# sectool

A modular cybersecurity multi-tool CLI for security teams. `sectool` bundles
eight focused auditors behind a single, consistent command-line interface with
severity-ranked, color-coded output and machine-readable JSON or SARIF.

| Command | Purpose |
| --- | --- |
| `sectool scan` | Static code scan for SQL injection, XSS, hardcoded secrets, command injection and weak crypto |
| `sectool ssl` | SSL/TLS certificate, protocol and cipher auditor |
| `sectool deps` | Dependency vulnerability checker backed by the OSV database |
| `sectool packets` | Network traffic analyzer for protocol breakdown and suspicious patterns (educational) |
| `sectool pass` | Password strength auditor with HaveIBeenPwned breach checking (k-anonymity) |
| `sectool crypto` | Auditor for weak cryptographic primitives and misuse |
| `sectool headers` | HTTP response security-header auditor (HSTS, CSP, cookies, CORS) |
| `sectool fuzz` | Threaded web fuzzer for content discovery and unexpected responses |

## Responsible use

`sectool` is intended for **authorized** security testing, defensive review and
education. Only scan code, hosts, networks and credentials you own or have
explicit written permission to assess. The packet analyzer captures live
traffic and may require elevated privileges; capturing networks you do not
control may be illegal.

## Installation

Requires Python 3.9+.

```bash
git clone https://github.com/NormalLinuxUser2/sectool.git
cd sectool

python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
pip install -e .
```

The packet analyzer depends on [scapy](https://scapy.net/), which is included in
`requirements.txt`. If you installed only the core package, add it with:

```bash
pip install -e ".[packets]"
```

After installation the `sectool` command is available on your PATH. You can also
run it without installing via `python -m sectool`.

## Global options

These options are available on every subcommand and are placed **after** the
command name:

| Option | Description |
| --- | --- |
| `--json` | Emit findings as JSON instead of text |
| `--sarif` | Emit findings as SARIF 2.1.0 (for GitHub code scanning / CI) |
| `--no-color` | Disable ANSI colors |
| `--min-severity LEVEL` | Hide findings below `LEVEL` (`info`, `low`, `medium`, `high`, `critical`) |
| `--fail-on LEVEL` | Exit non-zero when a finding at or above `LEVEL` is present (default: `low`) |
| `--output FILE` | Write the report to a file instead of stdout |
| `-v`, `-vv` | Increase log verbosity (logs go to stderr) |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Completed; no findings at or above `--fail-on` |
| `1` | Completed; findings at or above `--fail-on` were reported |
| `2` | Error (bad input, unreachable host, missing dependency) |
| `130` | Interrupted |

This makes `sectool` easy to wire into CI: a non-zero exit fails the build.

## Usage

### Code vulnerability scanner

```bash
# Scan a project directory
sectool scan ./myapp

# Only show medium and above, restrict to Python files
sectool scan ./myapp --min-severity medium --ext .py

# Focus on specific categories and ignore a directory
sectool scan ./myapp --category secret --category sql-injection --exclude vendor

# JSON output for tooling
sectool scan ./myapp --json --output report.json
```

Categories: `sql-injection`, `xss`, `secret`, `command-injection`, `weak-crypto`.
Add the marker `sectool:ignore` to a source line to suppress findings on it.

### SSL/TLS auditor

```bash
# Audit a host on the default port (443)
sectool ssl example.com

# Custom port and a stricter expiry warning window
sectool ssl mail.example.com --port 993 --expiry-warning-days 45

# Only surface real problems
sectool ssl example.com --min-severity medium
```

Checks certificate expiration and validity, trust-chain and hostname
verification, key size, signature algorithm, self-signed certificates, enabled
protocol versions (flagging SSLv3/TLS 1.0/1.1) and acceptance of weak cipher
suites.

### Dependency checker

```bash
# Check the current directory's manifests
sectool deps

# Check a specific manifest
sectool deps ./requirements.txt
sectool deps ./frontend/package.json

# Parse manifests without contacting the OSV API
sectool deps ./myapp --offline
```

Parses `requirements.txt` and `package.json`, cross-references pinned versions
against [OSV](https://osv.dev/), and reports vulnerable packages with suggested
fixed versions. Unpinned dependencies are flagged as a hygiene issue.

### Packet analyzer (educational)

```bash
# Analyze a capture file
sectool packets --read capture.pcap

# Live capture (usually requires admin/root)
sectool packets --iface eth0 --count 500 --bpf "tcp port 80"
```

Summarizes the protocol distribution and top talkers, then flags suspicious
patterns: probable port scans, cleartext protocols, possible cleartext
credentials and possible ARP spoofing.

### Password auditor

```bash
# Prompt securely (recommended; the password is never echoed)
sectool pass

# From stdin (does not appear in shell history)
echo 'hunter2' | sectool pass --stdin

# Skip the online breach check
sectool pass --no-hibp
```

Estimates entropy, detects predictable patterns (common passwords, sequences,
repeats, keyboard walks, years) and checks the password against the
HaveIBeenPwned breach corpus. The breach check uses **k-anonymity**: only the
first 5 characters of the SHA-1 hash are sent, so the password itself never
leaves your machine.

### Crypto auditor

```bash
# Audit cryptographic usage in a codebase
sectool crypto ./myapp

# Limit to specific categories
sectool crypto ./myapp --category weak-hash --category weak-random
```

Categories: `weak-hash`, `weak-cipher`, `weak-mode`, `weak-random`,
`weak-keysize`, `static-iv`, `weak-protocol`, `cert-validation`.

### HTTP security-header auditor

```bash
# Audit the response headers of a URL
sectool headers https://example.com

# Send a HEAD request and don't follow redirects
sectool headers example.com --method HEAD --no-redirect

# Add an auth header and only show real problems
sectool headers https://app.example.com --header "Authorization: Bearer $TOKEN" --min-severity medium
```

Checks for missing or weak `Strict-Transport-Security`, `Content-Security-Policy`
(including `unsafe-inline`/`unsafe-eval`), clickjacking protection
(`X-Frame-Options`/`frame-ancestors`), `X-Content-Type-Options`,
`Referrer-Policy` and `Permissions-Policy`; insecure CORS (wildcard origin with
credentials); missing `Secure`/`HttpOnly`/`SameSite` cookie flags; and version
disclosure via `Server`/`X-Powered-By`.

### Web fuzzer

```bash
# Content discovery against a base URL (paths appended from the built-in wordlist)
sectool fuzz http://testsite.local/

# Explicit injection point with the FUZZ keyword and a custom wordlist
sectool fuzz "http://testsite.local/FUZZ" --wordlist paths.txt --ext .php --ext .bak

# Tune concurrency and filter noise by status code, response size or word count
sectool fuzz http://testsite.local/ --threads 16 --match-code 200,301,403 --filter-size 0

# Recurse into discovered directories up to two levels deep
sectool fuzz http://testsite.local/ --recursion --recursion-depth 2
```

Requests each candidate path concurrently and reports responses that stand out.
It auto-calibrates a baseline from a random path to suppress wildcard/"soft-404"
servers, and classifies notable hits — an exposed `.git` directory, `.env`,
private keys, database dumps, backups, admin panels — at an appropriate
severity. Use the `FUZZ` keyword to fuzz any part of the URL (or the `--data`
body).

With `--recursion`, any discovered directory (a redirect to a trailing slash, or
an extensionless `200`) is re-fuzzed with the same wordlist up to
`--recursion-depth` levels, so nested paths like `/admin/.env` are found
automatically. Responses can be included or excluded by status code
(`--match-code`/`--filter-code`), byte size (`--match-size`/`--filter-size`) or
word count (`--match-word`/`--filter-word`). **Only fuzz targets you own or are
explicitly authorized to test.**

## Output and severity

Findings are ranked across five severity levels, color-coded in the terminal:

`CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFO`

Each finding includes a title, location, description, remediation advice and,
where relevant, a reference (CWE or advisory). Use `--json` for a structured
document containing a summary count and the full findings array, or `--sarif` to
emit SARIF 2.1.0 that GitHub code scanning and other CI tooling can ingest
directly.

## Project structure

```
sectool/
├── sectool/
│   ├── cli.py              Central argparse entry point and dispatch
│   ├── core/
│   │   ├── findings.py     Severity levels and the Finding model
│   │   ├── output.py       Color/JSON reporter
│   │   ├── logging.py      Structured logging setup
│   │   ├── codescan.py     Shared regex/rule scanning engine
│   │   ├── httpclient.py   Shared HTTP session/URL helpers
│   │   ├── context.py      Reporter + logger container
│   │   └── errors.py       Exception types
│   └── modules/
│       ├── scan.py         Code vulnerability scanner
│       ├── ssl_audit.py    SSL/TLS auditor
│       ├── deps.py         Dependency checker (OSV)
│       ├── packets.py      Packet analyzer
│       ├── passwords.py    Password auditor (HIBP)
│       ├── crypto.py       Crypto auditor
│       ├── headers.py      HTTP security-header auditor
│       └── fuzz.py         Web content-discovery fuzzer
├── tests/                  pytest suite
├── requirements.txt
├── pyproject.toml
├── CHANGELOG.md
└── LICENSE
```

## Development

```bash
pip install -r requirements-dev.txt
pip install -e .
pytest
```

The test suite is network-free: the HaveIBeenPwned and OSV integrations are
mocked, so it runs fast and offline.

## Contributing

Contributions are welcome.

1. **Fork and branch.** Create a feature branch from `main`
   (`git checkout -b feature/my-change`).
2. **Match the style.** The codebase favors small, self-documenting functions
   and the shared `Finding`/`Severity`/`Reporter` abstractions. New detectors
   should return `Finding` objects so output stays consistent. The code is kept
   comment-free; prefer clear names over comments.
3. **Add detectors via rules.** For `scan` and `crypto`, add a `compile_rule(...)`
   entry to the module's `RULES` list rather than writing bespoke logic.
4. **Write tests.** Every new rule or feature needs coverage under `tests/`.
   Keep tests offline by mocking network calls.
5. **Run the suite.** `pytest` must pass before opening a pull request.
6. **Keep findings actionable.** Each finding should carry a clear title, a
   precise location and a concrete remediation.
7. **Open a pull request** describing the change, the motivation and any new
   dependencies.

Please report security issues responsibly via a private channel rather than a
public issue.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the release history.

## License

Released under the [MIT License](LICENSE).
