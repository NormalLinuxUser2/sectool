from sectool.modules import headers


def _titles(findings):
    return [f.title for f in findings]


def test_missing_headers_are_flagged_on_https():
    findings = headers.audit_headers({"Content-Type": "text/html"}, is_https=True)
    joined = " ".join(_titles(findings))
    assert "Strict-Transport-Security" in joined
    assert "Content-Security-Policy" in joined
    assert "clickjacking" in joined.lower()
    assert "X-Content-Type-Options" in joined


def test_hsts_not_required_on_http():
    findings = headers.audit_headers({}, is_https=False)
    assert not any("Strict-Transport-Security" in f.title for f in findings)


def test_good_headers_produce_no_findings():
    secure = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }
    findings = headers.audit_headers(secure, is_https=True)
    assert findings == []


def test_wildcard_cors_with_credentials_is_high():
    findings = headers.check_cors({
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    })
    assert findings and findings[0].severity.name == "HIGH"


def test_csp_unsafe_inline_flagged():
    findings = headers.check_csp({"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"})
    assert any("unsafe-inline" in f.title for f in findings)


def test_banner_version_disclosure():
    findings = headers.check_banner({"Server": "nginx/1.25.3", "X-Powered-By": "PHP/8.1.0"})
    assert len(findings) == 2


class MultiHeaders(dict):
    """Mimics requests' CaseInsensitiveDict-like get_all for Set-Cookie."""

    def __init__(self, base, cookies):
        super().__init__(base)
        self._cookies = cookies

    def get_all(self, name):
        if name.lower() == "set-cookie":
            return self._cookies
        value = self.get(name)
        return [value] if value is not None else []


def test_cookie_flags_checked():
    hdrs = MultiHeaders({}, ["sid=abc; Path=/"])
    findings = headers.check_cookies(hdrs)
    assert findings
    assert "Secure" in findings[0].title
    assert "HttpOnly" in findings[0].title
    assert "SameSite" in findings[0].title
