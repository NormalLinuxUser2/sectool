import datetime

from sectool.modules import probe


class FakeResponse:
    def __init__(self, status_code=200, body=b"", headers=None, elapsed_ms=None):
        self.status_code = status_code
        self.content = body
        self.headers = headers or {}
        if elapsed_ms is not None:
            self.elapsed = datetime.timedelta(milliseconds=elapsed_ms)


class FakeSession:
    def __init__(self, routes, default=None):
        self.routes = routes
        self.default = default or FakeResponse(404)

    def request(self, method, url, timeout=None, allow_redirects=False):
        for needle, response in self.routes.items():
            if needle in url:
                return response
        return self.default


def test_fingerprint_from_headers_cookies_and_body():
    headers = {"Server": "nginx/1.25.1", "X-Powered-By": "PHP/8.2",
               "Set-Cookie": "PHPSESSID=abc; path=/"}
    tech = probe.fingerprint(headers, "<html>wp-content/themes</html>")
    assert "Nginx" in tech
    assert "PHP" in tech
    assert "WordPress" in tech
    # PHP should not be duplicated (header + cookie)
    assert tech.count("PHP") == 1


def test_probe_follows_redirect_chain():
    session = FakeSession(routes={
        "http://site/": FakeResponse(301, headers={"Location": "https://site/"}),
        "https://site/": FakeResponse(200, b"<title>Home</title>",
                                      headers={"Content-Type": "text/html"}),
    })
    info = probe.probe_url(session, "http://site/", timeout=5)
    assert info.status == 200
    assert info.final_url == "https://site/"
    assert len(info.chain) == 2
    assert info.title == "Home"


def test_probe_flags_cleartext_http():
    session = FakeSession(routes={"http://site/": FakeResponse(200, b"hi")})
    info = probe.probe_url(session, "http://site/", timeout=5)
    findings = probe.probe_to_findings(info)
    assert any("cleartext HTTP" in f.title for f in findings)


def test_probe_reports_http_to_https_upgrade():
    session = FakeSession(routes={
        "http://site/": FakeResponse(308, headers={"Location": "https://site/"}),
        "https://site/": FakeResponse(200, b"ok"),
    })
    info = probe.probe_url(session, "http://site/", timeout=5)
    findings = probe.probe_to_findings(info)
    assert any("redirects to HTTPS" in f.title for f in findings)


def test_probe_detects_directory_listing():
    session = FakeSession(routes={"https://site/": FakeResponse(
        200, b"<title>Index of /files</title>", headers={"Content-Type": "text/html"})})
    info = probe.probe_url(session, "https://site/", timeout=5)
    findings = probe.probe_to_findings(info)
    assert any(f.title == "Directory listing enabled" for f in findings)


def test_probe_error_raises():
    import requests

    class BoomSession:
        def request(self, *a, **k):
            raise requests.ConnectionError("no route")

    info = probe.probe_url(BoomSession(), "https://x/", timeout=1)
    assert info.error
    try:
        probe.probe_to_findings(info)
    except Exception as exc:
        assert "failed" in str(exc)
    else:
        raise AssertionError("expected SectoolError")
