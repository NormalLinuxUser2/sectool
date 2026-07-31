from sectool.modules import methods


class FakeResponse:
    def __init__(self, status_code=200, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


class FakeSession:
    def __init__(self, status_by_method, allow=None):
        self.status_by_method = status_by_method
        self.allow = allow

    def request(self, method, url, timeout=None, allow_redirects=False):
        headers = {}
        if method == "OPTIONS" and self.allow is not None:
            headers["Allow"] = self.allow
        return FakeResponse(self.status_by_method.get(method, 405), headers=headers)


def test_enabled_reports_successish_methods():
    session = FakeSession({"GET": 200, "PUT": 201, "DELETE": 405})
    report = methods.audit_methods(session, "https://x/", timeout=5)
    assert "PUT" in report.enabled()
    assert "DELETE" not in report.enabled()


def test_put_and_delete_flagged_high():
    session = FakeSession({"GET": 200, "PUT": 200, "DELETE": 204})
    report = methods.audit_methods(session, "https://x/", timeout=5)
    findings = methods.methods_to_findings(report)
    titles = {f.title: f.severity.name for f in findings}
    assert titles.get("HTTP PUT method enabled") == "HIGH"
    assert titles.get("HTTP DELETE method enabled") == "HIGH"


def test_trace_flagged_medium():
    session = FakeSession({"GET": 200, "TRACE": 200})
    report = methods.audit_methods(session, "https://x/", timeout=5)
    findings = methods.methods_to_findings(report)
    assert any(f.title.startswith("HTTP TRACE") and f.severity.name == "MEDIUM" for f in findings)


def test_allow_header_advertised_methods_reported():
    session = FakeSession({"OPTIONS": 200}, allow="GET, POST, PUT, OPTIONS")
    report = methods.audit_methods(session, "https://x/", timeout=5)
    assert "PUT" in report.advertised
    findings = methods.methods_to_findings(report)
    assert any("advertises HTTP methods" in f.title for f in findings)
    # PUT advertised should surface as a dangerous-method finding even if the
    # active probe was rejected.
    assert any(f.title == "HTTP PUT method enabled" for f in findings)


def test_no_dangerous_methods_gives_info():
    session = FakeSession({"GET": 200, "HEAD": 200, "POST": 200})
    report = methods.audit_methods(session, "https://x/", timeout=5)
    findings = methods.methods_to_findings(report)
    assert any(f.title == "No dangerous HTTP methods detected" for f in findings)
