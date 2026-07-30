import requests

from sectool.modules import fuzz


class FakeResponse:
    def __init__(self, status_code=200, body=b"", headers=None):
        self.status_code = status_code
        self.content = body
        self.headers = headers or {}


class FakeSession:
    def __init__(self, routes, default=None, error_paths=()):
        self.routes = routes
        self.default = default or FakeResponse(404, b"not found")
        self.error_paths = set(error_paths)
        self.calls = []

    def request(self, method, url, timeout=None, data=None, allow_redirects=True):
        self.calls.append(url)
        for needle in self.error_paths:
            if needle in url:
                raise requests.ConnectionError("boom")
        for needle, response in self.routes.items():
            if needle in url:
                return response
        return self.default


def test_build_url_keyword_and_append():
    assert fuzz.build_url("http://h/FUZZ", "admin") == "http://h/admin"
    assert fuzz.build_url("http://h", "admin") == "http://h/admin"
    assert fuzz.build_url("http://h/", "admin") == "http://h/admin"


def test_expand_words_adds_extensions_and_dedupes():
    words = fuzz.expand_words(["a", "a"], [".php", "bak"])
    assert words == ["a", "a.php", "a.bak"]


def test_run_fuzz_reports_non_baseline_hits():
    session = FakeSession(
        routes={"/admin": FakeResponse(200, b"secret panel")},
        default=FakeResponse(404, b"nope"),
    )
    result = fuzz.run_fuzz(
        session, "http://h", ["admin", "missing"], threads=2,
        filters=fuzz.FuzzFilters(filter_codes={404}),
    )
    words = {hit.word for hit in result.hits}
    assert "admin" in words
    assert "missing" not in words


def test_run_fuzz_filters_wildcard_baseline():
    session = FakeSession(routes={}, default=FakeResponse(200, b"same body"))
    result = fuzz.run_fuzz(session, "http://h", ["admin", "login"], threads=2)
    assert result.baseline_status == 200
    assert result.hits == []


def test_run_fuzz_counts_errors():
    session = FakeSession(
        routes={"/ok": FakeResponse(200, b"ok")},
        default=FakeResponse(404),
        error_paths=("/boom",),
    )
    result = fuzz.run_fuzz(session, "http://h", ["ok", "boom"], threads=2, calibrate=False)
    assert result.errors == 1
    assert any(h.word == "ok" for h in result.hits)


def test_sensitive_path_becomes_high_severity_finding():
    session = FakeSession(
        routes={"/.git/config": FakeResponse(200, b"[core]")},
        default=FakeResponse(404),
    )
    result = fuzz.run_fuzz(session, "http://h", [".git/config"], calibrate=False)
    findings = fuzz.hits_to_findings(result)
    assert findings
    top = findings[0]
    assert top.category == "content-discovery"
    assert top.severity.name == "CRITICAL"


def test_filters_accept_logic():
    filters = fuzz.FuzzFilters(match_codes={200, 301}, filter_sizes={0})
    assert filters.accepts(200, 12)
    assert not filters.accepts(404, 12)
    assert not filters.accepts(200, 0)


def test_word_count_filter_matches_expected_hit():
    session = FakeSession(
        routes={"/rich": FakeResponse(200, b"alpha beta gamma")},
        default=FakeResponse(200, b"noise"),
    )
    result = fuzz.run_fuzz(
        session, "http://h", ["rich", "other"], threads=2, calibrate=False,
        filters=fuzz.FuzzFilters(match_words={3}),
    )
    assert {hit.word for hit in result.hits} == {"rich"}
    assert result.hits[0].words == 3


def test_response_words_counts_tokens():
    assert fuzz._response_words(FakeResponse(200, b"one two three")) == 3
    assert fuzz._response_words(FakeResponse(200, b"")) == 0


def test_is_directory_detection():
    redirect = fuzz.FuzzHit("admin", "http://h/admin", 301, 0, redirect="http://h/admin/")
    assert fuzz._is_directory(redirect)
    extensionless = fuzz.FuzzHit("blog", "http://h/blog", 200, 10)
    assert fuzz._is_directory(extensionless)
    a_file = fuzz.FuzzHit("index.html", "http://h/index.html", 200, 10)
    assert not fuzz._is_directory(a_file)


def test_recursion_descends_into_directories():
    session = FakeSession(
        routes={
            "/admin/secret": FakeResponse(200, b"top secret"),
            "/admin": FakeResponse(200, b"admin dir"),
        },
        default=FakeResponse(404),
    )
    result = fuzz.run_fuzz(
        session, "http://h", ["admin", "secret"], threads=2, calibrate=False,
        filters=fuzz.FuzzFilters(filter_codes={404}), recursion_depth=1,
    )
    urls = {hit.url for hit in result.hits}
    assert "http://h/admin/secret" in urls
    assert result.bases_scanned == 2


def test_recursion_disabled_by_default():
    session = FakeSession(
        routes={
            "/admin/secret": FakeResponse(200, b"top secret"),
            "/admin": FakeResponse(200, b"admin dir"),
        },
        default=FakeResponse(404),
    )
    result = fuzz.run_fuzz(
        session, "http://h", ["admin", "secret"], threads=2, calibrate=False,
        filters=fuzz.FuzzFilters(filter_codes={404}),
    )
    urls = {hit.url for hit in result.hits}
    assert "http://h/admin/secret" not in urls
    assert result.bases_scanned == 1
