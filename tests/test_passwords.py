import hashlib

from sectool.modules import passwords


def test_entropy_increases_with_complexity():
    assert passwords.entropy_bits("aaaa") < passwords.entropy_bits("aA1!aA1!aA1!")


def test_entropy_empty_is_zero():
    assert passwords.entropy_bits("") == 0.0


def test_strength_label_buckets():
    assert passwords.strength_label(10) == "very weak"
    assert passwords.strength_label(200) == "very strong"


def test_common_password_detected():
    issues = passwords.detect_patterns("password")
    assert any("common" in issue for issue in issues)


def test_sequential_characters_detected():
    issues = passwords.detect_patterns("abcdef")
    assert any("sequential" in issue for issue in issues)


def test_repeated_characters_detected():
    issues = passwords.detect_patterns("aaaa1234")
    assert any("repeated" in issue for issue in issues)


def test_hibp_uses_k_anonymity(monkeypatch):
    password = "password"
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]

    class FakeResponse:
        text = f"0000000000000000000000000000000000A:7\n{suffix}:42"

        def raise_for_status(self):
            return None

    captured = {}

    def fake_get(url, headers=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        return FakeResponse()

    monkeypatch.setattr(passwords.requests, "get", fake_get)
    count = passwords.check_hibp(password)

    assert count == 42
    assert captured["url"] == passwords.HIBP_RANGE_URL + prefix
    assert suffix not in captured["url"]
    assert digest not in captured["url"]
    assert captured["headers"]["Add-Padding"] == "true"


def test_hibp_not_found(monkeypatch):
    class FakeResponse:
        text = "0000000000000000000000000000000000A:7"

        def raise_for_status(self):
            return None

    monkeypatch.setattr(passwords.requests, "get", lambda *a, **k: FakeResponse())
    assert passwords.check_hibp("a-very-unique-password") == 0
