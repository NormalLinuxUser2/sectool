import pytest

from sectool.core.findings import Finding, Severity


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO


def test_severity_from_name_case_insensitive():
    assert Severity.from_name("high") == Severity.HIGH
    assert Severity.from_name("CRITICAL") == Severity.CRITICAL
    assert Severity.from_name(" Medium ") == Severity.MEDIUM


def test_severity_from_name_invalid():
    with pytest.raises(ValueError):
        Severity.from_name("nope")


def test_finding_to_dict_serializes_severity_name():
    finding = Finding(Severity.HIGH, "title", "desc", location="a.py:1")
    data = finding.to_dict()
    assert data["severity"] == "HIGH"
    assert data["title"] == "title"
    assert data["location"] == "a.py:1"
    assert data["metadata"] == {}
