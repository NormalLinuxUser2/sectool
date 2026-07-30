import io
import json

from sectool.core.findings import Finding, Severity
from sectool.core.output import Reporter


def _render(findings, title="Scan"):
    buffer = io.StringIO()
    reporter = Reporter(fmt="sarif", color=False, stream=buffer)
    reporter.report(findings, title=title)
    return json.loads(buffer.getvalue())


def test_sarif_shape_is_valid():
    doc = _render([Finding(Severity.HIGH, "t", "d", location="a.py:12", category="secret",
                           metadata={"rule": "SECRET-GENERIC"})])
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "sectool"
    assert run["results"][0]["ruleId"] == "SECRET-GENERIC"
    assert run["results"][0]["level"] == "error"


def test_sarif_location_parses_line_number():
    doc = _render([Finding(Severity.MEDIUM, "t", "d", location="src/app.py:42")])
    physical = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "src/app.py"
    assert physical["region"]["startLine"] == 42


def test_sarif_level_mapping():
    doc = _render([
        Finding(Severity.CRITICAL, "c", "d"),
        Finding(Severity.MEDIUM, "m", "d"),
        Finding(Severity.INFO, "i", "d"),
    ])
    levels = [r["level"] for r in doc["runs"][0]["results"]]
    assert levels == ["error", "warning", "note"]


def test_sarif_network_location_has_no_region():
    doc = _render([Finding(Severity.LOW, "t", "d", location="https://example.com/path")])
    physical = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "https://example.com/path"
    assert "region" not in physical


def test_message_suppressed_in_sarif():
    buffer = io.StringIO()
    reporter = Reporter(fmt="sarif", color=False, stream=buffer)
    reporter.message("should not appear")
    reporter.report([], title="x")
    assert "should not appear" not in buffer.getvalue()
