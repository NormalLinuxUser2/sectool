import io
import json

from sectool.core.findings import Finding, Severity
from sectool.core.output import Reporter


def test_text_report_contains_title_and_finding():
    buffer = io.StringIO()
    reporter = Reporter(fmt="text", color=False, stream=buffer)
    reporter.report(
        [Finding(Severity.HIGH, "Hardcoded secret", "a description", location="a.py:1")],
        title="Scan",
    )
    out = buffer.getvalue()
    assert "Scan" in out
    assert "Hardcoded secret" in out
    assert "HIGH" in out


def test_text_report_no_findings():
    buffer = io.StringIO()
    reporter = Reporter(fmt="text", color=False, stream=buffer)
    reporter.report([], title="Scan")
    assert "No findings." in buffer.getvalue()


def test_json_report_is_valid():
    buffer = io.StringIO()
    reporter = Reporter(fmt="json", color=False, stream=buffer)
    reporter.report([Finding(Severity.LOW, "t", "d")], title="x")
    payload = json.loads(buffer.getvalue())
    assert payload["findings"][0]["severity"] == "LOW"
    assert payload["summary"]["LOW"] == 1
    assert payload["total"] == 1


def test_min_severity_filter():
    buffer = io.StringIO()
    reporter = Reporter(fmt="text", color=False, min_severity=Severity.HIGH, stream=buffer)
    shown = reporter.report([
        Finding(Severity.LOW, "low", "d"),
        Finding(Severity.CRITICAL, "crit", "d"),
    ])
    assert len(shown) == 1
    assert shown[0].severity == Severity.CRITICAL


def test_findings_sorted_by_severity_descending():
    buffer = io.StringIO()
    reporter = Reporter(fmt="text", color=False, stream=buffer)
    shown = reporter.report([
        Finding(Severity.LOW, "low", "d"),
        Finding(Severity.CRITICAL, "crit", "d"),
        Finding(Severity.MEDIUM, "med", "d"),
    ])
    assert [f.severity for f in shown] == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]
