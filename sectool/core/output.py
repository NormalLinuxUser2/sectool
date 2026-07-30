from __future__ import annotations

import json
import sys
from typing import Iterable, List, Optional, TextIO

from colorama import Fore, Style
from colorama import init as colorama_init

from .findings import Finding, Severity

colorama_init()

SEVERITY_STYLE = {
    Severity.CRITICAL: Fore.MAGENTA + Style.BRIGHT,
    Severity.HIGH: Fore.RED + Style.BRIGHT,
    Severity.MEDIUM: Fore.YELLOW + Style.BRIGHT,
    Severity.LOW: Fore.CYAN,
    Severity.INFO: Fore.WHITE,
}

SEVERITY_TAG = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED ",
    Severity.LOW: "LOW ",
    Severity.INFO: "INFO",
}

SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


class Reporter:
    def __init__(
        self,
        fmt: str = "text",
        color: bool = True,
        min_severity: Severity = Severity.INFO,
        stream: Optional[TextIO] = None,
    ) -> None:
        self.fmt = fmt
        self.color = color
        self.min_severity = min_severity
        self.stream = stream if stream is not None else sys.stdout

    def report(self, findings: Iterable[Finding], title: Optional[str] = None) -> List[Finding]:
        selected = sorted(
            [f for f in findings if f.severity >= self.min_severity],
            key=lambda finding: finding.severity,
            reverse=True,
        )
        if self.fmt == "json":
            self._render_json(selected, title)
        elif self.fmt == "sarif":
            self._render_sarif(selected, title)
        else:
            self._render_text(selected, title)
        return selected

    def message(self, text: str, style: str = "") -> None:
        if self.fmt != "text":
            return
        self.stream.write(self._paint(text, style) + "\n")

    def _paint(self, text: str, style: str) -> str:
        if not self.color or not style:
            return text
        return f"{style}{text}{Style.RESET_ALL}"

    def _render_json(self, findings: List[Finding], title: Optional[str]) -> None:
        payload = {
            "title": title,
            "summary": self._summary(findings),
            "total": len(findings),
            "findings": [finding.to_dict() for finding in findings],
        }
        self.stream.write(json.dumps(payload, indent=2) + "\n")

    def _render_sarif(self, findings: List[Finding], title: Optional[str]) -> None:
        rules: dict = {}
        results = []
        for finding in findings:
            rule_id = str(finding.metadata.get("rule") or finding.category or "sectool.finding")
            if rule_id not in rules:
                rule = {"id": rule_id, "name": rule_id}
                if finding.category:
                    rule.setdefault("properties", {})["category"] = finding.category
                if finding.reference:
                    rule["helpUri"] = finding.reference
                rules[rule_id] = rule
            result = {
                "ruleId": rule_id,
                "level": SARIF_LEVEL[finding.severity],
                "message": {"text": self._sarif_message(finding)},
                "properties": {"severity": finding.severity.name},
            }
            physical = self._sarif_location(finding.location)
            if physical is not None:
                result["locations"] = [{"physicalLocation": physical}]
            results.append(result)

        document = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "sectool",
                            "informationUri": "https://github.com/NormalLinuxUser2/sectool",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        self.stream.write(json.dumps(document, indent=2) + "\n")

    @staticmethod
    def _sarif_message(finding: Finding) -> str:
        parts = [finding.title, finding.description]
        if finding.recommendation:
            parts.append(f"Fix: {finding.recommendation}")
        return " ".join(part for part in parts if part)

    @staticmethod
    def _sarif_location(location: Optional[str]) -> Optional[dict]:
        if not location:
            return None
        uri = location
        region = None
        head, sep, tail = location.rpartition(":")
        if sep and tail.isdigit():
            uri = head
            region = {"startLine": int(tail)}
        physical = {"artifactLocation": {"uri": uri}}
        if region is not None:
            physical["region"] = region
        return physical

    def _render_text(self, findings: List[Finding], title: Optional[str]) -> None:
        if title:
            self.stream.write("\n" + self._paint(title, Style.BRIGHT) + "\n")
            self.stream.write(self._paint("=" * len(title), Style.DIM) + "\n")
        if not findings:
            self.stream.write(self._paint("No findings.", Fore.GREEN + Style.BRIGHT) + "\n")
            return
        for finding in findings:
            self._render_finding(finding)
        self._render_summary(findings)

    def _render_finding(self, finding: Finding) -> None:
        style = SEVERITY_STYLE[finding.severity]
        tag = self._paint(f"[{SEVERITY_TAG[finding.severity]}]", style)
        self.stream.write(f"\n{tag} {finding.title}\n")
        if finding.location:
            self.stream.write(f"  location: {finding.location}\n")
        if finding.category:
            self.stream.write(f"  category: {finding.category}\n")
        self.stream.write(f"  {finding.description}\n")
        if finding.evidence:
            self.stream.write(f"  evidence: {finding.evidence}\n")
        if finding.recommendation:
            self.stream.write(self._paint(f"  fix: {finding.recommendation}", Fore.GREEN) + "\n")
        if finding.reference:
            self.stream.write(f"  ref: {finding.reference}\n")

    def _summary(self, findings: List[Finding]) -> dict:
        counts = {member.name: 0 for member in Severity}
        for finding in findings:
            counts[finding.severity.name] += 1
        return counts

    def _render_summary(self, findings: List[Finding]) -> None:
        counts = self._summary(findings)
        parts = []
        for severity in sorted(Severity, reverse=True):
            count = counts[severity.name]
            if count:
                parts.append(self._paint(f"{count} {severity.label}", SEVERITY_STYLE[severity]))
        rendered = ", ".join(parts) if parts else "none"
        self.stream.write("\n" + self._paint("Summary: ", Style.BRIGHT) + rendered)
        self.stream.write(f"  (total {len(findings)})\n")
