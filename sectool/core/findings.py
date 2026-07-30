from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        try:
            return cls[str(name).strip().upper()]
        except KeyError as exc:
            valid = ", ".join(member.name.lower() for member in cls)
            raise ValueError(f"unknown severity '{name}' (expected one of: {valid})") from exc

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass
class Finding:
    severity: Severity
    title: str
    description: str
    location: Optional[str] = None
    recommendation: Optional[str] = None
    category: Optional[str] = None
    evidence: Optional[str] = None
    reference: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.name
        return data
