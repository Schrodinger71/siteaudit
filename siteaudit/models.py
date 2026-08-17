"""Модели данных аудита: находки, результаты модулей, итоговый отчёт."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    OK = "ok"

    @property
    def penalty(self) -> float:
        return _PENALTY[self]

    @property
    def label(self) -> str:
        return _LABEL[self]

    @property
    def rank(self) -> int:
        """Чем меньше, тем важнее — используется для сортировки."""
        return _RANK[self]

    @property
    def color(self) -> str:
        return _COLOR[self]


_PENALTY: dict[Severity, float] = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH: 12.0,
    Severity.MEDIUM: 6.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.0,
    Severity.OK: 0.0,
}

_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "КРИТИЧНО",
    Severity.HIGH: "ВАЖНО",
    Severity.MEDIUM: "СРЕДНЕ",
    Severity.LOW: "МЕЛОЧЬ",
    Severity.INFO: "ИНФО",
    Severity.OK: "ОК",
}

_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.OK: 5,
}

_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "blue",
    Severity.OK: "green",
}


@dataclass
class Finding:
    """Одна находка аудита."""

    id: str
    title: str
    severity: Severity
    detail: str = ""
    recommendation: str = ""
    evidence: list[str] = field(default_factory=list)
    weight: float = 1.0

    @property
    def penalty(self) -> float:
        return self.severity.penalty * self.weight

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "penalty": round(self.penalty, 2),
        }


@dataclass
class Tech:
    """Обнаруженная технология."""

    name: str
    category: str
    version: str | None = None
    confidence: int = 50
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass
class ModuleResult:
    """Результат работы одного модуля аудита."""

    key: str
    title: str
    weight: float = 1.0
    findings: list[Finding] = field(default_factory=list)
    facts: list[tuple[str, str]] = field(default_factory=list)
    error: str | None = None

    def add(
        self,
        id: str,
        title: str,
        severity: Severity,
        detail: str = "",
        recommendation: str = "",
        evidence: list[str] | None = None,
        weight: float = 1.0,
    ) -> Finding:
        f = Finding(
            id=id,
            title=title,
            severity=severity,
            detail=detail,
            recommendation=recommendation,
            evidence=evidence or [],
            weight=weight,
        )
        self.findings.append(f)
        return f

    def ok(self, id: str, title: str, detail: str = "") -> Finding:
        return self.add(id, title, Severity.OK, detail)

    def fact(self, name: str, value: Any) -> None:
        self.facts.append((name, "—" if value is None or value == "" else str(value)))

    @property
    def score(self) -> int:
        if self.error:
            return 0
        total = sum(f.penalty for f in self.findings)
        return max(0, min(100, round(100 - total)))

    @property
    def problems(self) -> list[Finding]:
        out = [f for f in self.findings if f.severity not in (Severity.OK, Severity.INFO)]
        return sorted(out, key=lambda f: (f.severity.rank, f.id))

    @property
    def notes(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.INFO]

    @property
    def passed(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.OK]

    def counts(self) -> dict[str, int]:
        c: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "score": self.score,
            "error": self.error,
            "counts": self.counts(),
            "facts": [{"name": n, "value": v} for n, v in self.facts],
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class Report:
    """Итоговый отчёт по одному сайту."""

    target: str
    final_url: str = ""
    started_at: datetime = field(default_factory=datetime.now)
    duration: float = 0.0
    modules: list[ModuleResult] = field(default_factory=list)
    techs: list[Tech] = field(default_factory=list)
    error: str | None = None

    @property
    def score(self) -> int:
        usable = [m for m in self.modules if not m.error]
        if not usable:
            return 0
        total_w = sum(m.weight for m in usable) or 1.0
        return round(sum(m.score * m.weight for m in usable) / total_w)

    @property
    def grade(self) -> str:
        s = self.score
        for threshold, letter in ((90, "A"), (80, "B"), (70, "C"), (55, "D"), (35, "E")):
            if s >= threshold:
                return letter
        return "F"

    def all_problems(self) -> list[Finding]:
        out: list[Finding] = []
        for m in self.modules:
            out.extend(m.problems)
        return sorted(out, key=lambda f: (f.severity.rank, f.id))

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "final_url": self.final_url,
            "started_at": self.started_at.isoformat(timespec="seconds"),
            "duration_sec": round(self.duration, 2),
            "score": self.score,
            "grade": self.grade,
            "error": self.error,
            "technologies": [t.to_dict() for t in self.techs],
            "modules": [m.to_dict() for m in self.modules],
        }
