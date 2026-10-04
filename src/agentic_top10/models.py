"""Core data types shared by every analyzer."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import List, Optional, Tuple


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            choices = ", ".join(s.label for s in cls)
            raise ValueError(f"unknown severity {value!r}; expected one of: {choices}") from None

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    categories: Tuple[str, ...]
    severity: Severity
    summary: str
    remediation: str
    precision: str = "medium"  # SARIF precision: very-high, high, medium, low

    @property
    def primary_category(self) -> str:
        return self.categories[0]


@dataclass
class Finding:
    rule_id: str
    path: str
    line: int
    message: str
    severity: Severity
    column: int = 1
    evidence: str = ""
    categories: Tuple[str, ...] = ()

    def fingerprint(self) -> str:
        basis = f"{self.rule_id}|{self.path}|{' '.join(self.evidence.split())}|{self.message}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]

    def sort_key(self):
        return (-int(self.severity), self.path, self.line, self.rule_id)


@dataclass
class ToolInfo:
    """An agent tool discovered in source code (used by project-level checks)."""

    path: str
    line: int
    name: str
    logs: bool


@dataclass
class ProjectState:
    """Facts gathered across files, consumed by project-level checks."""

    root: Path
    is_agent_project: bool = False
    tools: List[ToolInfo] = field(default_factory=list)
    tracing_signals: List[str] = field(default_factory=list)
    lockfiles: List[str] = field(default_factory=list)
    manifests: List[str] = field(default_factory=list)
    pinned: List[Tuple[str, str, str, str, int]] = field(default_factory=list)  # ecosystem, name, version, path, line


class FileContext:
    """A file being scanned, plus the sink that collects its findings."""

    def __init__(self, path: Path, rel: str, text: str, kind: str, project: ProjectState):
        self.path = path
        self.rel = rel
        self.text = text
        self.kind = kind
        self.project = project
        self.lines = text.splitlines()
        self.findings: List[Finding] = []

    @property
    def name(self) -> str:
        return self.path.name

    def line_text(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1]
        return ""

    def line_of_offset(self, offset: int) -> int:
        return self.text.count("\n", 0, offset) + 1

    def report(
        self,
        rule_id: str,
        line: int,
        message: str,
        severity: Optional[Severity] = None,
        column: int = 1,
        evidence: Optional[str] = None,
    ) -> None:
        from .rules import RULES

        rule = RULES[rule_id]
        line = max(1, int(line or 1))
        if evidence is None:
            evidence = self.line_text(line).strip()
        self.findings.append(
            Finding(
                rule_id=rule_id,
                path=self.rel,
                line=line,
                column=max(1, int(column or 1)),
                message=message,
                severity=rule.severity if severity is None else severity,
                evidence=evidence,
                categories=rule.categories,
            )
        )
