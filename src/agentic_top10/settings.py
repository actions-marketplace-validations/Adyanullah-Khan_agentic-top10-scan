"""Scan settings: CLI options merged with an optional .agentic-top10.yml file, plus inline suppressions."""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .configfiles import load_yaml
from .models import Severity
from .rules import RULES

SETTINGS_FILES = (".agentic-top10.yml", ".agentic-top10.yaml")
SUPPRESS_RE = re.compile(r"agentic-top10:\s*ignore(?:\[([^\]]+)\])?", re.I)


@dataclass
class Settings:
    exclude: List[str] = field(default_factory=list)
    disable: List[str] = field(default_factory=list)
    severity_overrides: Dict[str, Severity] = field(default_factory=dict)
    fail_on: Optional[Severity] = Severity.HIGH
    min_severity: Severity = Severity.INFO
    online: bool = False
    include_tests: bool = False

    def is_excluded(self, *rels: str) -> bool:
        """gitignore-like matching: a pattern without '/' matches any path component; others match from the root."""
        for rel in rels:
            parts = rel.split("/")
            for pattern in self.exclude:
                pat = pattern.strip().rstrip("/")
                if pat.startswith("./"):
                    pat = pat[2:]
                if not pat:
                    continue
                if "/" not in pat and any(fnmatch.fnmatch(part, pat) for part in parts):
                    return True
                if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat + "/*") or rel.startswith(pat + "/"):
                    return True
                if pat.startswith("**/") and (fnmatch.fnmatch(rel, pat[3:]) or fnmatch.fnmatch(rel, pat[3:] + "/*")
                                              or any(fnmatch.fnmatch("/".join(parts[i:]), pat[3:])
                                                     for i in range(len(parts)))):
                    return True
        return False


def parse_fail_on(value: str) -> Optional[Severity]:
    return None if str(value).strip().lower() in ("none", "never", "off", "") else Severity.parse(value)


def load_settings_file(path: Path, settings: Settings) -> List[str]:
    """Merge a settings file into `settings`. Returns warnings."""
    warnings: List[str] = []
    try:
        data = load_yaml(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return [f"could not read {path}: {exc}"]
    if data is None:
        return warnings
    if not isinstance(data, dict):
        return [f"{path}: expected a mapping at the top level"]
    settings.exclude.extend(str(p) for p in data.get("exclude") or [])
    for rule_id in data.get("disable") or []:
        if str(rule_id) not in RULES:
            warnings.append(f"{path}: unknown rule id in disable: {rule_id}")
        settings.disable.append(str(rule_id))
    for rule_id, level in (data.get("severity") or {}).items():
        try:
            settings.severity_overrides[str(rule_id)] = Severity.parse(level)
        except ValueError as exc:
            warnings.append(f"{path}: {exc}")
    if "fail_on" in data:
        settings.fail_on = parse_fail_on(str(data["fail_on"]))
    if "min_severity" in data:
        settings.min_severity = Severity.parse(str(data["min_severity"]))
    if "include_tests" in data:
        settings.include_tests = bool(data["include_tests"])
    return warnings


def is_suppressed(lines: List[str], line: int, rule_id: str) -> bool:
    for idx in (line - 1, line - 2):
        if 0 <= idx < len(lines):
            m = SUPPRESS_RE.search(lines[idx])
            if m:
                if not m.group(1):
                    return True
                ids = {part.strip().upper() for part in m.group(1).split(",")}
                if rule_id.upper() in ids:
                    return True
    return False
