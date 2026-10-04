"""Helpers for loading config files (JSON with comments, YAML, TOML) and locating keys by line."""
from __future__ import annotations

import json
import re
from typing import Any, List, Optional

import yaml


def load_jsonc(text: str) -> Any:
    """Parse JSON, tolerating // and /* */ comments and trailing commas (VS Code style)."""
    try:
        return json.loads(text)
    except ValueError:
        pass
    out: List[str] = []
    i, n, in_str = 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return json.loads(re.sub(r",(\s*[}\]])", r"\1", "".join(out)))


def load_yaml(text: str) -> Any:
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        return None


def load_toml(text: str) -> Any:
    try:
        import tomllib  # type: ignore[import-not-found]
    except ModuleNotFoundError:  # Python < 3.11
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ModuleNotFoundError:
            return None
    try:
        return tomllib.loads(text)
    except Exception:  # noqa: BLE001 - any TOML error means "unparseable"
        return None


def load_structured(text: str, suffix: str) -> Any:
    suffix = suffix.lower()
    if suffix in (".json", ".jsonc"):
        try:
            return load_jsonc(text)
        except ValueError:
            return None
    if suffix in (".yaml", ".yml"):
        return load_yaml(text)
    if suffix == ".toml":
        return load_toml(text)
    return None


def find_line(lines: List[str], pattern: str, start: int = 1, default: Optional[int] = None) -> Optional[int]:
    """1-based line of the first regex match at or after `start`."""
    rx = re.compile(pattern)
    for i in range(max(1, start), len(lines) + 1):
        if rx.search(lines[i - 1]):
            return i
    return default


def key_line(lines: List[str], key: str, start: int = 1, default: int = 1) -> int:
    """Line of a JSON/YAML/TOML key, searching from `start`."""
    k = re.escape(str(key))
    return find_line(lines, rf"""(["']{k}["']\s*[:=]|^\s*-?\s*{k}\s*[:=]|\[[\w."-]*\b{k}\b[\w."-]*\])""", start,
                     default) or default


def as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [dict(v, name=v.get("name", k)) if isinstance(v, dict) else v for k, v in value.items()]
    return [value]
