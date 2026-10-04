import random
import string
import textwrap
from pathlib import Path

import pytest

from agentic_top10.scanner import scan
from agentic_top10.settings import Settings

FIXTURES = Path(__file__).parent / "fixtures"


def run_scan(root: Path, **settings):
    return scan(root, Settings(**settings), base=root)


def rule_ids(result) -> set:
    return {f.rule_id for f in result.findings}


def findings(result, rule_id):
    return [f for f in result.findings if f.rule_id == rule_id]


def fake_token(prefix: str, length: int, alphabet: str = string.ascii_letters + string.digits, seed: int = 7) -> str:
    """Build credential-shaped strings at runtime so no secret-like literal is committed to the repository."""
    rnd = random.Random(seed)
    return prefix + "".join(rnd.choice(alphabet) for _ in range(length))


@pytest.fixture
def project(tmp_path):
    """Write {relative_path: content} into a temp dir and return a function that scans it."""

    def _make(files: dict, **settings):
        for rel, content in files.items():
            path = tmp_path / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
        return run_scan(tmp_path, **settings)

    return _make
