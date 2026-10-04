"""Text-level detectors shared by several analyzers: secrets, hidden Unicode, prompt phrases, URLs."""
from __future__ import annotations

import math
import re
import unicodedata
from typing import Iterator, List, Optional, Tuple
from urllib.parse import urlparse

# ── Secrets ──────────────────────────────────────────────────────────────────

KNOWN_SECRET_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("Anthropic API key", re.compile(r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{60,}")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{16,}T3BlbkFJ[A-Za-z0-9_\-]{16,}")),
    ("OpenAI project key", re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{40,}")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Stripe live key", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
    ("Groq API key", re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----")),
]

GENERIC_SECRET_RE = re.compile(
    r"(?i)(?P<key>[A-Za-z0-9_.\-]*(?:api[_\-]?key|secret|passw(?:or)?d|token|access[_\-]?key|private[_\-]?key"
    r"|auth[_\-]?key|credential)[A-Za-z0-9_.\-]*)[\"']?\s*(?::=|=>|[:=])\s*[\"'](?P<value>[^\"'\s]{16,200})[\"']"
)
_NON_SECRET_KEY_RE = re.compile(
    r"(?i)(max|min|num|count|limit|size|length|budget|usage|_tokens$|^tokens|tokenizer|token_?(count|limit|type|url|"
    r"endpoint|file|path|name|uri|id_?key|header)|_(url|uri|path|file|name|env|var|field|id)$|^(token|secret)_?(url|"
    r"uri|path|file|name)|password_(policy|reset|hash|field|label|regex))"
)
_PLACEHOLDER_RE = re.compile(
    r"(?i)(your|example|sample|dummy|fake|test|placeholder|changeme|change_me|xxxx|\*{3}|<|>|\$\{|\{\{|%\(|"
    r"os\.environ|getenv|process\.env|redacted|replace|insert|todo|none|null|undefined|secret_?name|"
    r"\.\.\.|^sk-\.\.\.|abc123|123456|password|^\[|^\$)"
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


_SECRET_HINT_RE = re.compile(r"(?i)(api[_\-]?key|secret|passw|token|access[_\-]?key|private[_\-]?key|auth[_\-]?key|"
                             r"credential)")


def _generic_candidates(text: str) -> Iterator["re.Match[str]"]:
    # The generic pattern backtracks badly over long text, so only run it on lines that could match.
    offset = 0
    for line in text.splitlines(keepends=True):
        if ("'" in line or '"' in line) and _SECRET_HINT_RE.search(line):
            for m in GENERIC_SECRET_RE.finditer(line):
                yield offset, m
        offset += len(line)


def iter_secrets(text: str) -> Iterator[Tuple[int, int, str, str]]:
    """Yield (start, end, kind, matched_value) for credential-looking strings."""
    seen = []
    for kind, pattern in KNOWN_SECRET_PATTERNS:
        for m in pattern.finditer(text):
            seen.append((m.start(), m.end()))
            yield m.start(), m.end(), kind, m.group(0)
    for base, m in _generic_candidates(text):
        start, end = base + m.start("value"), base + m.end("value")
        if any(s <= start < e for s, e in seen):
            continue
        key, value = m.group("key"), m.group("value")
        if _NON_SECRET_KEY_RE.search(key) or _PLACEHOLDER_RE.search(value):
            continue
        if not (re.search(r"[A-Za-z]", value) and re.search(r"\d", value)):
            continue
        if shannon_entropy(value) < 3.5:
            continue
        yield start, end, f"credential assigned to '{key}'", value


def redact(text: str) -> str:
    """Mask every credential-looking value in text (used on all evidence strings)."""
    spans = sorted(((s, e) for s, e, _, _ in iter_secrets(text)), reverse=True)
    for start, end in spans:
        value = text[start:end]
        text = text[:start] + value[:4] + "…[REDACTED]" + text[end:]
    return text


# ── Hidden Unicode ────────────────────────────────────────────────────────────

_HIDDEN_RANGES = [
    (0x200B, 0x200F),  # zero-width space/joiners, LRM/RLM
    (0x202A, 0x202E),  # bidi embeddings/overrides
    (0x2060, 0x2064),  # word joiner, invisible operators
    (0x2066, 0x2069),  # bidi isolates
    (0x180E, 0x180E),  # Mongolian vowel separator
    (0xFEFF, 0xFEFF),  # zero-width no-break space (BOM mid-text)
    (0xE0000, 0xE007F),  # Unicode tag characters (ASCII smuggling)
]
_VARIATION_SUPPLEMENT = (0xE0100, 0xE01EF)
HIDDEN_CHAR_RE = re.compile("[" + "".join(f"{chr(lo)}-{chr(hi)}" for lo, hi in _HIDDEN_RANGES + [_VARIATION_SUPPLEMENT])
                            + "]")


def _is_hidden(cp: int) -> bool:
    return any(lo <= cp <= hi for lo, hi in _HIDDEN_RANGES)


def find_hidden_unicode(line: str, is_first_line: bool = False) -> Optional[str]:
    """Return a description of hidden characters on the line, or None."""
    if not HIDDEN_CHAR_RE.search(line):
        return None
    found = []
    tag_payload = []
    vs_supp = 0
    for idx, ch in enumerate(line):
        cp = ord(ch)
        if cp == 0xFEFF and is_first_line and idx == 0:
            continue
        if _VARIATION_SUPPLEMENT[0] <= cp <= _VARIATION_SUPPLEMENT[1]:
            vs_supp += 1
            continue
        if cp in (0x200C, 0x200D):
            # Joiners are legitimate inside emoji sequences and many non-Latin scripts.
            neighbours = (line[idx - 1] if idx else "") + (line[idx + 1] if idx + 1 < len(line) else "")
            if any(ord(c) > 0x7F for c in neighbours):
                continue
        if _is_hidden(cp):
            if 0xE0020 <= cp <= 0xE007E:
                tag_payload.append(chr(cp - 0xE0000))
            name = unicodedata.name(ch, "TAG CHARACTER" if cp >= 0xE0000 else "UNNAMED")
            label = f"U+{cp:04X} {name}"
            if label not in found:
                found.append(label)
    if vs_supp >= 2:
        found.append(f"{vs_supp} variation-selector-supplement characters (possible emoji smuggling)")
    if not found:
        return None
    desc = ", ".join(found[:4]) + (" …" if len(found) > 4 else "")
    if tag_payload:
        desc += f"; hidden text decodes to: {''.join(tag_payload)[:120]!r}"
    return desc


# ── Prompt phrase detectors ───────────────────────────────────────────────────

INJECTION_PATTERNS = [
    (re.compile(r"(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,40}?\b(all\s+)?(previous|prior|above|earlier|"
                r"preceding|original|initial|system)\b[^.\n]{0,20}?\b(instructions?|prompts?|rules|directions|"
                r"guidelines|directives)\b"), "instruction-override phrase"),
    (re.compile(r"(?i)\byou\s+are\s+now\s+(in\s+)?(developer|dan|jailbreak|god|unrestricted|admin|debug)\s*mode\b|"
                r"\bdo\s+anything\s+now\b"), "jailbreak persona"),
    (re.compile(r"(?i)\b(reveal|print|output|repeat|leak|dump)\b[^.\n]{0,30}?\b(your|the)\s+(system\s+prompt|hidden\s+"
                r"instructions|initial\s+instructions|developer\s+message)\b"), "system-prompt extraction request"),
    (re.compile(r"<\|(im_start|im_end|endoftext|system)\|>|\[/?INST\]|<<SYS>>"), "chat-template control tokens"),
    (re.compile(r"(?i)\b(new|updated|revised)\s+(system\s+)?instructions\s*:"), "injected instruction header"),
    (re.compile(r"(?i)\b(bypass|disable|turn\s+off|ignore)\b[^.\n]{0,20}?\b(safety|guardrails?|content\s+filters?|"
                r"security\s+checks?)\b"), "guardrail-bypass phrase"),
]

TOOL_POISONING_PATTERNS = [
    (re.compile(r"(?i)<\s*important\s*>"), "hidden <IMPORTANT> directive"),
    (re.compile(r"(?i)\b(do\s+not|don't|never)\s+(tell|inform|mention|reveal|show|notify)\b[^.\n]{0,30}?\b(the\s+)?"
                r"(user|human)\b"), "instruction to hide behaviour from the user"),
    (re.compile(r"(?i)\b(before|prior\s+to)\s+(using|calling|invoking)\s+(this|any|the)\s+tool\b[^.\n]{0,80}?\b(read|"
                r"send|include|pass|fetch)\b"), "pre-call side instruction"),
    (re.compile(r"(?i)(~/\.ssh|id_rsa|\.aws/credentials|\.env\b|mcp\.json|\.cursor/|private\s+key)"),
     "reference to sensitive files"),
]

EXFIL_PATTERNS = [
    (re.compile(r"!\[[^\]]*\]\(\s*https?://[^)\s]*(\{\{?|\$\{|%s|\{[A-Za-z_]+\})[^)]*\)"),
     "markdown image with a templated URL"),
    (re.compile(r"(?i)\b(send|post|upload|forward|transmit|exfiltrate|leak)\b[^.\n]{0,60}?\b(to|at)\s+https?://"),
     "instruction to send data to a URL"),
    (re.compile(r"(?i)\b(append|include|encode|embed)\b[^.\n]{0,40}?\b(conversation|chat\s+history|secrets?|api\s+"
                r"keys?|credentials|passwords?|tokens?)\b[^.\n]{0,40}?\b(url|link|query\s+string|image)\b"),
     "instruction to encode sensitive data into a link"),
]

DECEPTION_PATTERNS = [
    (re.compile(r"(?i)\b(never|do\s+not|don't)\s+(reveal|disclose|admit|mention|say|tell\s+(anyone|the\s+user|users))"
                r"\b[^.\n]{0,25}?\byou\s*(are|'re)\s+(an?\s+)?(ai|bot|robot|language\s+model|llm|assistant|automated|"
                r"machine)\b"), "hide that it is an AI"),
    (re.compile(r"(?i)\b(pretend|claim|insist|act\s+as\s+if)\b[^.\n]{0,20}?\b(to\s+be|you\s+are|you're)\s+(a\s+)?(real"
                r"\s+)?(human|person)\b"), "pretend to be human"),
    (re.compile(r"(?i)\byou\s+are\s+a\s+real\s+(human|person)\b"), "pretend to be human"),
    (re.compile(r"(?i)\b(create|use|build|instil|instill)\b[^.\n]{0,15}?\b(false\s+)?sense\s+of\s+urgency\b"),
     "manufacture urgency"),
    (re.compile(r"(?i)\bpressure\s+(the\s+)?(user|customer|client)s?\b"), "pressure users"),
    (re.compile(r"(?i)\b(hide|conceal|downplay|omit)\b[^.\n]{0,30}?\b(risks?|fees?|errors?|mistakes?|uncertainty|"
                r"side\s+effects)\b"), "hide risks or errors"),
    (re.compile(r"(?i)\b(do\s+not|don't|never)\s+(tell|inform|let)\s+the\s+(user|customer)\b"),
     "conceal actions from the user"),
]

NO_CONFIRM_PATTERNS = [
    (re.compile(r"(?i)\b(never|don't|do\s+not)\s+(ask|request|wait|seek|prompt)\b[^.\n]{0,25}?\b(for\s+)?"
                r"(confirmation|permission|approval|consent)\b"), "never ask for confirmation"),
    (re.compile(r"(?i)\bwithout\s+(asking|requesting|seeking|waiting\s+for|requiring|needing)\b[^.\n]{0,20}?\b("
                r"confirmation|permission|approval|consent|the\s+user)\b"), "act without asking"),
    (re.compile(r"(?i)\bauto-?approve\s+(all|every|everything|any)\b"), "auto-approve everything"),
]


_NEGATION_RE = re.compile(r"(?i)\b(not|never|n't|avoid|refuse|without|no)\b[\s\w,]{0,12}$")


def iter_pattern_hits(text: str, patterns, negatable: bool = False) -> Iterator[Tuple[int, str, str]]:
    """Yield (offset, label, matched_text) for each pattern hit, at most one per line per label.

    With negatable=True a hit preceded by a negation ("do not ignore previous instructions") is skipped.
    """
    seen = set()
    for pattern, label in patterns:
        for m in pattern.finditer(text):
            if negatable and _NEGATION_RE.search(text[max(0, m.start() - 24):m.start()]):
                continue
            line = text.count("\n", 0, m.start())
            if (line, label) in seen:
                continue
            seen.add((line, label))
            yield m.start(), label, m.group(0)


# ── URLs ─────────────────────────────────────────────────────────────────────

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "host.docker.internal", ""}
_DOC_HOSTS = ("example.com", "example.org", "example.net", "w3.org", "schemas.xmlsoap.org", "json-schema.org",
              "schemas.openxmlformats.org", "purl.org", "xmlns.com", "apache.org/licenses")


def is_remote_plain_http(url: str) -> bool:
    if not isinstance(url, str) or not url.lower().startswith("http://"):
        return False
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    if host in _LOCAL_HOSTS or host.endswith(".local") or host.endswith(".localhost") or host.endswith(".internal"):
        return False
    if host.startswith("127.") or host.startswith("10.") or host.startswith("192.168."):
        return False
    if any(host == d or host.endswith("." + d) or d in url for d in _DOC_HOSTS):
        return False
    if "{" in host or "$" in host:
        return False
    return True


def is_local_url(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    return host in _LOCAL_HOSTS or host.startswith("127.") or host.endswith(".local")


def truncate(text: str, limit: int = 200) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
