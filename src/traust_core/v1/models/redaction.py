from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

PEM_PATTERN = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)(.*?)(-----END [A-Z ]*PRIVATE KEY-----)", re.DOTALL
)
PAYMENT_CARD_PATTERN = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, digit in enumerate(reversed(digits)):
        value = int(digit) * (2 if i % 2 else 1)
        total += value - 9 if value > 9 else value
    return total % 10 == 0


@dataclass(frozen=True, slots=True)
class SecretSpan:
    tag: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class SecretRule:
    category: str
    pattern: re.Pattern[str]
    group: int = 0
    evidence_tag: str | None = None
    evidence_pattern: re.Pattern[str] | None = None
    evidence_group: int | None = None
    evidence_order: int = 100
    publication: bool = True

    @property
    def tag(self) -> str:
        return self.evidence_tag or self.category

    def spans(self, text: str) -> Iterator[SecretSpan]:
        ranges = [match.span(self.group) for match in self.pattern.finditer(text)]
        if self.evidence_pattern is not None:
            group = self.group if self.evidence_group is None else self.evidence_group
            ranges.extend(match.span(group) for match in self.evidence_pattern.finditer(text))
            ranges.sort()
        pending: SecretSpan | None = None
        for start, end in ranges:
            if self.category == "payment-card":
                digits = re.sub(r"[ -]", "", text[start:end])
                if not (13 <= len(digits) <= 19 and luhn_ok(digits)):
                    continue
            if pending is not None and start < pending.end:
                pending = SecretSpan(self.tag, pending.start, max(pending.end, end))
            else:
                if pending is not None:
                    yield pending
                pending = SecretSpan(self.tag, start, end)
        if pending is not None:
            yield pending


_RULES = (
    SecretRule(
        "aws-access-key",
        re.compile(r"AKIA[0-9A-Z]{12,}"),
        evidence_tag="aws-akid",
        evidence_pattern=re.compile(r"\b(?:AKIA[0-9A-Z]{12,}|ASIA[0-9A-Z]{16})\b"),
        evidence_order=2,
    ),
    SecretRule(
        "github-token",
        re.compile(r"gh[posru]_[a-zA-Z0-9]{30,}"),
        evidence_pattern=re.compile(r"\bgh[posru]_[A-Za-z0-9]{20,}\b"),
        evidence_order=12,
    ),
    SecretRule("github-pat", re.compile(r"github_pat_[a-zA-Z0-9_]{20,}"), evidence_order=13),
    SecretRule(
        "gitlab-token",
        re.compile(r"glpat-[a-zA-Z0-9\-_]{20,}"),
        evidence_tag="gitlab-pat",
        evidence_pattern=re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}\b"),
        evidence_order=14,
    ),
    SecretRule(
        "slack-token",
        re.compile(r"xox[bpsa]-[a-zA-Z0-9\-]{10,}"),
        evidence_pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        evidence_order=15,
    ),
    SecretRule("llm-api-key", re.compile(r"sk-[a-zA-Z0-9]{20,}")),
    SecretRule("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    SecretRule(
        "bearer-token",
        re.compile(r"Bearer\s+([a-zA-Z0-9._\-]{20,})"),
        1,
        evidence_tag="bearer",
        evidence_pattern=re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}", re.I),
        evidence_group=0,
        evidence_order=6,
    ),
    SecretRule(
        "jwt",
        re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}"),
        evidence_order=7,
    ),
    *(
        SecretRule(
            f"{name}-assignment",
            re.compile(rf"{key}\s*[:=]\s*\\?['\"]([^'\"\\]{{8,}})\\?['\"]", re.IGNORECASE),
            1,
        )
        for name, key in (
            ("password", "(?:password|passwd)"),
            ("secret", "secret"),
            ("token", "token"),
            ("apikey", "api[_-]?key"),
        )
    ),
    SecretRule(
        "url-credentials",
        re.compile(r"://[A-Za-z0-9._%+-]+:([^@/\s'\"]{6,})@"),
        1,
        evidence_order=17,
    ),
    SecretRule("us-ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    SecretRule(
        "azure-client-secret", re.compile(r"\b[a-zA-Z0-9~_.\-]{3}8Q~[a-zA-Z0-9~_.\-]{30,}\b")
    ),
    SecretRule("gcp-sa-key", re.compile(r'\\?"private_key_id\\?"\s*:\s*\\?"([a-f0-9]{40})\\?"'), 1),
    SecretRule(
        "pem-private-key",
        PEM_PATTERN,
        evidence_tag="pem-privkey",
        evidence_order=0,
        publication=False,
    ),
    SecretRule(
        "key-data",
        re.compile(r'(client-key-data|private_key)"?\s*[:=]\s*"?([A-Za-z0-9+/\\n=_-]{40,})', re.I),
        2,
        evidence_order=1,
        publication=False,
    ),
    SecretRule(
        "aws-secret",
        re.compile(
            r'(aws_secret_access_key|secretAccessKey)"?\s*[:=]\s*"?([A-Za-z0-9+/=]{30,})', re.I
        ),
        2,
        evidence_order=3,
        publication=False,
    ),
    SecretRule(
        "cloud-client-secret",
        re.compile(
            r'(client[_-]?secret|clientSecret|client_secret_data)"?\s*[:=]\s*"?'
            r"([A-Za-z0-9~._+/=-]{20,})",
            re.I,
        ),
        2,
        evidence_order=4,
        publication=False,
    ),
    SecretRule(
        "oc-token",
        re.compile(r"\bsha256~[A-Za-z0-9_-]{20,}\b"),
        evidence_order=5,
        publication=False,
    ),
    SecretRule(
        "registry-auth",
        re.compile(r'("auth"\s*:\s*")([A-Za-z0-9+/=]{40,})'),
        2,
        evidence_order=8,
        publication=False,
    ),
    SecretRule(
        "b64-pem",
        re.compile(r"LS0tLS1CRUdJTi[A-Za-z0-9+/=]{40,}"),
        evidence_order=9,
        publication=False,
    ),
    SecretRule(
        "b64-dockerconfig",
        re.compile(r"\beyJhdXRo[A-Za-z0-9+/=]{20,}"),
        evidence_order=10,
        publication=False,
    ),
    SecretRule(
        "aws-session",
        re.compile(r'(aws_session_token)"?\s*[:=]\s*"?([A-Za-z0-9+/=]{40,})', re.I),
        2,
        evidence_order=16,
        publication=False,
    ),
    SecretRule(
        "generic-secret",
        re.compile(
            r"([A-Za-z0-9_.\-]*(?:password|passwd|token|api[_-]?key|secret))"
            r'"?\s*[:=]\s*"?([^\s\"\',;]{12,})',
            re.I,
        ),
        2,
        evidence_order=18,
        publication=False,
    ),
    SecretRule("payment-card", PAYMENT_CARD_PATTERN, publication=False),
)


class SecretDetector:
    """The shared secret-shape owner; rendering and structured-map policy belong to callers."""

    @staticmethod
    def publication_rules() -> tuple[SecretRule, ...]:
        return tuple(rule for rule in _RULES if rule.publication)

    @staticmethod
    def evidence_rules() -> tuple[SecretRule, ...]:
        return tuple(sorted(_RULES, key=lambda rule: rule.evidence_order))

    @classmethod
    def evidence_tags(cls) -> tuple[str, ...]:
        return tuple(dict.fromkeys(rule.tag for rule in cls.evidence_rules()))
