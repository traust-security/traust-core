from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from html import escape
from urllib.parse import urlsplit

from traust_core.v1.models.artifacts import PqcReadinessArtifact
from traust_core.v1.models.pqc import PqcRemediation
from traust_core.v1.rendering.markdown import inline

_CATEGORIES = {
    "fix now": "fix-now",
    "upgrade": "upgrade",
    "waiting on upstream": "waiting-on-upstream",
}
_LEGEND = """### What the domains mean

| Domain | Question it answers | Scale |
|---|---|---|
| VULN | Is crypto quantum-vulnerable? | 0 = exposed; 100 = no vulnerable crypto |
| AGIL | How easy is it to swap the crypto when needed? | 0 = hardcoded; 100 = configurable |
| PQCA | Has this repo adopted post-quantum crypto? | 0 = no adoption; 100 = fully adopted |
| HNDL | Could recorded traffic be decrypted later? | 0 = high harvest risk; 100 = no risk |

Overall combines VULN 40%, AGIL 25%, PQCA 20% and HNDL 15%; higher is more ready.
Effort size and independently evidenced external blocking do not determine readiness.
"""


@dataclass(frozen=True)
class PqcReportRepair:
    report: PqcReadinessArtifact
    markdown: str
    changed: bool


def repair_report(
    doc: PqcReadinessArtifact, markdown: str, *, force: bool = False, derive: bool = True
) -> PqcReportRepair:
    body = json.loads(doc.payload)
    changed = derive and (force or "remediations" not in body)
    if changed:
        entries = _markdown_actions(markdown)
        covered = " ".join(f"{e.action} {e.details or ''}" for e in entries).lower()
        for clock in body.get("clock_items") or ():
            primitive = clock["primitive"]
            if primitive and primitive.lower() in covered:
                continue
            year = clock.get("disallowed_after") or clock.get("deprecated_after")
            if year not in (2030, 2035):
                continue
            transition = (
                "disallowed after"
                if clock.get("disallowed_after")
                else "deprecated for new use after"
            )
            entries.append(
                PqcRemediation.model_validate(
                    {
                        "id": "pending",
                        "category": "deadline",
                        "action": f"Migrate off {primitive} — {transition} {year} (NIST IR 8547)",
                        "deadline": year,
                        **{
                            k: clock[k]
                            for k in ("remediation_effort", "blocked_external", "blast_radius")
                            if k in clock
                        },
                    }
                )
            )
        meta = body["metadata"]
        slug = urlsplit(meta["repository"]).path.strip("/").replace("/", "--") or "unknown"
        slug = re.sub(r"[^A-Za-z0-9]", "_", slug).upper()[:24]
        commit = meta.get("commit") or ""
        provenance = (
            commit[:7]
            if re.fullmatch(r"[0-9a-f]{7,40}", commit)
            else "u" + hashlib.sha256(meta["repository"].encode()).hexdigest()[:6]
        )
        body["remediations"] = [
            {
                **e.model_dump(mode="json", exclude_none=True),
                "id": f"{slug}-{provenance}-REM-{i:03d}",
                "remediation_effort": e.remediation_effort,
            }
            for i, e in enumerate(entries, 1)
        ]
        doc = PqcReadinessArtifact.from_document(body)
    return PqcReportRepair(doc, _repair_markdown(markdown, body.get("remediations") or []), changed)


def _markdown_actions(markdown: str) -> list[PqcRemediation]:
    entries: list[PqcRemediation] = []
    category = None
    current: dict[str, object] | None = None
    for line in [*markdown.splitlines(), "## End"]:
        heading = re.match(r"^(#{1,6})\s+(.+)$", line)
        bullet = re.match(r"^-\s+(?:`(?P<loc>[^`]+)`\s*[—-]\s*)?(?P<desc>.+)$", line)
        if (heading or (bullet and category)) and current is not None:
            if current["category"] == "waiting-on-upstream" and not current.get("blocked_on"):
                current["blocked_on"] = str(current.get("details") or current["action"])[:120]
            entries.append(PqcRemediation.model_validate(current))
            current = None
        if heading:
            category = (
                next((v for k, v in _CATEGORIES.items() if heading[2].lower().startswith(k)), None)
                if len(heading[1]) == 3
                else None
            )
        elif bullet and category:
            description = bullet["desc"].strip()
            current = {
                "id": "pending",
                "category": category,
                "action": description,
                "locations": (bullet["loc"],) if bullet["loc"] else (),
            }
            if category == "waiting-on-upstream":
                blocked = re.search(r"blocked on\s+([^.,;]+)", description, re.I)
                if blocked:
                    current["blocked_on"] = blocked[1].strip()
        elif current is not None:
            if action := re.match(r"^\s+Action:\s*(.+)$", line):
                current.update(details=current["action"], action=action[1].strip())
                if category == "upgrade":
                    current["target"] = action[1].strip()
            elif recipe := re.match(r"^\s+Playbook:\s*(\S+)", line):
                current["recipe"] = recipe[1]
    return entries


def _replace_section(text: str, heading: str, section: str) -> str:
    pattern = re.compile(r"^" + re.escape(heading) + r"\s*$[\s\S]*?(?=^#{1,3} |\Z)", re.M)
    if pattern.search(text):
        return pattern.sub(lambda _: section.rstrip() + "\n\n", text, count=1)
    if heading == "## Remediations" and "## Scores" in text:
        return text.replace("## Scores", section.rstrip() + "\n\n## Scores", 1)
    return text.rstrip() + "\n\n" + section.rstrip() + "\n"


def _repair_markdown(text: str, entries: list[dict[str, object]]) -> str:
    lines = []
    drop = None
    for line in text.splitlines():
        if re.match(r"^\s+Playbook:\s*", line):
            continue
        if line.strip().startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if "Facts" in cells:
                drop = cells.index("Facts")
            if drop is not None and len(cells) > drop:
                del cells[drop]
                line = "| " + " | ".join(cells) + " |"
        else:
            drop = None
        lines.append(line)
    text = "\n".join(lines) + "\n"
    section = ["## Remediations", ""]
    for raw in entries:
        entry = PqcRemediation.model_validate(
            {
                k: v
                for k, v in raw.items()
                if k in PqcRemediation.model_fields and k != "remediation_effort"
            }
        )
        extras = [
            f"{name}: {_safe(value)}"
            for name, value in (
                ("deadline", entry.deadline),
                ("target", entry.target),
                ("effort", raw.get("remediation_effort")),
                ("blocked on", entry.blocked_on),
                ("external wait", entry.blocked_external),
            )
            if value is not None
        ]
        section.append(
            f"- {_safe(entry.id)} ({_safe(entry.category)}): {_safe(entry.action)}"
            + (f" ({'; '.join(extras)})" if extras else "")
        )
        if entry.locations:
            section.append("  Locations: " + ", ".join(_safe(loc) for loc in entry.locations))
    if not entries:
        section.append("None — no remediation actions identified.")
    text = _replace_section(text, "## Remediations", "\n".join(section))
    return _replace_section(text, "### What the domains mean", _LEGEND).rstrip() + "\n"


def _safe(value: object) -> str:
    return escape(inline(value)).replace("|", "\\|").replace("`", "\\`")
