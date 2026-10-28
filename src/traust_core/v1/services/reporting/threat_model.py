"""A threat model's Markdown: the rendering of its validated JSON, and the deterministic lint of
that prose contract (sections, tables, enums, coverage, provenance, evidence hygiene). A lint
failure means "fix the artifact", never "the threat is wrong"."""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from typing import Any

from traust_core.v1 import contracts
from traust_core.v1.models.vocabulary import MitigationEffort
from traust_core.v1.services.reporting import threat_rating

Doc = dict[str, Any]
Lines = list[str]

REQUIRED_SECTIONS = [
    "1. System context",
    "2. Assets",
    "3. Entry points & trust boundaries",
    "4. Threats",
    "5. Deprioritized",
    "6. Open questions",
    "7. Provenance",
]
OPTIONAL_SECTIONS = [
    "8. Recommended mitigations",
    "9. Attack scenarios",
    "10. Tenant boundaries",
    "11. Risk ratings",
]

ACTOR_ENUM = {
    "remote_unauth",
    "remote_auth",
    "adjacent_network",
    "local_user",
    "local_admin",
    "supply_chain",
    "insider",
}
IMPACT_ENUM = {"low", "medium", "high", "critical", "existential"}
LIKELIHOOD_ENUM = {"very_rare", "rare", "possible", "likely", "almost_certain"}
STATUS_ENUM = {"unmitigated", "partially_mitigated", "mitigated", "risk_accepted"}
SENSITIVITY_ENUM = {"low", "medium", "high", "critical"}
CLOSES_CLASS_ENUM = {"yes", "partial", "no"}
EFFORT_ENUM = {member.value for member in MitigationEffort}
MODE_ENUM = {"interview", "bootstrap", "bootstrap-then-interview"}

IMPACT_ORDER = ["existential", "critical", "high", "medium", "low"]
LIKELIHOOD_ORDER = ["almost_certain", "likely", "possible", "rare", "very_rare"]

THREATS_COLUMNS = [
    "id",
    "threat",
    "actor",
    "surface",
    "asset",
    "impact",
    "likelihood",
    "status",
    "controls",
    "evidence",
]
THREATS_COLUMNS_ATTACK = [*THREATS_COLUMNS, "attack_refs"]
# attack_refs is required for emissions from this harness version; ten-column models stay valid.
ATTACK_REFS_SINCE = (0, 82, 0)
THREATS_COLUMNS_ISOLATION = [*THREATS_COLUMNS_ATTACK, "isolation_dimensions"]
THREATS_COLUMNS_OWASP = [
    "id",
    "threat",
    "actor",
    "surface",
    "asset",
    "severity",
    "likelihood",
    "impact",
    "status",
    "controls",
    "evidence",
    "attack_refs",
]
THREATS_COLUMNS_OWASP_ISOLATION = [*THREATS_COLUMNS_OWASP, "isolation_dimensions"]
_THREATS_BASE_VARIANTS = (
    THREATS_COLUMNS,
    THREATS_COLUMNS_ATTACK,
    THREATS_COLUMNS_ISOLATION,
    THREATS_COLUMNS_OWASP,
    THREATS_COLUMNS_OWASP_ISOLATION,
)
_THREATS_SURFACE_VARIANTS = (
    *_THREATS_BASE_VARIANTS,
    *([*v, "review_surfaces"] for v in _THREATS_BASE_VARIANTS),
)
# Threats against LLM, agent or MCP components may end in their OWASP LLM categories and ATLAS IDs.
LLM_COLUMNS = ("owasp_llm_references", "atlas_refs")
_LLM_SUFFIXES = ((), ("owasp_llm_references",), ("atlas_refs",), LLM_COLUMNS)
THREATS_COLUMN_VARIANTS = tuple(
    [*v, *suffix] for suffix in _LLM_SUFFIXES for v in _THREATS_SURFACE_VARIANTS
)

BOUNDARY_COLUMNS = [
    "boundary_id",
    "interface",
    "kind",
    "exposure",
    "complexity",
    "privilege",
    "encryption",
    "authentication",
    "connectivity",
    "hygiene",
    "threat_ids",
    "isolation_review_ref",
]
ISOLATION_DIMENSIONS = ["privilege", "encryption", "authentication", "connectivity", "hygiene"]
BOUNDARY_KIND_ENUM = {"api", "data-store", "queue", "ingress", "webhook", "cli", "other"}
BOUNDARY_EXPOSURE_ENUM = {"public", "tenant", "partner", "internal"}
BOUNDARY_COMPLEXITY_ENUM = {"low", "medium", "high"}
DIMENSION_RESULT_ENUM = {"yes", "partial", "no", "na"}
BOUNDARY_ID = re.compile(r"^IF-\d+$")
ISOLATION_REVIEW_REF = re.compile(
    r"^analysis-results/isolation/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]*)*$"
)
ASSETS_COLUMNS = ["asset", "description", "sensitivity"]
ASSETS_OPTIONAL_COLUMNS = ["regulatory_scope", "example_records"]
ENTRY_COLUMNS = ["entry_point", "description", "trust_boundary", "reachable_assets"]
ENTRY_COLUMNS_SURFACES = [*ENTRY_COLUMNS, "review_surfaces"]
DEPRI_COLUMNS = ["threat", "reason"]
DEPRI_COLUMNS_SURFACES = [*DEPRI_COLUMNS, "review_surfaces"]
MITIG_COLUMNS = ["mitigation", "threat_ids", "closes_class", "effort"]
UPDATE_HISTORY_COLUMNS = ["date", "changes", "reason"]

# Evidence holds references that instantiate a threat (CVE, GHSA, commit, finding id, issue
# link, tracker id), never code locations.
EVIDENCE_OK = [
    re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE),
    re.compile(r"^GHSA(-[a-z0-9]{4}){3}$", re.IGNORECASE),
    re.compile(r"^[0-9a-f]{7,40}$"),
    re.compile(r"^FIND-\d{3,}$"),
    re.compile(r"^[A-Z0-9_.]+-[0-9a-f]{7,12}-\d{3}$"),
    re.compile(r"^-\d{3}$"),  # continuation shorthand after a canonical id
    re.compile(r"^https?://\S+$"),
    re.compile(r"^[A-Z]{2,}[A-Z0-9]*-\d+$"),
]
FILE_LINE = re.compile(r"[\w./-]+\.[A-Za-z]{1,5}:\d+")
_ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
_ATLAS_ID = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")
THREAT_ID = re.compile(r"^T\d+$")
SCENARIO_HEADING = re.compile(r"^### (T\d+)\b")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

THREAT_PROVENANCE_FIELDS = ("mode", "date", "target", "inputs", "owner", "harness_version")
THREAT_COLUMNS = (*THREATS_COLUMNS, "attack_refs")
THREAT_COLUMNS_OWASP = tuple(THREATS_COLUMNS_OWASP)

AttackIdCheck = Callable[[list[str]], Sequence[str]]


def _split(cell: str) -> list[str]:
    return re.split(r"[,;]\s*", cell)


def _surface_errors(where: str, cell: str) -> list[str]:
    known = list(contracts.enum_values("review-surface"))
    return [
        f"{where}: review_surfaces '{s}' not in {known}"
        for s in (x.strip() for x in _split(cell or "") if x.strip())
        if s not in known
    ]


def shape_only_atlas_ids(ids: list[str]) -> list[str]:
    """Without the pinned ATLAS table, only each id's shape is checked, and the message says so."""
    return [
        f"'{t}' is not a well-formed ATLAS technique ID "
        "(pinned table unavailable; shape check only)"
        for t in ids
        if not _ATLAS_ID.match(t)
    ]


def shape_only_attack_ids(ids: list[str]) -> list[str]:
    """Without the pinned ATT&CK table, only each id's shape is checked, and the message says so."""
    return [
        f"'{t}' is not a well-formed technique ID (pinned table unavailable; shape check only)"
        for t in ids
        if not _ATTACK_ID.match(t)
    ]


def evidence_token_ok(token: str) -> bool:
    """A recognized vuln reference, allowing a `commit ` prefix and a trailing parenthetical."""
    token = re.sub(r"\s*\([^)]*\)\s*$", "", token.strip())
    token = re.sub(r"^commits?\s+", "", token, flags=re.IGNORECASE)
    return any(p.match(token) for p in EVIDENCE_OK)


def parse_sections(text: str) -> list[tuple[str, Lines]]:
    """Each `## ` heading with the lines under it, in order."""
    sections: list[tuple[str, Lines]] = []
    current: tuple[str, Lines] | None = None
    for line in text.splitlines():
        m = re.match(r"^## (.+?)\s*$", line)
        if m:
            current = (m.group(1), [])
            sections.append(current)
        elif current is not None:
            current[1].append(line)
    return sections


def split_row(stripped: str) -> list[str]:
    """A table row's cells, split on unescaped pipes (GFM: `\\|` is a literal)."""
    cells = re.split(r"(?<!\\)\|", stripped)
    if cells and cells[0].strip() == "":
        cells = cells[1:]
    if cells and cells[-1].strip() == "":
        cells = cells[:-1]
    return [c.strip() for c in cells]


def parse_table(body_lines: Lines) -> tuple[list[str] | None, list[list[str]]]:
    """The first Markdown table in a section: (columns, rows), or (None, [])."""
    columns: list[str] | None = None
    rows: list[list[str]] = []
    for line in body_lines:
        stripped = line.strip()
        if not stripped.startswith("|"):
            if columns is not None and stripped == "":
                break
            continue
        cells = split_row(stripped)
        if columns is None:
            columns = cells
        elif set(stripped) <= {"|", "-", " ", ":"}:
            continue
        else:
            rows.append(cells)
    return columns, rows


def parse_provenance(body_lines: Lines) -> dict[str, str]:
    fields = {}
    for line in body_lines:
        m = re.match(r"^\s*-\s*([a-z_ ]+?)\s*:\s*(.*)$", line)
        if m:
            fields[m.group(1).strip()] = m.group(2).strip()
    return fields


def lint_threat_model(
    text: str,
    *,
    strict: bool = False,
    attack_ids: AttackIdCheck = shape_only_attack_ids,
    atlas_ids: AttackIdCheck = shape_only_atlas_ids,
) -> tuple[list[str], list[str]]:
    """(errors, warnings) of a THREAT_MODEL.md against the prose contract; `strict` adds the
    recommended-but-optional gaps as warnings. `attack_ids` and `atlas_ids` say why ATT&CK and
    ATLAS ids are invalid."""
    errors: list[str] = []
    warnings: list[str] = []

    if not re.match(r"^# Threat Model:\s*\S", text.splitlines()[0] if text else ""):
        errors.append("first line must be '# Threat Model: <system name>'")

    sections = parse_sections(text)
    headings = [h for h, _ in sections]
    numbered = [h for h in headings if re.match(r"^\d+\.", h)]
    for i, want in enumerate(REQUIRED_SECTIONS):
        if want not in headings:
            errors.append(f"missing required section '## {want}'")
        elif numbered and want in numbered and numbered.index(want) != i:
            errors.append(f"section '## {want}' out of order")
    for h in numbered:
        if h not in REQUIRED_SECTIONS and h not in OPTIONAL_SECTIONS:
            warnings.append(f"unrecognized numbered section '## {h}'")

    def body(name: str) -> Lines | None:
        return next((b for h, b in sections if h == name), None)

    b = body("2. Assets")
    if b is not None:
        cols, rows = parse_table(b)
        if cols is None:
            errors.append("section 2 has no assets table")
        else:
            if cols[:3] != ASSETS_COLUMNS:
                errors.append(f"section 2 columns must start with {ASSETS_COLUMNS}, got {cols[:3]}")
            warnings += [
                f"section 2 unexpected column '{extra}'"
                for extra in cols[3:]
                if extra not in ASSETS_OPTIONAL_COLUMNS
            ]
            for r in rows:
                if len(r) < 3:
                    errors.append(f"section 2 row too short: {r}")
                    continue
                if r[2] not in SENSITIVITY_ENUM:
                    errors.append(
                        f"section 2 asset '{r[0]}': sensitivity '{r[2]}' not in "
                        f"{sorted(SENSITIVITY_ENUM)}"
                    )

    entry_points = []
    b = body("3. Entry points & trust boundaries")
    if b is not None:
        cols, rows = parse_table(b)
        if cols is None:
            errors.append("section 3 has no entry-points table")
        elif cols not in (ENTRY_COLUMNS, ENTRY_COLUMNS_SURFACES):
            errors.append(
                f"section 3 columns must be {ENTRY_COLUMNS} "
                f"(optionally + ['review_surfaces']), got {cols}"
            )
        for r in rows:
            if r and r[0]:
                entry_points.append(r[0])
                if cols == ENTRY_COLUMNS_SURFACES and len(r) == len(cols):
                    errors += _surface_errors(f"section 3 '{r[0]}'", r[-1])

    threat_ids: list[str] = []
    surface_cells: list[str] = []
    threat_rows: list[dict[str, str]] = []
    rated_rows: dict[str, dict[str, str]] = {}
    threat_cols_seen = None
    b = body("4. Threats")
    if b is not None:
        cols, rows = parse_table(b)
        if cols is None:
            errors.append("section 4 has no threats table")
        elif cols not in THREATS_COLUMN_VARIANTS:
            errors.append(
                f"section 4 columns must be {THREATS_COLUMNS} "
                f"(optionally + ['attack_refs'], optionally then "
                f"+ ['isolation_dimensions']), or the OWASP-rated "
                f"{THREATS_COLUMNS_OWASP} (optionally + "
                f"['isolation_dimensions']), either optionally ending in "
                f"'review_surfaces', then optionally {list(LLM_COLUMNS)} (either or both, in "
                f"that order), got {cols}"
            )
        else:
            threat_cols = threat_cols_seen = cols
            for r in rows:
                if len(r) != len(threat_cols):
                    errors.append(
                        f"section 4 row has {len(r)} cells, expected {len(threat_cols)}: {r[:2]}"
                    )
                    continue
                row = dict(zip(threat_cols, r, strict=False))
                threat_rows.append(row)
                tid = row["id"]
                if not THREAT_ID.match(tid):
                    errors.append(f"section 4 id '{tid}' must match T<number>")
                elif tid in threat_ids:
                    errors.append(f"section 4 duplicate id '{tid}'")
                threat_ids.append(tid)
                surface_cells.append(row["surface"])
                for a in re.split(r",\s*", row["actor"]):
                    if a not in ACTOR_ENUM:
                        errors.append(f"section 4 {tid}: actor '{a}' not in {sorted(ACTOR_ENUM)}")
                if "severity" in row:
                    errors += [
                        f"section 4 {tid}: {msg}"
                        for msg in threat_rating.cell_problems(
                            row["severity"], row["likelihood"], row["impact"]
                        )
                    ]
                    rated_rows[tid] = row
                    rating_enums: tuple[tuple[str, set[str]], ...] = (("status", STATUS_ENUM),)
                else:
                    rating_enums = (
                        ("impact", IMPACT_ENUM),
                        ("likelihood", LIKELIHOOD_ENUM),
                        ("status", STATUS_ENUM),
                    )
                for field, enum in rating_enums:
                    if row[field] not in enum:
                        errors.append(
                            f"section 4 {tid}: {field} '{row[field]}' not in {sorted(enum)}"
                        )
                ev = row["evidence"].strip()
                if ev:
                    if FILE_LINE.search(ev):
                        errors.append(
                            f"section 4 {tid}: evidence contains a file:line citation "
                            f"('{ev}') — evidence holds vuln references (CVE/GHSA/commit/"
                            f"finding ID), never code locations; siblings go in the hand-back"
                        )
                    else:
                        for token in _split(ev):
                            token = token.strip()
                            if token and not evidence_token_ok(token):
                                warnings.append(
                                    f"section 4 {tid}: evidence token '{token}' is not a "
                                    "recognized vuln reference"
                                )
                ar = (row.get("attack_refs") or "").strip()
                if ar:
                    ids = [t.strip() for t in _split(ar) if t.strip()]
                    errors += [f"section 4 {tid}: attack_refs {msg}" for msg in attack_ids(ids)]
                    if len(ids) > 4:
                        warnings.append(
                            f"section 4 {tid}: {len(ids)} attack_refs — a row needing >4 "
                            "techniques is usually too broad; consider splitting"
                        )
                iso = (row.get("isolation_dimensions") or "").strip()
                if iso:
                    for d in [t.strip() for t in _split(iso) if t.strip()]:
                        if d not in ISOLATION_DIMENSIONS:
                            errors.append(
                                f"section 4 {tid}: isolation_dimensions "
                                f"'{d}' not in {ISOLATION_DIMENSIONS}"
                            )
                errors += _surface_errors(f"section 4 {tid}", row.get("review_surfaces") or "")
                categories = contracts.enum_values("owasp-llm-category")
                errors += [
                    f"section 4 {tid}: owasp_llm_references '{c}' not in {list(categories)}"
                    for c in (x.strip() for x in _split(row.get("owasp_llm_references") or ""))
                    if c and c not in categories
                ]
                atlas = [x.strip() for x in _split(row.get("atlas_refs") or "") if x.strip()]
                errors += [f"section 4 {tid}: atlas_refs {msg}" for msg in atlas_ids(atlas)]
            # a warning: legacy models predate strict ordering
            if "severity" in threat_cols:
                keys = [threat_rating.order_key(threat_rating.parse_row(r)) for r in threat_rows]
                if keys != sorted(keys):
                    warnings.append(
                        "section 4 rows are not sorted by (severity desc, impact score "
                        "desc, likelihood score desc), unrated rows after rated ones"
                    )
            else:
                legacy_keys = [
                    (IMPACT_ORDER.index(r["impact"]), LIKELIHOOD_ORDER.index(r["likelihood"]))
                    for r in threat_rows
                    if r["impact"] in IMPACT_ENUM and r["likelihood"] in LIKELIHOOD_ENUM
                ]
                if legacy_keys != sorted(legacy_keys):
                    warnings.append(
                        "section 4 rows are not sorted by (impact desc, likelihood desc)"
                    )

    depri_text = ""
    b = body("5. Deprioritized")
    if b is not None:
        depri_text = "\n".join(b)
        cols, rows = parse_table(b)
        if cols is not None and cols not in (DEPRI_COLUMNS, DEPRI_COLUMNS_SURFACES):
            errors.append(
                f"section 5 columns must be {DEPRI_COLUMNS} "
                f"(optionally + ['review_surfaces']), got {cols}"
            )
        if cols == DEPRI_COLUMNS_SURFACES:
            for r in rows:
                if r and r[0] and len(r) == len(cols):
                    errors += _surface_errors(f"section 5 '{r[0]}'", r[-1])

    # every entry point is threatened in section 4 or explicitly parked in section 5
    surfaces_joined = " ".join(surface_cells).lower()
    for ep in entry_points:
        if ep.lower() in surfaces_joined or ep.lower() in depri_text.lower():
            continue
        errors.append(
            f"coverage: entry point '{ep}' has no section 4 threat naming it in "
            f"'surface' and no section 5 row parking it"
        )

    b = body("7. Provenance")
    if b is not None:
        prov = parse_provenance(b)
        errors += [
            f"section 7 missing '{key}'"
            for key in ("mode", "date", "target", "inputs", "owner")
            if key not in prov
        ]
        mode = prov.get("mode", "")
        if mode and mode not in MODE_ENUM:
            errors.append(f"section 7 mode '{mode}' not in {sorted(MODE_ENUM)}")
        if prov.get("date") and not DATE_RE.match(prov["date"]):
            errors.append(f"section 7 date '{prov['date']}' must be YYYY-MM-DD")
        if "harness_version" not in prov:
            warnings.append(
                "section 7 missing 'harness_version' (required for new emissions; "
                "legacy artifacts predate it)"
            )
        m = re.match(r"(\d+)\.(\d+)\.(\d+)", prov.get("harness_version") or "")
        if (
            m
            and tuple(int(g) for g in m.groups()) >= ATTACK_REFS_SINCE
            and threat_cols_seen == THREATS_COLUMNS
        ):
            errors.append(
                "section 4 is missing the attack_refs column — default schema "
                f"for emissions at harness >= "
                f"{'.'.join(map(str, ATTACK_REFS_SINCE))} (this model's "
                f"provenance says {prov['harness_version']}); legacy models "
                "are exempt, new emissions are not"
            )
        cols, rows = parse_table(b)
        if cols is not None:
            if cols != UPDATE_HISTORY_COLUMNS:
                errors.append(
                    f"section 7 update-history columns must be {UPDATE_HISTORY_COLUMNS}, got {cols}"
                )
            errors += [
                f"section 7 update-history date '{r[0]}' must be YYYY-MM-DD"
                for r in rows
                if r and r[0] and not DATE_RE.match(r[0])
            ]

    b = body("8. Recommended mitigations")
    if b is None:
        if strict:
            warnings.append(
                "section 8 (Recommended mitigations) absent — recommended for new emissions"
            )
    else:
        cols, rows = parse_table(b)
        if cols is not None:
            if cols not in (MITIG_COLUMNS, [*MITIG_COLUMNS, "blocked_external"]):
                errors.append(f"section 8 columns must be {MITIG_COLUMNS}, got {cols}")
            else:
                for r in rows:
                    if len(r) != len(cols):
                        errors.append(f"section 8 row too short: {r}")
                        continue
                    for tid in _split(r[1]):
                        tid = tid.strip()
                        if tid and tid not in threat_ids:
                            errors.append(
                                f"section 8 mitigation '{r[0]}' references unknown threat id "
                                f"'{tid}'"
                            )
                    if r[2] not in CLOSES_CLASS_ENUM:
                        errors.append(
                            f"section 8 '{r[0]}': closes_class '{r[2]}' not in "
                            f"{sorted(CLOSES_CLASS_ENUM)}"
                        )
                    if r[3] not in EFFORT_ENUM and r[3] not in ("", "-"):
                        errors.append(
                            f"section 8 '{r[0]}': effort '{r[3]}' not in {sorted(EFFORT_ENUM)}"
                        )
                    if len(cols) == 5 and r[4] not in ("true", "false", "", "-"):
                        errors.append(
                            f"section 8 '{r[0]}': blocked_external must be true, false or unknown"
                        )

    b = body("9. Attack scenarios")
    if b is not None:
        scenario_ids = []
        for line in b:
            m = SCENARIO_HEADING.match(line)
            if m:
                scenario_ids.append(m.group(1))
            elif line.startswith("### "):
                errors.append(f"section 9 heading '{line.strip()}' must start '### T<n>'")
        if not scenario_ids:
            errors.append("section 9 present but has no '### T<n>' scenario subsections")
        errors += [
            f"section 9 scenario '{sid}' references unknown threat id"
            for sid in scenario_ids
            if sid not in threat_ids
        ]
        if len(scenario_ids) > 8:
            warnings.append(
                f"section 9 has {len(scenario_ids)} scenarios — keep to the top 3-5 threats"
            )

    b = body("10. Tenant boundaries")
    if b is not None:
        errors += _lint_boundaries(b, threat_ids)

    b = body("11. Risk ratings")
    rated = {
        tid: row for tid, row in rated_rows.items() if row["severity"] != threat_rating.UNRATED
    }
    if b is None:
        if rated:
            errors.append(
                f"section 11 (Risk ratings) is missing; it must list the factor "
                f"scores for rated threats {sorted(rated)}"
            )
    else:
        errors += _lint_risk_ratings(b, rated, threat_ids)

    return errors, warnings


def _lint_boundaries(body_lines: Lines, threat_ids: list[str]) -> list[str]:
    errors = []
    cols, rows = parse_table(body_lines)
    if cols is None:
        return ["section 10 present but has no tenant-boundaries table"]
    if cols != BOUNDARY_COLUMNS:
        return [f"section 10 columns must be {BOUNDARY_COLUMNS}, got {cols}"]
    boundary_ids: list[str] = []
    for r in rows:
        if len(r) != len(BOUNDARY_COLUMNS):
            errors.append(
                f"section 10 row has {len(r)} cells, expected {len(BOUNDARY_COLUMNS)}: {r[:2]}"
            )
            continue
        row = dict(zip(BOUNDARY_COLUMNS, r, strict=False))
        bid = row["boundary_id"]
        if not BOUNDARY_ID.match(bid):
            errors.append(f"section 10 boundary_id '{bid}' must match IF-<number>")
        elif bid in boundary_ids:
            errors.append(f"section 10 duplicate boundary_id '{bid}'")
        boundary_ids.append(bid)
        for field, enum in (
            ("kind", BOUNDARY_KIND_ENUM),
            ("exposure", BOUNDARY_EXPOSURE_ENUM),
            ("complexity", BOUNDARY_COMPLEXITY_ENUM),
        ):
            if row[field] not in enum:
                errors.append(f"section 10 {bid}: {field} '{row[field]}' not in {sorted(enum)}")
        errors += [
            f"section 10 {bid}: {dim} '{row[dim]}' not in {sorted(DIMENSION_RESULT_ENUM)}"
            for dim in ISOLATION_DIMENSIONS
            if row[dim] not in DIMENSION_RESULT_ENUM
        ]
        for tid in _split(row["threat_ids"]):
            tid = tid.strip()
            if tid and tid not in threat_ids:
                errors.append(f"section 10 {bid}: references unknown threat id '{tid}'")
        ref = row["isolation_review_ref"].strip()
        if ref and not ISOLATION_REVIEW_REF.match(ref):
            errors.append(
                f"section 10 {bid}: isolation_review_ref '{ref}' must "
                f"be empty or an analysis-results/isolation/"
                f"<service-slug>/ path"
            )
    return errors


def _rating_subsections(body_lines: Lines) -> list[tuple[str | None, str, Lines]]:
    out: list[tuple[str | None, str, Lines]] = []
    current: tuple[str | None, str, Lines] | None = None
    for line in body_lines:
        if line.startswith("### "):
            m = threat_rating.RATING_HEADING.match(line)
            current = (m.group(1) if m else None, line.strip(), [])
            out.append(current)
        elif current is not None:
            current[2].append(line)
    return out


def _lint_risk_ratings(
    body_lines: Lines, rated: dict[str, dict[str, str]], threat_ids: list[str]
) -> list[str]:
    """Every rated threat has a factor table reproducing its section 4 severity, levels and
    scores."""
    errors = []
    seen: list[str] = []
    for tid, heading, sub in _rating_subsections(body_lines):
        if tid is None:
            errors.append(f"section 11 heading '{heading}' must start '### T<n>'")
            continue
        where = f"section 11 {tid}"
        if tid in seen:
            errors.append(f"{where}: duplicate subsection")
            continue
        seen.append(tid)
        if tid not in threat_ids:
            errors.append(f"{where}: references unknown threat id")
            continue
        if tid not in rated:
            errors.append(f"{where}: section 4 does not rate this threat")
            continue
        cols, rows = parse_table(sub)
        if cols != threat_rating.FACTOR_COLUMNS:
            errors.append(f"{where}: columns must be {threat_rating.FACTOR_COLUMNS}, got {cols}")
            continue
        scores: dict[str, int] = {}
        for r in rows:
            if len(r) != len(cols):
                errors.append(f"{where}: row has {len(r)} cells, expected {len(cols)}: {r[:1]}")
                continue
            name, value = r[0], r[1]
            if name not in threat_rating.ALL_FACTORS:
                errors.append(f"{where}: unknown factor '{name}'")
            elif name in scores:
                errors.append(f"{where}: factor '{name}' listed twice")
            elif not re.fullmatch(r"\d", value):
                errors.append(f"{where}: factor '{name}' score '{value}' must be 0-9")
            else:
                scores[name] = int(value)
        stated = threat_rating.parse_row(rated[tid])
        if stated["severity_source"] != "owasp":
            continue  # the section 4 cell errors already say why
        rating, problems = threat_rating.rating_from_factors(scores, stated["impact_basis"])
        errors += [f"{where}: {p}" for p in problems]
        if rating is None:
            continue
        computed = threat_rating.parse_row(
            {
                "severity": rating["severity"],
                "likelihood": threat_rating.likelihood_cell(rating),
                "impact": threat_rating.impact_cell(rating),
            }
        )
        errors += [
            f"{where}: factors give {key} {computed[key]!r}, section 4 says {stated[key]!r}"
            for key in ("severity", "likelihood", "impact", "likelihood_score", "impact_score")
            if computed[key] != stated[key]
        ]
        heading_severity = heading.split("—")[-1].strip() if "—" in heading else None
        if heading_severity and heading_severity != rating["severity"]:
            errors.append(
                f"{where}: heading says '{heading_severity}', factors give '{rating['severity']}'"
            )
    errors += [
        f"section 11 has no factor table for rated threat {tid}"
        for tid in sorted(set(rated) - set(seen))
    ]
    return errors


def _section_filled(body_lines: Lines) -> bool:
    """A section carries content unless it is a bare table header or a placeholder."""
    lines = [line.strip() for line in body_lines if line.strip()]
    rows = [line for line in lines if line.startswith("|")]
    prose = [line for line in lines if not line.startswith("|")]
    return len(rows) > 2 or any(line not in ("_not recorded_", "_none_") for line in prose)


def lost_sections(existing: str, rendered: str) -> list[str]:
    """Sections the existing threat-model Markdown fills that a new rendering drops or empties:
    a JSON missing members its Markdown has would otherwise erase them silently."""
    before = {h: _section_filled(b) for h, b in parse_sections(existing)}
    after = {h: _section_filled(b) for h, b in parse_sections(rendered)}
    return [h for h, filled in before.items() if filled and not after.get(h, False)]


def _tm_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value)
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def _tm_table(columns: Sequence[str], rows: Sequence[Doc]) -> Lines:
    out = ["| " + " | ".join(columns) + " |", "|" + "|".join("---" for _ in columns) + "|"]
    out += ["| " + " | ".join(_tm_cell(row.get(c)) for c in columns) + " |" for row in rows]
    return out


def _optional(column: str, items: Sequence[Doc]) -> tuple[str, ...]:
    return (column,) if any(item.get(column) for item in items) else ()


def render_threat_model(document: Doc) -> str:
    """The Markdown view of a validated threat model, rendered to satisfy the lint: sections 1-7
    always, 8-10 omitted when empty (the lint reads present-but-empty as an error), and
    `inputs` / `owner` written as `unset` when absent (read back as absent)."""
    threats = document.get("threats") or []
    rated = [t for t in threats if t.get("risk_rating")]
    columns: tuple[str, ...] = THREAT_COLUMNS_OWASP if rated else THREAT_COLUMNS
    if rated:
        threats = [{**t, **threat_rating.threat_cells(t)} for t in threats]
    columns += _optional("isolation_dimensions", threats) + _optional("review_surfaces", threats)
    columns += tuple(c for c in LLM_COLUMNS if _optional(c, threats))

    lines: Lines = [f"# Threat Model: {document.get('system', '')}", ""]
    lines += ["## 1. System context", "", document.get("system_context") or "_not recorded_", ""]

    assets = document.get("assets") or []
    asset_columns = ("asset", "description", "sensitivity")
    asset_columns += _optional("regulatory_scope", assets) + _optional("example_records", assets)
    lines += ["## 2. Assets", "", *_tm_table(asset_columns, assets), ""]

    entry_points = document.get("entry_points") or []
    entry_columns = (*ENTRY_COLUMNS, *_optional("review_surfaces", entry_points))
    lines += ["## 3. Entry points & trust boundaries", "", *_tm_table(entry_columns, entry_points)]
    lines += ["", "## 4. Threats", "", *_tm_table(columns, threats), ""]

    deprioritized = document.get("deprioritized") or []
    depri_columns = (*DEPRI_COLUMNS, *_optional("review_surfaces", deprioritized))
    lines += ["## 5. Deprioritized", "", *_tm_table(depri_columns, deprioritized), ""]

    questions = document.get("open_questions") or []
    lines += ["## 6. Open questions", ""]
    lines += [f"- {q}" for q in questions] if questions else ["_none_"]
    lines += [""]

    provenance = document.get("provenance") or {}
    lines += ["## 7. Provenance", ""]
    for field in THREAT_PROVENANCE_FIELDS:
        value = provenance.get(field)
        if value:
            lines.append(f"- {field}: {value}")
        elif field in ("inputs", "owner"):
            lines.append(f"- {field}: unset")
    lines += [""]

    # the update history belongs to section 7, before any later section
    history = document.get("update_history") or []
    if history:
        lines += ["### Update history", "", *_tm_table(UPDATE_HISTORY_COLUMNS, history), ""]

    mitigations = document.get("mitigations") or []
    if mitigations:
        mitigation_columns = (*MITIG_COLUMNS, *_optional_key("blocked_external", mitigations))
        rows = [
            {
                **item,
                "effort": "-" if item["effort"] is None else item["effort"],
                "blocked_external": (
                    "-"
                    if item.get("blocked_external") is None
                    else str(item["blocked_external"]).lower()
                ),
            }
            for item in mitigations
        ]
        lines += ["## 8. Recommended mitigations", "", *_tm_table(mitigation_columns, rows), ""]

    scenarios = document.get("attack_scenarios") or []
    if scenarios:
        lines += ["## 9. Attack scenarios", ""]
        for scenario in scenarios:
            heading = f"### {scenario.get('id', '')}"
            if scenario.get("threat"):
                heading += f" — {scenario['threat']}"
            lines += [heading, ""]
            for step in scenario.get("steps") or []:
                lines += [step, ""]

    boundaries = document.get("tenant_boundaries") or []
    if boundaries:
        lines += ["## 10. Tenant boundaries", "", *_tm_table(BOUNDARY_COLUMNS, boundaries), ""]

    if rated:
        lines += [
            "## 11. Risk ratings",
            "",
            "Rated with the [OWASP Risk Rating Methodology]"
            f"({contracts.risk_rating.SOURCE}) (OWASP Foundation). "
            "Each factor is scored 0-9; likelihood and impact are the means "
            "of their factors.",
            "",
        ]
        for threat in rated:
            rating = threat["risk_rating"]
            lines += [f"### {threat.get('id', '')} — {rating['severity']}", ""]
            lines += _tm_table(threat_rating.FACTOR_COLUMNS, threat_rating.factor_rows(rating))
            lines += [""]

    return "\n".join(lines).rstrip() + "\n"


def _optional_key(column: str, items: Sequence[Doc]) -> tuple[str, ...]:
    return (column,) if any(column in item for item in items) else ()
