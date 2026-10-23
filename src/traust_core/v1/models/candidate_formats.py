"""Third-party scanner output (SARIF 2.x, Dependabot alerts, govulncheck -json) as finding fields.

Every result is a machine claim: nothing here sets a verdict.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from typing import Any

from traust_core.v1.errors import ValidationError

_LEVEL_TO_SEVERITY = {
    "error": "high",
    "warning": "medium",
    "note": "informational",
    "none": "informational",
}
_PRECISION_TO_CONFIDENCE = {"very-high": 0.95, "high": 0.85, "medium": 0.6, "low": 0.4}
_DEPENDABOT_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
}
_CWE_RX = re.compile(r"cwe[-/](\d+)", re.IGNORECASE)

Fields = dict[str, Any]


def _security_severity(score: float) -> str:
    for floor, severity in ((9, "critical"), (7, "high"), (4, "medium")):
        if score >= floor:
            return severity
    return "low" if score > 0 else "informational"


def _cwes(*tag_lists: Any) -> tuple[str, ...]:
    found = (_CWE_RX.search(str(tag)) for tags in tag_lists for tag in tags or ())
    return tuple(dict.fromkeys(f"CWE-{m.group(1)}" for m in found if m))


def _lines(*parts: str | None) -> str:
    return "\n".join(p for p in parts if p)


def _json(raw: bytes, format: str) -> Any:
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValidationError(f"{format}: not JSON: {e}") from e


def sarif(raw: bytes) -> list[Fields]:
    doc = _json(raw, "sarif")
    if not (
        isinstance(doc, dict)
        and isinstance(doc.get("runs"), list)
        and str(doc.get("version", "")).startswith("2.")
    ):
        raise ValidationError("sarif: expected a SARIF 2.x document with runs")
    return [fields for run in doc["runs"] for fields in _sarif_run(run)]


def _sarif_run(run: dict[str, Any]) -> Iterator[Fields]:
    tool = run.get("tool") or {}
    rules = (tool.get("driver") or {}).get("rules") or []
    by_id = {
        r.get("id"): r
        for pool in [rules, *((e.get("rules") or []) for e in tool.get("extensions") or [])]
        for r in pool
    }
    for result in run.get("results") or []:
        if result.get("suppressions"):
            continue
        index = result.get("ruleIndex")
        rule = (
            rules[index]
            if isinstance(index, int) and 0 <= index < len(rules)
            else by_id.get(result.get("ruleId"), {})
        )
        rule_props, props = rule.get("properties") or {}, result.get("properties") or {}
        path, line = _sarif_location(result)
        description = (result.get("message") or {}).get("text") or ""
        full = (rule.get("fullDescription") or {}).get("text")
        yield {
            "label": result.get("guid")
            or (result.get("partialFingerprints") or {}).get("harnessFindingId/v1")
            or result.get("ruleId"),
            "rule": result.get("ruleId"),
            "category": None,
            "title": (rule.get("shortDescription") or {}).get("text")
            or result.get("ruleId")
            or "(untitled)",
            "description": _lines(
                description,
                full if full and full not in description else None,
                (rule.get("help") or {}).get("text"),
            ),
            "severity": _sarif_severity(result, rule_props, props),
            "cwes": _cwes(rule_props.get("tags"), props.get("tags")),
            "path": path,
            "line": line,
            "confidence": _PRECISION_TO_CONFIDENCE.get(rule_props.get("precision")),
        }


def _sarif_severity(
    result: dict[str, Any], rule_props: dict[str, Any], props: dict[str, Any]
) -> str:
    score = props.get("security-severity", rule_props.get("security-severity"))
    try:
        return _security_severity(float(score))
    except (TypeError, ValueError):
        return _LEVEL_TO_SEVERITY.get(result.get("level", "warning"), "medium")


def _sarif_location(result: dict[str, Any]) -> tuple[str | None, int | None]:
    for loc in result.get("locations") or []:
        physical = loc.get("physicalLocation") or {}
        if uri := (physical.get("artifactLocation") or {}).get("uri"):
            return uri, (physical.get("region") or {}).get("startLine")
        for logical in loc.get("logicalLocations") or []:
            if name := logical.get("fullyQualifiedName") or logical.get("name"):
                return name, None
    return None, None


def dependabot(raw: bytes) -> list[Fields]:
    alerts = _json(raw, "dependabot")
    if not (
        isinstance(alerts, list)
        and all(isinstance(a, dict) and "security_advisory" in a for a in alerts)
    ):
        raise ValidationError("dependabot: expected a list of alerts with security_advisory")
    return [_dependabot_alert(a) for a in alerts]


def _dependabot_alert(alert: dict[str, Any]) -> Fields:
    advisory, vuln = alert.get("security_advisory") or {}, alert.get("security_vulnerability") or {}
    dependency = alert.get("dependency") or {}
    package = dependency.get("package") or {}
    ids = ", ".join(i for i in (advisory.get("ghsa_id"), advisory.get("cve_id")) if i)
    fixed = (vuln.get("first_patched_version") or {}).get("identifier")
    return {
        "label": advisory.get("ghsa_id") or f"dependabot-{alert.get('number')}",
        "rule": None,
        "category": "supply-chain",
        "title": advisory.get("summary") or f"Vulnerable dependency {package.get('name')}",
        "description": _lines(
            advisory.get("description"),
            f"Package: {package.get('ecosystem')}/{package.get('name')} "
            f"({vuln.get('vulnerable_version_range', 'range unknown')})",
            f"Identifiers: {ids}" if ids else None,
            f"Alert state: {alert['state']}" if alert.get("state") else None,
            f"Upgrade to {fixed} or later." if fixed else None,
        ),
        "severity": _DEPENDABOT_SEVERITY.get(
            (vuln.get("severity") or advisory.get("severity") or "").lower()
        ),
        "cwes": tuple(c["cwe_id"] for c in advisory.get("cwes") or () if c.get("cwe_id")),
        "path": dependency.get("manifest_path"),
        "line": None,
        "confidence": None,
    }


def govulncheck(raw: bytes) -> list[Fields]:
    """One finding per OSV id; a trace ending in a function means the symbol is called."""
    try:
        records = list(_json_stream(raw.decode()))
    except UnicodeDecodeError as e:
        raise ValidationError(f"govulncheck: not text: {e}") from e
    if not records or not all(
        isinstance(r, dict) and r.keys() & {"config", "progress", "osv", "finding"} for r in records
    ):
        raise ValidationError("govulncheck: expected a -json record stream")
    osvs = {r["osv"].get("id"): r["osv"] for r in records if "osv" in r}
    hits: dict[str, dict[str, Any]] = {}
    for f in (r["finding"] for r in records if "finding" in r):
        if not (osv_id := f.get("osv")):
            continue
        frame = (f.get("trace") or [{}])[0]
        hit = hits.setdefault(
            osv_id,
            {"frame": frame, "fixed": f.get("fixed_version"), "called": False, "modules": set()},
        )
        if frame.get("function"):
            hit["called"], hit["frame"] = True, frame
        if frame.get("module"):
            hit["modules"].add(f"{frame['module']}@{frame.get('version', '?')}")
    return [_govulncheck_hit(osv_id, hit, osvs.get(osv_id, {})) for osv_id, hit in hits.items()]


def _govulncheck_hit(osv_id: str, hit: dict[str, Any], osv: dict[str, Any]) -> Fields:
    aliases = ", ".join(a for a in osv.get("aliases") or () if a)
    position = hit["frame"].get("position") or {}
    reach = "symbol_reachable" if hit["called"] else "module_present"
    return {
        "label": osv_id,
        "rule": None,
        "category": "supply-chain",
        "title": f"{osv_id}: {osv.get('summary') or 'vulnerable Go dependency'}",
        "description": _lines(
            (osv.get("details") or "")[:800],
            f"Aliases: {aliases}" if aliases else None,
            f"Modules: {', '.join(sorted(hit['modules']))}" if hit["modules"] else None,
            f"Reachability: {reach}",
            f"Upgrade to {hit['fixed']} or later." if hit["fixed"] else None,
        ),
        "severity": None,
        "cwes": (),
        "path": position.get("filename"),
        "line": position.get("line"),
        "confidence": None,
    }


def _json_stream(text: str) -> Iterator[Any]:
    decoder, pos = json.JSONDecoder(), 0
    while True:
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos == len(text):
            return
        try:
            obj, pos = decoder.raw_decode(text, pos)
        except json.JSONDecodeError as e:
            raise ValidationError(f"govulncheck: malformed record at offset {pos}: {e.msg}") from e
        yield obj
