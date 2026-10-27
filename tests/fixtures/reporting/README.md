# Reporting documents

`widget-report.json` is `assessments/widget-audit-report.json` with three synthetic findings
(example hosts and names) that cover every SARIF mapping: categories, `effective_severity`,
`lines` ranges and unparseable lines, pseudo-paths, location descriptions, CVSS, false-positive /
risk-accepted / resolved dispositions, and a skipped probe (a degraded run).

`widget-report.sarif` and `myrepo-cloud-config-audit.sarif` are what traust-engine
`upstream/development` (`302e8e4`) `reporting/sarif.py::export` wrote for `widget-report.json`
and `cloud_config/myrepo-cloud-config-audit.json`, with `locations.sarif_tool_uri` set to
`https://tool.example/traust`.

`widget-report.md` and `widget-threat-model.md` are what traust-engine `upstream/development`
(`1f86137`) `reporting/render.py` wrote for `widget-report.json` and
`assessments/widget-threat-model.json` (`render_report`, `render_threat_model`).

`example-service-threat-model.md` and `example-mt-service-threat-model.md` are the `VALID` and
`VALID_ISOLATION` threat models of traust-engine `tests/test_lint_threat_model.py` (synthetic).
