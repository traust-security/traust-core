# Reporting documents

`widget-report.json` is `assessments/widget-audit-report.json` with three synthetic findings
(example hosts and names) that cover every SARIF mapping: categories, `effective_severity`,
`lines` ranges and unparseable lines, pseudo-paths, location descriptions, CVSS, false-positive /
risk-accepted / resolved dispositions, and a skipped probe (a degraded run).

`widget-report.sarif` and `myrepo-cloud-config-audit.sarif` are what traust-engine
`upstream/development` (`302e8e4`) `reporting/sarif.py::export` wrote for `widget-report.json`
and `cloud_config/myrepo-cloud-config-audit.json`, with `locations.sarif_tool_uri` set to
`https://tool.example/traust`.
