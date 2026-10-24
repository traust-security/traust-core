# Assessment documents

`widget-threat-model.json` is traust-contracts' `tests/storage_samples.py` threat-model sample
(trimmed from the live corpus and sanitized there: example hosts, ids and names), with T2
re-rated by the OWASP Risk Rating Methodology (`rated_threat_model()`), so one model carries a
legacy-labelled and a re-rated threat, ATT&CK refs, a mitigation and a tenant boundary.

`widget-operator-priv-profile.json` is the same file's operator-priv-profile sample (trimmed from
a real profile and sanitized there: example operator, image and namespace names).

`widget-isolation-review.json` is an isolation review authored to the contract (one tenant-facing
interface, one gap; example hosts and names), the shape the isolation-review skill writes.

`widget-audit-report.json` and `widget-vuln-findings.json` start from traust-contracts'
`tests/storage_samples.py` report and vuln-findings samples (example hosts and names), with the
report's placeholder text replaced by a clean container audit's.
