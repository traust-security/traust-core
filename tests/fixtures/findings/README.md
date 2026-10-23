Identity vectors copied from traust-ledger at d1b589a (tests/fixtures/); repositories are example hosts.
Scanner outputs under scanners/ are the synthetic CodeQL SARIF, Dependabot alerts and govulncheck stream from traust's tests/test_normalize_input.py (fabdb13); no real hosts or repositories.
scanners/codeql-symbols.sarif adapts that sanitized CodeQL fixture with a standard SARIF indexed enclosing-function location for the scanner-to-precedent regression.
triage/: the triage skill's canary target and the triage report from traust's tests/test_triage_tooling.py (fabdb13); synthetic C/YAML, no real code.
