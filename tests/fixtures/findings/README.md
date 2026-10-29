Identity vectors copied from traust-ledger at d1b589a (tests/fixtures/); repositories are example hosts.
Scanner outputs under scanners/ are the synthetic CodeQL SARIF, Dependabot alerts and govulncheck stream from traust's tests/test_normalize_input.py (fabdb13); no real hosts or repositories.
scanners/codeql-symbols.sarif adapts that sanitized CodeQL fixture with a standard SARIF indexed enclosing-function location for the scanner-to-precedent regression.
triage/: the triage skill's canary target and the triage report from traust's tests/test_triage_tooling.py (fabdb13); synthetic C/YAML, no real code.
scanners/hash_claim_scanner.py is an offline test producer over hash-target.py: it detects print calls, emits their enclosing symbols and hashes the actual input bytes. Its output is exercised through record_scan and triage preparation; it is not a captured production-scanner report. Parser mutation cases derive from the existing synthetic CodeQL fixture.
