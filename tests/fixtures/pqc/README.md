# PQC readiness fixtures

`legacy-census-facts.json` is the legacy Layer-1 adapter's census half over the crypto-probe
parity fixture (`../code_facts/crypto/`), recorded 2026-10-24: `pqc_facts._adapter_native_facts`
then `_post_process` from traust `harnessing/3-audit/pqc-readiness/scripts/pqc_facts.py` at
`c2d4fbe6f7c7325e7ef8a81901e1bcfce38ea229`, fed the recorded `probe_repo` facts of
`legacy-crypto-probe.json` (SBOM components excluded, as the source mode never read them),
facts as `Fact.to_dict()`. Tests never run the legacy code.

`widget-pqc-readiness.json` is a Layer-2 report in the shape the skill emits (SKILL.md example
and the legacy validator's fixtures); repository, commit, paths and vendor are placeholders.

`vendor-claims.json` is six vendors of the curated registry `build_pqc_vendor_tracker.py` read
(`<results-root>/pqc/inputs/vendor-registry.json`, reviewed 2026-07-19), reshaped to the
contracts `pqc-vendor-claims` document: `graph_deps` became full package names, `status_note`
the `claim`; internal owners, repositories and products were removed from the claims and a
public source URL and a team reviewer were added (the legacy registry carried neither).
