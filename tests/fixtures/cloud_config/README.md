# Recorded Checkov output

`checkov-3.3.6.json` is actual `checkov 3.3.6 --output json --skip-download --compact
--skip-framework secrets` output over the public-safe sample in `source/`, recorded 2026-10-23
(passed checks and unused keys dropped for size; the scan root rewritten to
`/work/clone-a/myrepo`). It contains no estate data. traust's legacy `run_checkov.py`
(`origin/development`) normalizes it to 33 facts with snapshot id `68045f8c…0dea`.

`myrepo-cloud-config-audit.json` is a report over those facts, written the way the
skill's Phase 2 does.
