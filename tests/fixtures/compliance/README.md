Copied from traust `fabdb13`: `compliance-mapping.json` is traust-engine's `data/compliance/compliance-mapping.yaml` (as JSON); `checks/<check>/{good,bad}/snapshot.json` are the per-check calibration snapshots from traust `tests/fixtures/compliance/fixtures/`. Synthetic data, nothing to sanitize.

`efficacy/` is traust `fabdb13` `tests/fixtures/compliance/efficacy/seeded-target/`: `cloud-inventory.json` and `khs.json` verbatim, `expected-verdicts.json` the answer key from `expected-verdicts.yaml` (its `run:` block becomes the test's `EvaluationRequest`; its comments, which say why each verdict is true by construction, are in the test). The findings leg (`findings-rows.json`: one open confirmed critical CWE-1104) and `org-parameters.yaml` (`allowed_data_regions: [us-east-1, eu-west-1]`) are built in the test. Synthetic data, nothing to sanitize.

`security-hardening-excerpt.html` is an attributed, CC BY-SA 3.0 excerpt retrieved with
stock curl from Red Hat's RHEL 9 Security hardening guide on 2026-11-03. It retains the
real section, heading-link, tooltip and inline-code markup used by the local TLS
transport regression; only the excerpt boundary is closed. The original URL and
license are in the fixture.
