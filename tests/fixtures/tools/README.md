# Toolchain config

`external-tools.yaml` and `safe-exec-profiles.yaml` are traust-engine's estate-neutral test config
(`tests/fixtures/config/`, `development` at `1f86137`): the tool pins and safe-exec profiles of a
default deployment, with no operational data.

`gitleaks-rules.toml` is one rule (`traust-openshift-sha256-token`) copied from traust-engine's
bundled `gitleaks-default.toml` (`development` at `1f86137`) over gitleaks' default set: a test
rule set, not the pack's.
