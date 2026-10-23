# Crypto probe parity fixture

`repo/` is a public-safe sample checkout shaped like a FIPS-built Go operator with Node, Python,
JVM, Rust, C, .NET and Ruby side projects; hostnames are `example.com`, hashes are placeholders.
`sbom.cdx.json` is a CycloneDX SBOM of the same sample.

`legacy-crypto-probe.json` is the output of the legacy source tier over it, recorded 2026-10-24:
`probe_repo(repo) + probe_sbom(sbom.cdx.json)` from traust-engine
`src/traust_engine/adapters/crypto_probe.py` at `60d2e7e93d157c44607535aa89f685ccd11103bf`
(`origin/development`), facts as `dataclasses.asdict`. The parity test runs the core
`CryptoProbe` over the same files and compares fact for fact. Tests never run the legacy code.
