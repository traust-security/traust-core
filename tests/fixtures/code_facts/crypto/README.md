# Crypto probe parity fixture

`repo/` is a public-safe sample checkout shaped like a FIPS-built Go operator with Node, Python,
JVM, Rust, C, .NET and Ruby side projects; hostnames are `example.com`, hashes are placeholders.
`sbom.cdx.json` is a CycloneDX SBOM of the same sample.

`legacy-crypto-probe.json` is the output of the legacy source tier over it, recorded 2026-10-24:
`probe_repo(repo) + probe_sbom(sbom.cdx.json)` from traust-engine
`src/traust_engine/adapters/crypto_probe.py` at `60d2e7e93d157c44607535aa89f685ccd11103bf`
(`origin/development`), facts as `dataclasses.asdict`. Tests never run the legacy code.

The parity test splits it. 27 facts are what the checkout configures; the core `CryptoProbe`
reproduces them field for field. The other 8 are crypto packages (Python deps, Rust TLS
backends, .NET packages, Ruby gems, SBOM components). Core reads those from the dependency rows
of the ref's ingested manifest SBOM, so the test ingests `manifest-sbom.cdx.json` and compares
through `CodeFactsService.crypto`, listing what the rows can't carry.

`manifest-sbom.cdx.json` is hand-written in the shape of `syft 1.51.1 dir:<repo>` CycloneDX
output (syft properties trimmed to `foundBy` and location). It holds the packages that
`sbom.cdx.json` and the manifests in `repo/` name. A real `syft scan dir:repo` finds only
`cryptography`, `flask`, `golang.org/x/crypto` and `github.com/golang-fips/openssl/v2`. The
others need lockfiles syft reads and `repo/` lacks: `pyjwt>=2.9.0` is unpinned, and
`Cargo.toml`, `Gemfile` and `Sample.csproj` have no `Cargo.lock`, `Gemfile.lock` or
`packages.lock.json`. The locations name those lockfiles. `golang-fips/openssl/v2` is left out
because `sbom.cdx.json` doesn't list it (its go.mod signal is `CRYPTO_GO_FIPS_BACKEND`).
`openssl-libs` comes over from `sbom.cdx.json`: syft lists rpms only from an rpmdb or `.rpm`
files, and has no `rpms.lock.yaml` cataloger, which is why `CRYPTO_RPM_NEVRA` stays in the probe.
