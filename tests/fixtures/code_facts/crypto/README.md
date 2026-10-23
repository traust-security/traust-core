# Crypto probe parity fixture

`repo/` is a public-safe sample checkout shaped like a FIPS-built Go operator with Node, Python,
JVM, Rust, C, .NET and Ruby side projects; hostnames are `example.com`, hashes are placeholders.
`sbom.cdx.json` is a CycloneDX SBOM of the same sample.

`legacy-crypto-probe.json` is the output of the legacy source tier over it, recorded 2026-10-24:
`probe_repo(repo) + probe_sbom(sbom.cdx.json)` from traust-engine
`src/traust_engine/adapters/crypto_probe.py` at `60d2e7e93d157c44607535aa89f685ccd11103bf`
(`origin/development`), facts as `dataclasses.asdict`. Tests never run the legacy code.

The parity tests split it:
- 27 of the facts are what the checkout configures. The core `CryptoProbe` reproduces them
  field for field.
- The other 8 are crypto packages. Core reads those from the dependency rows of the ref's
  ingested manifest SBOM, through `CodeFactsService.crypto`.

`manifest-sbom.cdx.json` is hand-written in the shape of `syft 1.51.1 dir:<repo>` CycloneDX
output, with syft properties trimmed to `foundBy` and location. It lists every package the
legacy dependency facts name, as syft would with lockfiles. It also has dependency edges
(root -> packages, rustls -> ring), so both direct and transitive rows are mapped. It tests the
row -> fact mapping, not what a real scan of `repo/` finds. The rpmdb `openssl-libs` that
`sbom.cdx.json` carries is left out: it's an image OS package, which `syft dir:` never emits,
and it belongs to the image tier.

`syft-dir-scan.cdx.json` is the real `syft 1.51.1 scan dir:repo -o cyclonedx-json` output,
recorded 2026-10-23, with the scan path replaced by `/sample`. It finds only `cryptography`,
`flask`, `golang.org/x/crypto` and `github.com/golang-fips/openssl/v2`, and no dependency edges,
so nothing is marked direct. The other crypto packages need lockfiles that `repo/` lacks:
- `pyjwt>=2.9.0` is unpinned
- `Cargo.toml` has no `Cargo.lock`
- `Gemfile` has no `Gemfile.lock`
- `Sample.csproj` has no `packages.lock.json`, which .NET only writes when opted in

syft has no `rpms.lock.yaml` cataloger, so `CRYPTO_RPM_NEVRA` stays in the probe.
