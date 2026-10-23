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

## Image and cluster tiers

`image/` was recorded on 2026-10-23 from the public `registry.access.redhat.com/ubi9/ubi-minimal`,
pinned at `sha256:2d4c4551af6831dcd26bbf86108c4385de5183ec8fe6b5868f6f9640fe47f4ed` (linux/arm64):
- `syft-image-scan.cdx.json`: `syft 1.51.1 scan <image> -o cyclonedx-json`, trimmed to the
  package components (file components dropped; syft properties cut to `foundBy` and location;
  licenses, CPEs and the serial number removed). The edges between kept components stay.
- `legacy-image-sbom-probe.json`: legacy `crypto_probe.probe_sbom` over that file (traust-engine
  `60d2e7e`), facts as `dataclasses.asdict`. This is the image OS-package half of `--from-sbom`.
- `podman-image-inspect.json`: `podman image inspect` of the same image, cut to the fields the
  tier reads.

`cluster/` holds `openssl 3.6.4 s_client` transcripts against a local `s_server` with a throwaway
self-signed `CN=svc.example.com` certificate (TLS 1.3, TLS 1.2, refused connection). It also holds
`legacy-parse-tls.json`, legacy `crypto_audit._parse_tls_output` over each transcript, and
`pod-crypto-no-openssl.txt`, the pod crypto probe's output in ubi9-minimal, which has no
`openssl`, so the shell exits 127.
