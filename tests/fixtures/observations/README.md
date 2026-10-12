# Observation reference provenance

`reference.json` and `recorded-github.json` were copied unchanged from [Traust PR #58](https://github.com/traust-security/traust/pull/58). The reference contains thirteen legacy observation cases, including one replay of sanitized public GitHub metadata/comparison output; the other inputs are synthetic. Source revision, capture context and checksums are recorded in those files. These are observation expectations, not the 302 routing decisions from XWING-2216.

No network or fixture regeneration is required to run the Core tests. Test fakes supply the recorded data through SourceProvider. Keep the original reference when moving code; investigate mismatches instead of regenerating expected output.
