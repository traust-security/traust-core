# Versioning

Additive (stays in `v1`): new module, new optional field, new method, new provider, new view row type.

Breaking (needs `v2`): rename, removed field, changed signature, changed behaviour, required field added.

For a breaking change:

1. Create `src/traust_core/v2/<package>/` with only the changed modules; import the rest from `v1`.
2. Mirror tests in `tests/v2/`.
3. Leave `v1` untouched and importable.
4. `v2` may import `v1`; `v1` never imports `v2`.
5. README: note the new version and what moved.
