# MAPPING — adapter-syft-sbom

## Tool

`syft <source> -o cyclonedx-json` for CycloneDX (AIEOS primary); `-o spdx-json`
for the accepted SPDX 2.3 alternative. syft accepts both filesystem paths and
OCI image references; the adapter passes the input through unchanged.

## Normalization

syft emits CycloneDX 1.6 natively. The adapter only backfills AIEOS-required
component fields that syft occasionally omits:

- `bom-ref` — defaults to the component's `purl` or `component-<index>`.
- `type` — defaults to "library".
- `name`, `version` — default to "unknown".

These defaults are conservative; real syft output populates all four for
managed-ecosystem components.

## Evidence

`cyclonedx-sbom:inline`, `component-count:<N>`, `exit-code:<N>`.

## Exit code

0 on parsed output; 2 when source path doesn't exist; 127 binary missing;
3 malformed JSON or zero-exit empty output.
