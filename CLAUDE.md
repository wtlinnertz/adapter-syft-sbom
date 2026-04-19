# AIEOS Adapter — sbom.generate via syft

Claims: `sbom.generate` at 1.0.0. Contract: `aieos-governance-foundation/contracts/sbom.generate.contract.yaml`.
Findings schema: `findings/schemas/cyclonedx-1.6-sbom.schema.json`.

Inputs: source_path_or_image_ref (filesystem dir or OCI ref),
format_preference (cyclonedx default; spdx alternative).

Unit tests mock subprocess. Real conformance requires syft on $PATH.
