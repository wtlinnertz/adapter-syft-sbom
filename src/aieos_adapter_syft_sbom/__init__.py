"""AIEOS adapter: sbom.generate via syft.

Invokes `syft <source> -o cyclonedx-json`, parses the output, and returns
the CycloneDX 1.6 SBOM as findings. syft produces CycloneDX natively; the
normalizer ensures AIEOS-required fields are present (bom-ref, type, name,
version on every component).
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__version__ = "1.0.0"


@dataclass
class AdapterResult:
    findings: dict[str, Any] | None
    evidence: list[str]
    exit_code: int


class SyftSbomAdapter:
    def __init__(self, syft_binary: str = "syft") -> None:
        self._syft = syft_binary

    def execute(self, inputs: dict[str, Any]) -> AdapterResult:
        source = inputs["source_path_or_image_ref"]
        # Heuristic: an OCI image ref typically carries a digest (@sha256:) or
        # a registry-style hostname (contains '.' before the first '/'). Anything
        # else is treated as a filesystem path and validated before subprocess.
        is_image_ref = "@sha256:" in source or ":" in source.rsplit("/", 1)[-1]
        if not is_image_ref:
            source_path = Path(source)
            if not source_path.exists():
                return AdapterResult(findings=None, evidence=["exit-code:2"], exit_code=2)

        fmt = inputs.get("format_preference", "cyclonedx")
        # Pin CycloneDX to 1.6 — syft defaults to a newer spec (1.7), which the
        # AIEOS schema (specVersion const "1.6") rejects.
        output_flag = "cyclonedx-json@1.6" if fmt == "cyclonedx" else "spdx-json"

        cmd = [self._syft, source, "-o", output_flag, "-q"]
        try:
            proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
        except FileNotFoundError:
            return AdapterResult(
                findings=None,
                evidence=["exit-code:127", "stderr:syft not on $PATH"],
                exit_code=127,
            )

        if proc.returncode != 0 or not proc.stdout.strip():
            return AdapterResult(
                findings=None,
                evidence=[
                    f"exit-code:{proc.returncode}",
                    "stderr:" + (proc.stderr[:500] or ""),
                ],
                exit_code=proc.returncode if proc.returncode != 0 else 3,
            )

        try:
            raw = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            return AdapterResult(
                findings=None,
                evidence=[f"exit-code:{proc.returncode}", f"stderr:json-decode: {exc}"],
                exit_code=3,
            )

        findings = ensure_aieos_sbom_shape(raw)
        return AdapterResult(
            findings=findings,
            evidence=[
                "cyclonedx-sbom:inline",
                f"component-count:{len(findings.get('components', []))}",
                f"exit-code:{proc.returncode}",
            ],
            exit_code=0,
        )


def _normalize_component(c: dict[str, Any], fallback_ref: str) -> dict[str, Any]:
    """Fill the AIEOS-required component fields (bom-ref, type, name, version).

    The AIEOS SBOM schema requires these on every component — both entries in
    components[] and the metadata.component (the scanned subject). syft omits
    version for some ecosystems and for directory-scan roots; supply
    conservative defaults so downstream validators don't reject those cases.
    """
    c = dict(c)
    c.setdefault("bom-ref", c.get("purl") or fallback_ref)
    c.setdefault("type", "library")
    c.setdefault("name", "unknown")
    c.setdefault("version", "unknown")
    return c


def ensure_aieos_sbom_shape(doc: dict[str, Any]) -> dict[str, Any]:
    """Ensure CycloneDX 1.6 + AIEOS-required component fields.

    AIEOS requires bom-ref, type, name, version on every component — both the
    entries in components[] and metadata.component (the scanned subject, which
    syft emits without a version for directory-scan roots).
    """
    out = dict(doc)
    out.setdefault("bomFormat", "CycloneDX")
    out.setdefault("specVersion", "1.6")
    components_in = out.get("components", []) or []
    out["components"] = [
        _normalize_component(c, f"component-{i}") for i, c in enumerate(components_in)
    ]
    metadata = out.get("metadata")
    if isinstance(metadata, dict):
        metadata = dict(metadata)
        if isinstance(metadata.get("component"), dict):
            metadata["component"] = _normalize_component(metadata["component"], "root-component")
        # AIEOS schema models metadata.tools as an array (CycloneDX 1.4 form);
        # syft emits the 1.5+ object form {components:[...], services:[...]}.
        tools = metadata.get("tools")
        if isinstance(tools, dict):
            metadata["tools"] = list(tools.get("components", [])) + list(tools.get("services", []))
        out["metadata"] = metadata
    return out
