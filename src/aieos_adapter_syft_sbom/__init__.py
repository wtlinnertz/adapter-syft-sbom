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
        source_path = Path(source) if "/" in source or Path(source).exists() else None
        if source_path is not None and not source_path.exists():
            return AdapterResult(findings=None, evidence=["exit-code:2"], exit_code=2)

        fmt = inputs.get("format_preference", "cyclonedx")
        output_flag = "cyclonedx-json" if fmt == "cyclonedx" else "spdx-json"

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


def ensure_aieos_sbom_shape(doc: dict[str, Any]) -> dict[str, Any]:
    """Ensure CycloneDX 1.6 + AIEOS-required component fields.

    AIEOS requires every component entry to carry bom-ref, type, name, version.
    syft populates these for most ecosystems but occasionally emits a component
    without a version; this normalizer supplies 'unknown' as a conservative
    default so downstream validators don't reject on syft's edge cases.
    """
    out = dict(doc)
    out.setdefault("bomFormat", "CycloneDX")
    out.setdefault("specVersion", "1.6")
    components_in = out.get("components", []) or []
    components_out = []
    for i, c in enumerate(components_in):
        c = dict(c)
        c.setdefault("bom-ref", c.get("purl") or f"component-{i}")
        c.setdefault("type", "library")
        c.setdefault("name", "unknown")
        c.setdefault("version", "unknown")
        components_out.append(c)
    out["components"] = components_out
    return out
