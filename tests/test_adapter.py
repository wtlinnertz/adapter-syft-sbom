"""Unit tests for adapter-syft-sbom."""

from __future__ import annotations

import json
from unittest.mock import patch

from aieos_adapter_syft_sbom import SyftSbomAdapter, ensure_aieos_sbom_shape


class _Proc:
    def __init__(self, rc: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = rc
        self.stdout = stdout
        self.stderr = stderr


SYFT_CDX_SAMPLE = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [
        {
            "bom-ref": "pkg:npm/example@1.0.0",
            "type": "library",
            "name": "example",
            "version": "1.0.0",
            "purl": "pkg:npm/example@1.0.0",
        }
    ],
}


def test_ensure_sbom_shape_fills_in_missing_required_fields():
    raw = {"components": [{"purl": "pkg:foo/a@1"}]}
    out = ensure_aieos_sbom_shape(raw)

    assert out["bomFormat"] == "CycloneDX"
    assert out["specVersion"] == "1.6"
    c = out["components"][0]
    assert c["bom-ref"] == "pkg:foo/a@1"
    assert c["type"] == "library"
    assert c["name"] == "unknown"
    assert c["version"] == "unknown"


def test_ensure_sbom_shape_normalizes_metadata_component():
    raw = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"type": "file", "name": "requirements.txt"}},
        "components": [],
    }
    out = ensure_aieos_sbom_shape(raw)
    mc = out["metadata"]["component"]
    assert mc["version"] == "unknown"
    assert mc["bom-ref"] == "root-component"
    assert mc["type"] == "file"
    assert mc["name"] == "requirements.txt"


def test_execute_happy_path(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    with patch("subprocess.run", return_value=_Proc(0, json.dumps(SYFT_CDX_SAMPLE))):
        result = SyftSbomAdapter().execute({"source_path_or_image_ref": str(src)})

    assert result.exit_code == 0
    assert result.findings["specVersion"] == "1.6"
    assert any("cyclonedx-sbom:inline" in e for e in result.evidence)
    assert any("component-count:1" in e for e in result.evidence)


def test_execute_oci_image_ref_pass_through(tmp_path):
    captured = {}

    def _cap(cmd, **kw):
        captured["cmd"] = cmd
        return _Proc(0, json.dumps(SYFT_CDX_SAMPLE))

    with patch("subprocess.run", side_effect=_cap):
        SyftSbomAdapter().execute({"source_path_or_image_ref": "ghcr.io/example/app:1.0"})
    # The image ref appears in the command unchanged.
    assert "ghcr.io/example/app:1.0" in captured["cmd"]


def test_execute_format_preference_forwards_flag(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    captured = {}

    def _cap(cmd, **kw):
        captured["cmd"] = cmd
        return _Proc(0, json.dumps({"packages": []}))

    with patch("subprocess.run", side_effect=_cap):
        SyftSbomAdapter().execute(
            {"source_path_or_image_ref": str(src), "format_preference": "spdx"}
        )
    assert "spdx-json" in captured["cmd"]


def test_execute_binary_not_installed(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = SyftSbomAdapter().execute({"source_path_or_image_ref": str(src)})
    assert result.exit_code == 127


def test_execute_malformed_json(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    with patch("subprocess.run", return_value=_Proc(0, "not json")):
        result = SyftSbomAdapter().execute({"source_path_or_image_ref": str(src)})
    assert result.findings is None and result.exit_code == 3


def test_execute_missing_source_path(tmp_path):
    """A filesystem path that doesn't exist is rejected before subprocess."""
    result = SyftSbomAdapter().execute({"source_path_or_image_ref": str(tmp_path / "nope")})
    assert result.exit_code == 2
