# adapter-syft-sbom

AIEOS adapter: `sbom.generate` via syft. syft produces CycloneDX 1.6 JSON
natively; the adapter ensures AIEOS-required component fields (bom-ref,
type, name, version) are present and returns the SBOM as findings.

```bash
pip install -e '.[dev]'
pytest
```

MIT.
