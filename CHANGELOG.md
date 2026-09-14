# Changelog

All notable changes to this repository are documented here.

## 0.1.0 (research baseline)

- Initial research harness for DCRCVDrv.sys and Alinubx.sys.
- Reverse engineering writeup with evidence notation.
- Driver samples with verified hashes.
- Detections (Sigma, YARA, telemetry guidance).
- Metadata registry and validation script.

## 1.0.0 (research release) - in progress

- Service ownership model: only self-created services are cleaned up.
- Sample hash validation before any driver registration.
- Stable JSON output contract (docs/architecture.md).
- Twin-fallback driver selection.
- Strict evidence notation applied across the writeup and analysis
  documents.
- Documentation split into docs/ with per-driver analysis,
  IOCTL reference, provenance, blocklist status, reproduction, and
  detection guides.
- Threat model and research notes added.
- CI workflow added (fmt, clippy, test, build, metadata validation).
- Lab test matrix and manifests added.
- Removed stealth-oriented options from the research build
  (self-destruct, VM/debugger gating, silent redirection).