# Driver provenance

Every claim about a driver in this repository is hash-specific. A
filename is not a stable identifier: the same name can be carried by
different binaries, and the same binary can be shipped under different
names. The entries below describe the exact samples analyzed here.

The machine-readable registry lives in `metadata/drivers.json` and is
validated against this document and the writeup by
`scripts/validate_metadata.py`.

## DCRCVDrv.sys - sample 87e8d39d...

| Field | Value |
|---|---|
| Filename | DCRCVDrv.sys |
| SHA-256 | 87e8d39db624f37d3e77aedf487a2dfd197f71a4730ea74f4e7a4341deaec2ff |
| SHA-1 | 47d922b0fd5d704025d14ef98ded46e74830a423 |
| MD5 | 567c158ee0858f8e941d4ab7a6c18dbc |
| Architecture | AMD64 |
| Signer | MocoMsys / MOCOMSYS |
| Company | MOCOMSYS & DCRC |
| Version | 1.0.0 series (file version 1, 0, 0, 16 lineage) |
| Device | \\.\DCRCVDRV_U |
| IOCTL | 0x2205C0 |
| Primitive | PROCESS_TERMINATION |
| Campaign references | eSentire TRU Cruciferra report (2026-08-19) |
| External references | LOLDrivers 89643454-e38b-41cb-853d-abf649a104a5 |
| Blocklist observation | absent from MS VDBL snapshot (see blocklist-status.md) |

## Alinubx.sys - sample 611b3ba6...

| Field | Value |
|---|---|
| Filename | Alinubx.sys |
| SHA-256 | 611b3ba687b7f46319a19609605ddfe5225e6d85277d8e923eea3fdb6f7b5b61 |
| SHA-1 | 172c5ce3afab6d63fe12a7e036f20271b9d09c13 |
| MD5 | 10b3049f4a954665512eca5d24728c89 |
| Architecture | AMD64 |
| Signer | Microsoft Windows Hardware Compatibility Publisher |
| Company | CnCrypt Foundation |
| Device | \\.\Alinubx |
| IOCTL | 0x222024 |
| Primitive | PROCESS_TERMINATION |
| Campaign references | Cruciferra loader associated (eSentire TRU 2026-08-19) |
| External references | LOLDrivers 84a3007a-de5e-4622-bfc5-f05d927c3618 |
| Blocklist observation | absent from MS VDBL snapshot (see blocklist-status.md) |

## Sample acquisition

Both samples were obtained from the LOLDrivers project binary mirror
and verified against the hashes published in eSentire TRU IoC data and
the LOLDrivers YAML registry before being committed to `driver/`.
Digest verification instructions are in `docs/reproduction.md`.

## Scope of provenance

This registry describes the samples analyzed and shipped here. It
does not claim to describe every binary that has ever carried either
filename. External samples with the same filename should always be
verified against the SHA-256 digests above (or their own published
digests) before assumptions are drawn from either document.