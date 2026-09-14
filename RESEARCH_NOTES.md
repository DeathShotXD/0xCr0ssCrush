# Research notes

Working notes and methodology behind the analysis. This file tracks
how conclusions were reached and what remains open; it is updated as
the analysis evolves.

## 2026-09-10 - initial analysis pass

- Downloaded both samples from the LOLDrivers binary mirror and
  verified all hashes against eSentire TRU IoC reporting and the
  LOLDrivers YAML registry before including them in the repository.
- Import screening: both drivers import the process-control family
  (PsLookupProcessByProcessId, ObOpenObjectByPointer,
  ZwTerminateProcess). DCRCVDrv.sys additionally imports
  ZwOpenProcess.
- Device object names recovered from wide strings: \\.\DCRCVDRV_U and
  \\.\Alinubx.
- DCRCVDrv.sys IOCTL dispatch located at RVA 0x14964; kill case
  0x2205C0 leads to the termination helper at RVA 0x12280.
- DCRCVDrv.sys accepted the input PID as the first DWORD (>= 4 byte
  input). Alinubx.sys contract (PID at +0, exit status at +4) matches
  eSentire/LOLDrivers documentation for 0x222024.
- Confirmed the driver binaries contain no embedded AV/EDR target
  list; the documented 145-name list is a loader configuration. See
  the writeup and dcrcv-analysis.md.

## Open questions

- Alinubx.sys exit-status propagation is marked [INFERRED] in
  docs/alinubx-analysis.md; the harness sends 0 on the normal
  path and the propagation branch has not been exhaustively traced.
- DCRCVDrv.sys handle-source selection (ZwOpenProcess vs
  PsLookupProcessByProcessId path) is marked [UNRESOLVED] in
  docs/dcrcv-analysis.md. Behavior is identical on the observed path.
- Device DACL behavior was not independently measured on a non-
  elevated context; marked [INFERRED] in both analysis documents.
- Full IOCTL surface of Alinubx.sys is [UNRESOLVED]; only the
  documented kill IOCTL is asserted.

## Verification procedure

Independent reproduction steps are documented in
docs/reproduction.md. When adding evidence, record the artifact (for
example the annotated disassembly file in analysis/) so the claim can
be re-walked.