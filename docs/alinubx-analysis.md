# Alinubx.sys - analysis

Reverse engineering notes for the CnCrypt driver.

## Evidence notation

| Label | Meaning |
|---|---|
| [CONFIRMED] | Directly established from code or disassembly |
| [CORROBORATED] | Observed in this analysis and independently supported by external reporting |
| [INFERRED] | Likely based on control flow, not fully proven |
| [UNRESOLVED] | Current evidence is insufficient |

## Sample

| Field | Value |
|---|---|
| File | Alinubx.sys |
| SHA-256 | 611b3ba687b7f46319a19609605ddfe5225e6d85277d8e923eea3fdb6f7b5b61 |
| SHA-1 | 172c5ce3afab6d63fe12a7e036f20271b9d09c13 |
| MD5 | 10b3049f4a954665512eca5d24728c89 |
| Size | 538,664 bytes |
| Architecture | AMD64 |
| PE timestamp | 0x641D84B1 |
| Entry | 0x50954 (RVA, INIT section) |
| Sections | 8 (text, rdata, data, pdata, .KRT, INIT x2, rsrc, reloc) |

The .KRT section and the INIT-located entry follow the same protector
prologue seen in other legacy drivers (rspot.sys family), a build
lineage marker rather than an attacker artifact. [INFERRED]

## Imports [CONFIRMED]

ntoskrnl.exe process-control imports:

| Import | Address |
|---|---|
| PsLookupProcessByProcessId | 0x5A578 |
| ObOpenObjectByPointer | 0x5A290 |
| ZwTerminateProcess | 0x5A288 |
| ZwClose | 0x5A728 |

## Device objects [CONFIRMED]

```
\Device\Alinubx
\DosDevices\Alinubx
```

User-mode path: \\.\Alinubx [CONFIRMED]

Additional strings indicate WFP/ALE classification callouts
("Alinubx ALE Connect Classify" and similar), consistent with a
network-transmission control driver. [INFERRED]

## IOCTL contract

Documented IOCTL: 0x222024. [CORROBORATED - described in
eSentire/LOLDrivers reporting and reproduced in this analysis]

Input layout (two DWORDs):

```
+0x00  DWORD  pid
+0x04  DWORD  exit_status
```

## Termination semantics - resolved

The writeup previously described the exit_status field while the
harness sends 0. The resolution: the driver's dispatch passes the
input structure through to its termination helper; the helper reads
the PID at +0x00 and uses the value at +0x04 as the exit status
argument when terminating. Sending 0 produces a normal termination on
the observed path.

Evidence by branch:

- PID consumption at +0x00: [CONFIRMED] the helper for this IOCTL
  reads the first DWORD and passes it to the terminate path.
- Exit status at +0x04: [INFERRED] the second DWORD is present in the
  input and is propagated to the terminate call on the primary path;
  the exact propagation for every code path was not exhaustively
  proven.

The harness sends exit_status = 0, matching the normal-termination
behavior documented in the reverse engineering notes.

## Access control [INFERRED]

Standard IoCreateDevice without a secure-creation variant in the
import set; reachable from a non-elevated context when loaded. Exact
DACL behavior not independently tested.

## External references

- eSentire TRU, "Malware-as-a-Service Cocktail: ErrTraffic and
  Cruciferra - Killing Your EDR Since 2025" (2026-08-19)
- LOLDrivers entry 84a3007a-de5e-4622-bfc5-f05d927c3618 (2026-08-27)