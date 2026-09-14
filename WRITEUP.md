# Reversing the Cruciferra BYOVD pair - DCRCVDrv.sys + Alinubx.sys

*Companion write-up to 0xCr0ssCrush. Static reverse engineering of the two
signed kernel drivers eSentire's Threat Response Unit caught the Cruciferra
Malware-as-a-Service loader abusing to kill AV/EDR processes.*

## Evidence notation

Every claim in this document carries one of four labels:

| Label | Meaning |
|---|---|
| [CONFIRMED] | Directly established from code or disassembly |
| [CORROBORATED] | Observed in this analysis and independently supported by external reporting |
| [INFERRED] | Likely based on control flow, but not fully proven |
| [UNRESOLVED] | Current evidence is insufficient |

Per-driver analysis with the same notation is split into
[docs/dcrcv-analysis.md](docs/dcrcv-analysis.md) and
[docs/alinubx-analysis.md](docs/alinubx-analysis.md).

## TL;DR

| | DCRCVDrv.sys | Alinubx.sys |
|---|---|---|
| Vendor | MOCOMSYS & DCRC (South Korea) | CnCrypt Foundation |
| Signature | MocoMsys (DigiCert) | Microsoft Windows Hardware Compatibility Publisher |
| Device | `\Device\DCRCVDRV_U` -> `\\.\DCRCVDRV_U` | `\Device\Alinubx` -> `\\.\Alinubx` |
| Kill IOCTL | `0x2205C0` | `0x222024` |
| Buffer | 4-byte PID | `{ pid: DWORD, exit_status: DWORD }` |
| SHA-256 | `87e8d39db624f37d3e77aedf487a2dfd197f71a4730ea74f4e7a4341deaec2ff` | `611b3ba687b7f46319a19609605ddfe5225e6d85277d8e923eea3fdb6f7b5b61` |
| MS VDBL (2026-09-08) | Absent | Absent |

Both drivers expose an unauthenticated interface that terminates
arbitrary processes from kernel context. Both were observed in
threat-actor loaders before any public implementation was cataloged.

## Campaign context

eSentire TRU, *"Malware-as-a-Service Cocktail: ErrTraffic and
Cruciferra - Killing Your EDR Since 2025"* (2026-08-19):

- **ErrTraffic** ($380/mo) - ClickFix lure generation; victims are
  driven through a WordPress inject to a loader stage.
- **Cruciferra** ($1,200/mo for the EDR-killing package) - a .NET
  loader with DLL side-loading via `ServiceModelReg.exe`, process
  hollowing, FNV-1a process-name hashing, and 145 default AV/EDR
  targets configured in the loader.
- When EDR-kill is enabled, the loader: writes `DCRCVDrv.sys` to
  `C:\Windows\Temp\DCRCVDrv.sys`, creates a service, opens
  `\\.\DCRCVDRV_U`, and sends **IOCTL `0x2205C0`** per PID.
  [CORROBORATED]

The 145-name target list is a **loader configuration** (the crypter
panel config, FNV-1a hashed), not a driver constant. Both drivers are
PID-driven; neither embeds an AV/EDR name list.
[CONFIRMED - driver strings show only vendor component names, see
docs/dcrcv-analysis.md]

## DCRCVDrv.sys analysis

### Sample

```
SHA-256  87e8d39db624f37d3e77aedf487a2dfd197f71a4730ea74f4e7a4341deaec2ff
SHA-1    47d922b0fd5d704025d14ef98ded46e74830a423
MD5      567c158ee0858f8e941d4ab7a6c18dbc
AMD64, PE timestamp 0x639BE3C9, entry 0x2A008 (RVA)
```

### Imports [CONFIRMED]

Process-control imports in ntoskrnl.exe:

```
PsLookupProcessByProcessId  0x3E038
ZwOpenProcess               0x3E0E8
ZwTerminateProcess          0x3E108
ObOpenObjectByPointer       0x3E110
ZwClose                     0x3E0C0
```

### Device objects [CONFIRMED]

```
\Device\DCRCVDRV_U
\DosDevices\DCRCVDRV_U
\BaseNamedObjects\__DCRCV_CHILD_PROCESS_MON_SHARE_EVENT_{32,64}__
\Device\DCRCFS
\BaseNamedObjects\__DCRCV_U_WFP_FILTER_ADD_
```

The driver additionally carries WFP callout strings and
child-process/duplicate-file event objects, indicating vendor
monitoring functionality. [INFERRED] The embedded executable names
(`cdsMsgServer.exe`, `allegro.exe`, `Capture.exe`, ...) are vendor
components, not an attacker target list. [CONFIRMED]

### IOCTL dispatch [CONFIRMED]

Device-control entry at RVA 0x14964, sub/je compare chain. Decoded
cases:

| IOCTL | handler | min input | purpose |
|---|---|---|---|
| 0x2204FC | 0x149EB | 8 | state query |
| 0x220530..0x220540 | 0x14A14..0x14AF6 | 4..12 | config/state |
| 0x2205C0 | 0x149C3 | 4 | process termination |
| 0x220600, 0x22061C | 0x14B41, 0x14DA6 | - | additional surface |

Kill case at 0x149C3:

```
cmp  [inlen], 4
jb   error
mov  rcx, [input]        ; PID = first DWORD
call sub_12280           ; process termination helper
```

### Termination helper 0x12280

The helper obtains a process handle and terminates:

- `0x122A9`: OBJECT_ATTRIBUTES setup (Length 0x30, Attributes 0x240)
- `0x122CE`: call through import slot 0x2E0E8 - ZwOpenProcess
- `0x122F0`: call through import slot 0x2E038 -
  PsLookupProcessByProcessId
- termination path via ZwTerminateProcess

[CONFIRMED - both import slots are referenced inside the helper]
UNRESOLVED for the exact branch selection between the two handle
sources: the code reaches the terminate call in both cases, and the
observable behavior - a kernel-mode handle on the target followed by
termination - is identical. eSentire's report describes the same
helper (sub_12280 -> ZwTerminateProcess). [CORROBORATED]

## Alinubx.sys analysis

### Sample

```
SHA-256  611b3ba687b7f46319a19609605ddfe5225e6d85277d8e923eea3fdb6f7b5b61
SHA-1    172c5ce3afab6d63fe12a7e036f20271b9d09c13
MD5      10b3049f4a954665512eca5d24728c89
AMD64, PE timestamp 0x641D84B1, entry 0x50954 (RVA, INIT section)
```

The .KRT section and INIT entry follow the same protector prologue
seen in other legacy drivers; a build-lineage marker. [INFERRED]

### Imports [CONFIRMED]

```
PsLookupProcessByProcessId  0x5A578
ObOpenObjectByPointer       0x5A290
ZwTerminateProcess          0x5A288
ZwClose                     0x5A728
```

### Device objects [CONFIRMED]

```
\Device\Alinubx
\DosDevices\Alinubx
```

WFP/ALE callout strings ("Alinubx ALE Connect Classify", ...) suggest
a transmission-control driver surface. [INFERRED]

### IOCTL contract

IOCTL `0x222024` with `{ pid: DWORD, exit_status: DWORD }`.
[CORROBORATED - documented by eSentire TRU / LOLDrivers and
reproduced here]

### Termination semantics - resolved

Earlier drafts described an `exit_status` field while the harness sent
`0`. Resolution of the ambiguity:

- PID at +0x00 is consumed by the termination helper.
  [CONFIRMED - first DWORD feeds the terminate path]
- Value at +0x04 propagates toward the terminate call on the primary
  path as the exit-status argument. [INFERRED - not exhaustively
  proven across every branch]
- Sending `0` at +0x04 yields a normal termination on the observed
  path. [CONFIRMED]

The harness sends `exit_status = 0`, consistent with the normal-
termination behavior.

## Access control [INFERRED]

Both drivers create their devices via standard `IoCreateDevice`
without a secure-creation variant visible in the imports. When
loaded, the devices are reachable without an elevation check on the
documented IOCTL path. Exact DACL behavior was not independently
measured on a non-elevated context.

## PoCs (this repository)

- `src/drv.rs` - per-driver contract and device handle
- `src/loader.rs` - SCM lifecycle with service ownership
- `src/validation.rs` - SHA-256 sample validation before load
- `src/reporting.rs` - normalized research output (console + JSON)
- `src/main.rs` - twin-fallback orchestration

The harness validates driver hashes before any registration, reports
IOCTL submission as distinct from operation result
(docs/architecture.md), and never deletes services it does not own.

## Limitations

- Process-protection (PPL) targets were not terminable through these
  interfaces during testing; the handle opened on the observed paths
  was insufficient against PPL-protected processes.
- Alinubx.sys exit-status propagation: [INFERRED].
- DCRCVDrv.sys handle-source branch selection: [UNRESOLVED].
- Device DACL behavior: [INFERRED].
- Blocklist status is snapshot-specific (docs/blocklist-status.md).

## References

- eSentire TRU, *"Malware-as-a-Service Cocktail: ErrTraffic and
  Cruciferra - Killing Your EDR Since 2025"* (2026-08-19)
- eSentire TRU IoCs (DCRCVDrv.sys `87e8d39d...`)
- LOLDrivers - DCRCVDrv.sys (89643454-e38b-41cb-853d-abf649a104a5),
  Alinubx.sys (84a3007a-de5e-4622-bfc5-f05d927c3618), both 2026-08-27
- Microsoft Vulnerable Driver Blocklist (snapshot 2026-09-08)

## Responsible use

For authorized research and testing only. Loading these drivers on
systems you do not own is illegal in most jurisdictions. See
SECURITY.md.