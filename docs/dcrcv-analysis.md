# DCRCVDrv.sys - analysis

Full reverse engineering notes for the MocoMsys driver.

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
| File | DCRCVDrv.sys |
| SHA-256 | 87e8d39db624f37d3e77aedf487a2dfd197f71a4730ea74f4e7a4341deaec2ff |
| SHA-1 | 47d922b0fd5d704025d14ef98ded46e74830a423 |
| MD5 | 567c158ee0858f8e941d4ab7a6c18dbc |
| Size | 141,240 bytes |
| Architecture | AMD64 |
| PE timestamp | 0x639BE3C9 |
| Entry | 0x2A008 (RVA) |
| Sections | 7 (text, rdata, data, pdata, INIT, reloc, rsrc) |

## Imports [CONFIRMED]

ntoskrnl.exe imports directly relevant to process control:

| Import | Address |
|---|---|
| PsLookupProcessByProcessId | 0x3E038 |
| ZwOpenProcess | 0x3E0E8 |
| ZwTerminateProcess | 0x3E108 |
| ObOpenObjectByPointer | 0x3E110 |
| ZwClose | 0x3E0C0 |

Additional imports include ZwQuerySystemInformation,
ZwQueryInformationProcess, ZwSetInformationKey,
PsRemoveCreateThreadNotifyRoutine, Flt* callbacks, and
IoCreateFileSpecifyDeviceObjectHint.

## Device objects [CONFIRMED]

Wide strings in the binary:

```
\Device\DCRCVDRV_U
\DosDevices\DCRCVDRV_U
\BaseNamedObjects\__DCRCV_CHILD_PROCESS_MON_SHARE_EVENT_32__
\BaseNamedObjects\__DCRCV_CHILD_PROCESS_MON_SHARE_EVENT_64__
\Device\DCRCFS
\BaseNamedObjects\__DCRCV_U_WFP_FILTER_ADD_
\BaseNamedObjects\__DCRCV_U_FILE_DUPLICATE_MON_SHARE_EVENT__
\BaseNamedObjects\__DCRCV_U_PROGRAM_BLOCK_MON_SHARE_EVENT__
```

User-mode path: \\.\DCRCVDRV_U. [CONFIRMED]

The driver also carries WFP callout strings (auth connect v4/v6,
sub-layer) and a child-process monitor event pair, indicating the
vendor's own process and network monitoring functionality. [INFERRED]

## Legitimate origin markers [CONFIRMED]

Embedded executable names in the binary are all components of the
vendor software, not an attacker list:

```
spoolsv.exe
svchost.exe
alg.exe
Capture.exe
mpsinfo.exe
allegro.exe
cdsMsgServer.exe
cdsNameServer.exe
```

No AV/EDR process names are embedded. The 145-name hit list published
in eSentire's report belongs to the Cruciferra loader configuration,
not to this driver. [CORROBORATED]

## IOCTL dispatch [CONFIRMED]

The device-control entry is at RVA 0x14964 and uses a sub/je compare
chain. Decoded cases:

| IOCTL | handler | notes |
|---|---|---|
| 0x2204FC | 0x149EB | input >= 8 bytes |
| 0x220530..0x220540 | 0x14A14..0x14AF6 | config / state |
| 0x2205C0 | 0x149C3 | KILL - input >= 4 bytes |

The kill case at 0x149C3:

```
cmp  [input_len], 4
jb   error
mov  rcx, [input]        ; PID
call sub_12280           ; process termination helper
```

[CONFIRMED]

## Termination helper 0x12280 [CONFIRMED as observed behavior,
UNRESOLVED for exact branch selection]

The helper performs the full open/terminate sequence via both
ZwOpenProcess (import 0x3E0E8) and PsLookupProcessByProcessId
(import 0x3E038), followed by ZwTerminateProcess. Which handle source
is used on a given path has not been fully traced; the observable
behavior is identical: a handle is obtained and the process is
terminated from kernel context.

Sending PID, obtaining a handle, and terminating is the documented
behavior. eSentire TRU described the same chain in the Cruciferra
report (sub_12280 referenced in their figure analysis).
[CORROBORATED]

## Access control [INFERRED]

Device creation uses standard IoCreateDevice without a secure-
creation variant in the import set; the device is reachable from a
non-elevated context when the driver is loaded. Exact DACL behavior
was not tested independently and is marked accordingly.

## External references

- eSentire TRU, "Malware-as-a-Service Cocktail: ErrTraffic and
  Cruciferra - Killing Your EDR Since 2025" (2026-08-19)
- LOLDrivers entry 89643454-e38b-41cb-853d-abf649a104a5 (2026-08-27)