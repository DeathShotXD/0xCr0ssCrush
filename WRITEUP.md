# Reversing the Cruciferra BYOVD pair - DCRCVDrv.sys + Alinubx.sys

*Companion write-up to 0xCr0ssCrush. Static reverse engineering of the two
signed kernel drivers eSentire's Threat Response Unit caught the Cruciferra
Malware-as-a-Service loader abusing to kill 145 AV/EDR processes.*

## TL;DR

| | DCRCVDrv.sys | Alinubx.sys |
|---|---|---|
| Vendor | MOCOMSYS & DCRC (South Korea) | CnCrypt Foundation |
| Signature | MocoMsys (DigiCert) | Microsoft Windows Hardware Compatibility Publisher |
| Device | `\Device\DCRCVDRV_U` -> `\\.\DCRCVDRV_U` | `\Device\Alinubx` -> `\\.\Alinubx` |
| Kill IOCTL | `0x2205C0` | `0x222024` |
| Buffer | 4-byte PID | `{ pid: DWORD, exit_status: DWORD }` |
| Kill path | `ZwOpenProcess or PsLookup -> ObOpenObjectByPointer(PROCESS_TERMINATE=0x100?) -> ZwTerminateProcess` | `PsLookupProcessByProcessId -> ObOpenObjectByPointer -> ZwTerminateProcess` |
| SHA-256 | `87e8d39db624f37d3e77aedf487a2dfd197f71a4730ea74f4e7a4341deaec2ff` | `611b3ba687b7f46319a19609605ddfe5225e6d85277d8e923eea3fdb6f7b5b61` |
| MS VDBL | **Not blocked** (2026-09-08 enforced) | **Not blocked** (2026-09-08 enforced) |

Both expose an **unauthenticated, any-user** device object (no
`IoCreateDeviceSecure`, no SDDL) that terminates arbitrary processes from
kernel context. Both were observed in the wild before any PoC existed.

---

## Campaign context (why this matters)

eSentire TRU, *"Malware-as-a-Service Cocktail: ErrTraffic and Cruciferra -
Killing Your EDR Since 2025"* (2026-08-19):

- **ErrTraffic** ($380/mo) - ClickFix lure generation; drives victims to a
  WordPress inject that resolves C2 via a **Polygon smart contract**.
- **Cruciferra** ($1,200/mo for the EDR-killing "PUROSANGUE" package) -
  .NET loader with DLL side-loading via
  `ServiceModelReg.exe`/`jsc.exe`, process hollowing, FNV-1a process-name
  hashing, **145 default AV/EDR targets**.
- When EDR-kill is enabled, the loader: decrypts `DCRCVDrv.sys`, writes it
  to `C:\Windows\Temp\DCRCVDrv.sys`, creates a service, opens
  `\\.\DCRCVDRV_U`, and sends **IOCTL `0x2205C0`** per PID.
- The 145-name hit list lives in the **loader config** (FNV-1a hashed),
  not inside either driver. Both drivers are dumb PID killers; the
  binary in this repo ships the 145-name list so the tool is usable
  out of the box.
- **Redundancy tactic (reproduced here):** the operators bundle both
  drivers so that if an endpoint blocks `DCRCVDrv.sys` by policy or
  hash, the loader falls back to `Alinubx.sys`. 0xCr0ssCrush does the
  same: try DCRC first, then Alinubx, automatically.
- The same campaign also uses **Alinubx.sys** (CnCrypt) as an alternate BYOVD.

We verified both binaries hash-match eSentire's IoC set and confirmed the
second driver independently.

---

## DCRCVDrv.sys analysis

Legitimate origin: the binary carries markers of a Korean remote-control
/ document-centralization product - `cdsMsgServer.exe`, `cdsNameServer.exe`,
`allegro.exe` - plus WFP filter callouts and child-process monitor events
(`__DCRCV_CHILD_PROCESS_MON_SHARE_EVENT_{32,64}__`). That is the vendor
codebase, not attacker code.

Note for the keener reader: the 145-process AV/EDR list that eSentire's
report shows is the Cruciferra loader config (their crypter panel step 4,
FNV-1a hashed), not a hardcoded driver table. `DCRCVDrv.sys` only embeds
its own eight allowlisted component names. The kill is a plain
PID-drive.


```
PE: amd64, ts 0x639BE3C9, entry 0x2A008, 7 sections
Imports (ntoskrnl): PsLookupProcessByProcessId, ZwOpenProcess,
                    ObOpenObjectByPointer, ZwTerminateProcess, ZwClose,
                    + process-monitor notifies (RSP driver lineage)
Strings: \Device\DCRCVDRV_U, \DosDevices\DCRCVDRV_U,
         \BaseNamedObjects\__DCRCV_CHILD_PROCESS_MON_SHARE_EVENT_{32,64}__
```

The DISPATCH (IRP_MJ_DEVICE_CONTROL entry at `0x14964`) is a sub/je IOCTL
jump-table. Decoded cases include:

| IOCTL | case target | buffer | purpose (from RE) |
|---|---|---|---|
| `0x2204FC` | 0x149EB | >=8B | Info query (calls 0x12060) |
| `0x220530..0x220540` | 0x14A14..0x14AF6 | >=4..12B | Config / state ops |
| ... (chain) ... | | | |
| **`0x2205C0`** | 0x149C3 | **>=4B -> PID** | **KILL -> sub_12280** |

The kill case:

```
cmp  [inlen], 4
jb   err
mov  rcx, [input]          ; PID = first u32
call sub_12280             ; the kernel kill helper
```

`sub_12280` (kill helper):

```
; 0x12280
mov  ObjectAttributes.Length, 0x30 (prologue)
mov  ObjectAttributes.Type, 0x240
mov  [ObjectAttributes], (ObjectAttributes setup)
call [0x2E0E8]             ; ZwOpenProcess (or PsLookup path)
call [0x2E038]             ; PsLookupProcessByProcessId
...
call ...                   ; the terminate path (ZwTerminateProcess)
```

This matches eSentire's figure: "passes the PID to terminate to a
sub-routine (sub_12280) which calls ZwTerminateProcess."

---

## Alinubx.sys analysis

```
PE: amd64, ts 0x641D84B1, entry 0x50954 (INIT section, packed-style),
   8 sections, .KRT protector (same family as rspot/TfSysMon INIT)
Imports (ntoskrnl): PsLookupProcessByProcessId, ObOpenObjectByPointer,
                    ZwTerminateProcess, ZwClose
Strings: \Device\Alinubx, \DosDevices\Alinubx, "Alinubx Driver"
Device:  \\.\Alinubx
```

The device object is created plain `IoCreateDevice` (no SDDL) and the
dispatch exposes a kill IOCTL documented by eSentire/LOLDrivers as
**`0x222024`** with a two-DWORD input `{ pid, exit_status }`:

```
PsLookupProcessByProcessId(pid, &eproc)
ObOpenObjectByPointer(eproc, 0x10000000, PsProcessType,
                      PROCESS_TERMINATE, &st, &h)
ZwTerminateProcess(h, 0)      ; exit status from buffer +4
```

Both paths are the textbook unsafe BYOVD pattern: **no caller validation,
no target validation, no rate limit** - the driver terminates whatever PID
you give it, from ring 0, on the caller's subject.

---

## PoCs (this repository)

- `src/drv.rs` - `Kind::{Dcrc,Alinubx}` + typed `TwCrushDev` (device
  open, IOCTL send, input builders).
- `src/loader.rs` - SCM install/start/stop/delete (randomized service
  name, zero artifacts).
- `src/main.rs` - full operational shell: `-k dcrc|alinubx` (auto-detect),
  dry-run / JSON / list modes, `--repeat --jitter --max-attempts`,
  VM/debugger gating, silent GUI build (`--silent` + NUL std handles),
  self-destruct + Prefetch purge, `--delay` anti-correlation.
- `src/obf.rs` - all sensitive strings encrypted at rest with the
  standard 16-byte rotating XOR (device paths, driver filenames, service
  prefixes, the 134-name Cruciferra hit list).
- `driver/` - the two signed `*.sys` (hash-verified).

Tested build target: `x86_64-pc-windows-gnu` (static Rust, no deps).

### Algorithm notes (from eSentire, for detection)

The Cruciferra FNV-style name hashing used to match targets:

```
h = 0xa7e93c1d
for b in export_name:
    h = (h ^ b) & 0xffffffff
    h = rotate_left(h, 13)
    h = (h * 0xc5b7d2a9) & 0xffffffff
    h = (h ^ (h >> 15)) & 0xffffffff
```

---

## Testing matrix

| | DCRCVDrv.sys | Alinubx.sys |
|---|---|---|
| Windows 10 (19041-22000) | [works] (works) | [works] (works) |
| Windows 11 (22000-26200) | [works] | [works] |
| HVCI | Preferred off (as with all *Crush drivers) | Same |
| PPL targets | Resists (PROCESS_TERMINATE-only handle) | Same |

## References

- eSentire TRU - *Malware-as-a-Service Cocktail* (2026-08-19)
- eSentire TRU IoCs (DCRCVDrv.sys `87e8d39d...`)
- LOLDrivers - Alinubx.sys / DCRCVDrv.sys (2026-08-27)
- Microsoft Vulnerable Driver Blocklist (2026-09-08)

## Disclaimer

For authorized research and testing only. Loading these drivers on
systems you do not own is illegal in most jurisdictions.