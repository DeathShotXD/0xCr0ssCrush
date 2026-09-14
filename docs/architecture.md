# Architecture

0xCr0ssCrush is a research harness. It drives two signed Windows kernel
drivers through their user-mode device interfaces, validates every
sample against published metadata before use, and reports every
observation in a stable, documented format. This document describes the
components, the load flow, the twin-fallback design, and the output
contract.

## Components

| Source | Responsibility |
|---|---|
| `src/main.rs` | CLI, orchestration, attempt ordering, scan loop |
| `src/drv.rs` | per-driver contract (device, IOCTL, input layout), device handle |
| `src/loader.rs` | SCM lifecycle with service ownership tracking |
| `src/validation.rs` | SHA-256 sample validation against published metadata |
| `src/reporting.rs` | normalized research output (console + JSON) |
| `src/targets.rs` | process resolution against the target list |
| `src/config.rs` | target list loading (CLI, config file, defaults) |
| `src/obf.rs` | runtime decryption of the bundled target list |

The `metadata/` directory holds the machine-readable driver and sample
registry. `scripts/validate_metadata.py` cross-checks the README, the
writeup, and the metadata registry against each other.

## Driver load flow

Two phases happen before any process interaction:

1. Sample validation.
   `validation::validate_driver` computes the SHA-256 of the driver file
   named on the command line and compares it with the digest published
   in `metadata/drivers.json`. A mismatch aborts the run. Every claim in
   this repository is hash-specific; loading a file that is not a known
   sample is treated as an error.

2. Device reachability probe.
   `drv::CrossDev::open` attempts to open the device path. A driver
   already present on the system is used as-is (a prior install may
   have left it loaded). If the device is not reachable, the harness
   registers the service through the SCM, starts it, and re-opens the
   device.

## Service ownership model

The loader distinguishes between services this process created and
services that already existed:

| Situation | Behavior |
|---|---|
| service already exists | opened and started, `created_by_us = false`; never deleted on exit |
| service does not exist | registered by the harness, `created_by_us = true`; stopped and marked for deletion on exit |

This prevents a run from silently deleting a service it does not own.
Uniquely derived service names (runtime state based) avoid collisions
with stale registrations while keeping the identifier deterministic
enough to reproduce in a lab.

## Twin fallback

Both drivers are carried by the tool because operators of the
Cruciferra loader carried both. The attempt order is:

```
DCRCVDrv.sys  -> device probe -> validate -> register -> open
   (refused at any step)
Alinubx.sys   -> device probe -> validate -> register -> open
```

`--kind` selects which driver is attempted first. `--no-fallback`
limits the run to a single driver. Once a driver is active, the harness
stays on it for the whole pass; a new process start will re-run the
fallback sequence.

## IOCTL submit semantics

A successful `DeviceIoControl` call means the IOCTL was accepted by the
driver, not that the kernel terminated the target. The writeup and this
document distinguish three stages:

1. IOCTL submitted - the call returned success.
2. Driver accepted the request - the driver's own status code, when the
   interface exposes one.
3. Operation result - whether the target process actually stopped,
   observable by re-resolving the process after the call.

The harness reports stage 1 explicitly. Stage 3 verification is
described in `docs/reproduction.md` as part of the lab methodology; it
is not folded into the IOCTL return value.

## Output contract

`--json` emits one JSON object per line. Human output uses the same
events with plain text formatting.

### driver

```json
{"event":"driver","driver":"DCRCVDrv.sys","device":"\\\\.\\DCRCVDRV_U","ioctl":"0x2205C0","sha256":"87e8d39db624..."}
```

### resolved

```json
{"event":"resolved","pid":1234,"message":"MsMpEng.exe -> pid 1234"}
```

### submitted

```json
{"event":"submitted","pid":1234,"message":"ioctl submitted"}
```

### kill (failure path only)

```json
{"event":"kill","pid":1234,"message":"error open device \\\\.\\DCRCVDRV_U ..."}
```

### summary

```json
{"event":"summary","submitted":4,"resolved":4}
```

Exit codes: 0 = at least one IOCTL submitted, 2 = no targets resolved,
3 = driver validation or load failure. `--dry-run` performs resolution
and driver selection only and submits nothing.

## Timing parameters

`--delay <ms>` sleeps before any driver interaction.
`--jitter <ms>` adds an offset derived from the system tick counter to
the scan interval in `--repeat` mode. This is a deterministic timing
variation used to make repeated scans less uniform; it is not
cryptographic randomness and is documented as such.