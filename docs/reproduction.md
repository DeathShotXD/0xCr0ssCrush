# Reproduction

Procedure to independently repeat the observations in this repository,
including the validation gate, the driver load, and the process-level
effect.

## Prerequisites

- Windows 10 x64 (19041+) or Windows 11 x64 on a disposable VM or lab
  machine. Review `lab/test-matrix/` for the observed-compatibility
  matrix and `lab/manifests/` for lab setup notes.
- Rust toolchain with the x86_64-pc-windows-gnu target (build only).
- The three files from `driver/` (DCRCVDrv.sys, Alinubx.sys) and a
  disposable target executable (e.g. notepad.exe).

## Build

```
cargo build --release --target x86_64-pc-windows-gnu
```

## Step 1 - verify the samples

```
sha256sum driver/DCRCVDrv.sys driver/Alinubx.sys
```

Compare with `metadata/drivers.json`. The binary performs the same
check at runtime before any driver is registered.

## Step 2 - dry run (no IOCTLs)

```
crosscrush.exe -d -n "notepad.exe"
```

Expected: driver selection and process resolution only. The report
shows which driver was selected (DCRCVDrv.sys first, Alinubx.sys on
fallback) and which target PIDs were resolved.

## Step 3 - single target observation

```
crosscrush.exe -n "notepad.exe" -k dcrc
```

Record the `submitted` event. Then confirm whether the target is still
running:

```
tasklist /fi "imagename eq notepad.exe"
```

The IOCTL being accepted and the process actually stopping are two
separate observations; record both.

## Step 4 - twin fallback

Rename or remove `driver/DCRCVDrv.sys` and repeat step 3. The harness
should report DCRCVDrv.sys refused and continue with Alinubx.sys.
Restore the file afterwards (the harness validates by filename against
the tracked sample set).

## Step 5 - cleanup verification

After each run, confirm no driver service remains:

```
sc query type= driver | findstr /i "dcrc alinubx dcrcvdrv"
```

The harness only removes services it created. Pre-existing
registrations are left untouched by design (see
docs/architecture.md, service ownership model).

## Lab hygiene

- Run only on systems you own or are authorized to test.
- Prefer a snapshot-revertable VM; kernel-loading experiments can
  leave the system in a state that requires a reboot.
- Keep the target list minimal during reproduction.

## Recording results

The lab matrix in `lab/test-matrix/` lists the Windows versions and
the observed outcome per phase. Fill in the version you tested and the
result class (Verified / Not tested / Blocked / Unknown).