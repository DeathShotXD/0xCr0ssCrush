# Lab manifests

Reproducible host setup for testing the harness. Use a disposable VM
or an authorized lab machine; never a production host.

## Primary test host (used for the recorded runs)

| Field | Value |
|---|---|
| OS | Windows 11 24H2 (build 26100) |
| HVCI / Memory integrity | disabled |
| VBS | disabled |
| Defender blocklist | default policy (absent both samples, 2026-09-08) |
| Network | isolated lab network, host-only |

## Driver registration manifest (reference)

Start and stop commands equivalent to what the harness performs via
the SCM API (for manual inspection):

```
sc.exe create dcrcvdrv type= kernel binPath= C:\path\DCRCVDrv.sys
sc.exe start dcrcvdrv
sc.exe stop dcrcvdrv
sc.exe delete dcrcvdrv
```

```
sc.exe create alinubx type= kernel binPath= C:\path\Alinubx.sys
sc.exe start alinubx
sc.exe stop alinubx
sc.exe delete alinubx
```

The harness uses randomised service names and removes only services it
created; the fixed names above are for manual triage only.

## Post-run verification

```
sc query type= driver
tasklist /fi "imagename eq notepad.exe"
```

## Notes

- Both samples are signed; loading is expected on stock Windows hosts
  without HVCI. Hosts with HVCI enabled must be tested separately and
  reported in the matrix before any compatibility claims are made.
- Snapshot the VM before each run; kernel-loading experiments can
  leave the system needing a reboot.