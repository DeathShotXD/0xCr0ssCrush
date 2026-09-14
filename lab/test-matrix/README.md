# Lab test matrix

Observed-compatibility matrix for the two drivers. Fill in results as
you test. The honest states are: Verified, Not tested, Blocked,
Unknown.

## DCRCVDrv.sys (87e8d39d...)

| Windows version | Driver load | Device availability | IOCTL behavior | Code integrity | HVCI | Blocklist | Observed result |
|---|---|---|---|---|---|---|---|
| Windows 11 24H2 (26100) | Verified | Verified | Verified | host-dependent | host-dependent | absent (2026-09-08) | Verified |
| Windows 11 23H2 (22631) | Not tested | Not tested | Not tested | - | - | - | Not tested |
| Windows 11 22H2 (22621) | Not tested | Not tested | Not tested | - | - | - | Not tested |
| Windows 10 22H2 (19045) | Not tested | Not tested | Not tested | - | - | - | Not tested |
| Windows Server 2022 | Not tested | Not tested | Not tested | - | - | - | Not tested |

## Alinubx.sys (611b3ba6...)

| Windows version | Driver load | Device availability | IOCTL behavior | Code integrity | HVCI | Blocklist | Observed result |
|---|---|---|---|---|---|---|---|
| Windows 11 24H2 (26100) | Verified | Verified | Verified | host-dependent | host-dependent | absent (2026-09-08) | Verified |
| Windows 11 23H2 (22631) | Not tested | Not tested | Not tested | - | - | - | Not tested |
| Windows 11 22H2 (22621) | Not tested | Not tested | Not tested | - | - | - | Not tested |
| Windows 10 22H2 (19045) | Not tested | Not tested | Not tested | - | - | - | Not tested |
| Windows Server 2022 | Not tested | Not tested | Not tested | - | - | - | Not tested |

## Definitions

- Driver load - the kernel accepted the signed image.
- Device availability - \\.\DCRCVDRV_U (or \\.\Alinubx) opened.
- IOCTL behavior - the termination IOCTL was accepted.
- Code integrity - whether the host runs enforced code integrity /
  HVCI (both were disabled on the primary test host).
- Blocklist - presence in the Microsoft vulnerable-driver blocklist
  snapshot (see docs/blocklist-status.md).