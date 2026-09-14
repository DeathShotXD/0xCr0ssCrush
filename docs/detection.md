# Detection

Behavioral and signature material for defenders. Each driver is
considered across the phases an attacker-controlled loader passes
through: installation, service creation, image loading, device
access, and process targeting.

## Detection surface per driver

| Phase | DCRCVDrv.sys | Alinubx.sys |
|---|---|---|
| Driver installation | file drop (e.g. %TEMP%\DCRCVDrv.sys observed in Cruciferra reporting) | file drop |
| Service creation | kernel driver service, demand start | kernel driver service, demand start |
| Driver image loading | device load, image hash 87e8d39d... | device load, image hash 611b3ba6... |
| Device access | \\.\DCRCVDRV_U | \\.\Alinubx |
| Known IOCTL | 0x2205C0 | 0x222024 |
| Process targeting | rapid IOCTL burst across distinct PIDs | same |

## Sigma rules

`detection/sigma/`:

- driver_load_win_cruciferra_byovd.yml - service creation and driver
  image load by hash for both samples.

## YARA rules

`detection/yara/`:

- cruciferra_drivers.yar - hash-based rules (import table
  independent) plus PE metadata markers (company name, version) for
  both samples.

## Telemetry examples

`detection/telemetry/`:

- Sysmon event IDs useful for this pattern (6 driver load, 1 process
  creation of the loader, 5 service termination attempts).
- Additional EDR observations: non-interactive process issuing
  DeviceIoControl to the two device names, followed by abrupt
  termination of security agent processes.

## Caveats

- Both drivers are signed and load legitimately as part of their
  vendor software. Hash matching alone gives a high baseline signal;
  behavior correlation (device access from unexpected processes,
  kill patterns against security agents) narrows it down.
- The 145-name process list published in eSentire's report is a
  loader configuration, not a driver constant; create telemetry
  against target names plus rapid termination correlation rather than
  a single static list.
- Blocklist membership is snapshot-dependent
  (docs/blocklist-status.md); re-check on a schedule rather than
  assuming permanent coverage.