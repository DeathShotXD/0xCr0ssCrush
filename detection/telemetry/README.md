# Telemetry

Event-level guidance for correlating this behavior in a SOC stack.

## Sysmon events of interest

| EventID | Type | Why |
|---|---|---|
| 6 | Driver loaded | hash match on both samples; baseline coverage provided by detection/sigma |
| 1 | Process creation | loader executable writing a driver file to %TEMP% before registering a service |
| 1 | Process creation | `sc.exe create ... type= kernel` with the two driver filenames |
| 5 | Process terminated | bursts of terminations across distinct PIDs, including security agent processes |
| 11 | File created | DCRCVDrv.sys / Alinubx.sys appearing outside the vendor install directory |

## Correlation pattern

1. File creation of either driver filename (EventID 11, path outside
   `C:\Windows\System32\drivers` or the vendor product directory).
2. Within seconds: service registration (EventID 1, sc.exe) then
   driver load (EventID 6, matching hash).
3. Followed by device access to `\\.\DCRCVDRV_U` or `\\.\Alinubx`
   from a process that is not part of the vendor software.
4. Security agent processes exiting with abnormal termination within
   the same window.

All four steps inside 5-30 seconds is the strongest signal. Steps 1-3
alone can match legitimate vendor updates - correlate step 4 before
escalating.

## EDR notes

- The IOCTLs 0x2205C0 / 0x222024 are not typically documented by
  vendor telemetry; hooking DeviceIoControl argument capture is the
  reliable way to observe them.
- Alternatively, process-creation telemetry on the target list from
  the loader (the 145-name list published by eSentire) plus rapid
  exit correlation produces equivalent detection.
- Both drivers keep no persistent services when loaded by the harness
  (cleanup removes only self-created registrations), so detection
  should not rely on residual service enumeration.