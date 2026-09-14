# Threat model

Abuse of signed vulnerable kernel drivers via the Bring Your Own
Vulnerable Driver (BYOVD) technique. This model describes the threat
class the research harness exercises and the control stack defenders
have against it.

## Model

| Element | Value |
|---|---|
| Threat | Abuse of signed vulnerable kernel drivers |
| Initial capability | User or admin code execution |
| Security boundary | User mode to kernel mode |
| Primitive | Privileged process control |
| Impact | Security-control interference |
| Controls | HVCI, App Control, Vulnerable Driver Blocklist, ASR, EDR telemetry |

## Boundary crossing

The primitives exposed by both drivers let a user-mode process obtain
a kernel-mode handle on a target process and terminate it. The
security boundary between user mode and kernel mode is not enforced
by these interfaces because the drivers perform no caller validation
on the documented paths. The boundary that does apply is the ability
to load a signed kernel image in the first place.

## Relevant controls

- Hypervisor-Protected Code Integrity (HVCI): prevents execution of
  code the hypervisor has not authorized; restricts pool execution and
  driver image integrity at a level the blocklist cannot.
- App Control (WDAC): policy-driven image approval; a custom policy
  can deny driver images beyond the Microsoft defaults.
- Vulnerable Driver Blocklist: Microsoft-shipped block policy for
  known-vulnerable signed drivers. Snapshot-dependent coverage
  (see docs/blocklist-status.md).
- Attack Surface Reduction (ASR): can deny device-interface access
  patterns used by loaders.
- EDR telemetry: behavior correlation (driver load + device access +
  abrupt security-agent termination), see detection/.

## Why the twin matters for defenses

Both drivers can fill the same role, so blocking one file only moves
the attacker to the other. Blocklist and App Control policies should
cover both samples (metadata/drivers.json) and the failure mode used
by loaders (drop, attempt, fall back, repeat) should be covered by
behavioral detection rather than file matching alone.

## Assumptions

- Attacker already has code execution on the host (the loaders in the
  reference reporting arrive via clickfix/social engineering chains).
- The user-mode component does not require the target processes to be
  non-protected for the primitive to be useful; the report documents
  the process-protection (PPL) limit observed for these interfaces in
  the writeup limitations.