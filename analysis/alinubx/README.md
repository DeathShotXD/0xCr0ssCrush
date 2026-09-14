# Analysis artifacts

Supporting material for the Alinubx.sys analysis
(`docs/alinubx-analysis.md`).

## Files

- `alinubx-imports.txt` - import table capture (ntoskrnl.exe) for the
  Alinubx.sys sample 611b3ba6...
- `alinubx-strings.txt` - selected wide strings (device names, ALE
  callout markers)

All offsets are RVAs into the exact sample listed in
`docs/driver-provenance.md`. The IOCTL dispatch for this driver was
partially documented externally (eSentire/LOLDrivers); the wider
interface surface remains [UNRESOLVED] and is not asserted here.