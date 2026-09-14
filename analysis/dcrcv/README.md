# Analysis artifacts

Supporting material referenced from the writeup: annotated disassembly
excerpts, string tables, and the import captures used to reach the
conclusions in `docs/dcrcv-analysis.md`.

## Files

- `dcrcv-imports.txt` - import table capture (ntoskrnl.exe) for the
  DCRCVDrv.sys sample 87e8d39d...
- `dcrcv-dispatch.txt` - annotated IOCTL dispatch excerpt at RVA
  0x14964
- `dcrcv-strings.txt` - selected wide strings (device names, event
  objects, legitimate-component names)
- `dcrcv-kill-helper.txt` - annotated termination helper at RVA
  0x12280

All offsets are RVAs into the exact sample listed in
`docs/driver-provenance.md`. Regenerate with any PE disassembler;
the excerpts are included for reproducibility of the analysis path,
not as a substitute for the sample.