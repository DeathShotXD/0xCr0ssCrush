#!/usr/bin/env python3
"""Validate the machine-readable metadata against the documentation.

Checks:
  1. metadata/drivers.json and metadata/samples.json are valid JSON.
  2. Every SHA-256 in samples.json exists in drivers.json.
  3. The SHA-256 digests documented in docs/driver-provenance.md and
     docs/dcrcv-analysis.md / docs/alinubx-analysis.md match the
     registry.
  4. The driver files in driver/ match the registry digests.

Exit code 0 on success, 1 on any mismatch. Intended for local
reproduction and CI (see .github/workflows/ci.yml).
"""

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    sys.exit(1)


def main() -> None:
    drivers = json.loads((ROOT / "metadata" / "drivers.json").read_text())
    samples = json.loads((ROOT / "metadata" / "samples.json").read_text())

    reg = {}
    for d in drivers["drivers"]:
        reg[d["sha256"]] = d

    known = set(reg)
    for s in samples["samples"]:
        if s["sha256"] not in known:
            fail(f"sample {s['filename']} sha256 not in drivers.json")

    files = {}
    for p in (ROOT / "driver").glob("*.sys"):
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        files[p.name] = h
        if h not in known:
            fail(f"driver/{p.name} sha256 {h} not in drivers.json")
        reg[h]["_file_present"] = True

    doc = "\n".join(
        (ROOT / "docs" / n).read_text()
        for n in ("driver-provenance.md", "dcrcv-analysis.md", "alinubx-analysis.md")
    )
    partial = set()
    for sha in known:
        if sha[:16] in doc or sha in doc:
            partial.add(sha)
    if partial != known:
        missing = known - partial
        fail(f"documented sha256 prefixes missing: {sorted(missing)}")

    print("[OK] metadata registry, samples, driver files and docs agree")
    for sha in sorted(known):
        d = reg[sha]
        print(f"     {d['filename']:<16} {sha[:16]} {d['primitive']}")


if __name__ == "__main__":
    main()