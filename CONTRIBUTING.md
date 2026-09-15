# Contributing to 0xCr0ssCrush

Thanks for your interest in contributing to 0xCr0ssCrush.

This project is a Windows BYOVD research repository focused on documented driver abuse, kernel primitives, metadata, and defensive detection. Contributions should be rigorous, evidence-based, and safe.

## Scope and expectations

We welcome improvements in the following areas:

- Documentation clarifications and corrections
- Research notes, writeup updates, and evidence summaries
- Driver metadata validation and provenance updates
- Detection logic, Sigma/YARA/telemetry guidance
- Build and reproduction workflow improvements
- Bug fixes in the Rust harness or validation scripts

We do not accept speculative or unsupported claims. Any new analysis should be clearly labeled as one of:

- Confirmed
- Corroborated
- Inferred
- Unresolved

## Safety and responsible use

This repository contains security research material and references to potentially dangerous Windows drivers. Contributions must follow safe handling practices.

- Do not use lab or reproduction steps against production, internet-facing, or third-party systems.
- Keep all testing inside isolated, controlled lab environments.
- Do not publish private artifacts, customer data, or host identifiers.
- Avoid introducing tooling that bypasses protections or makes exploitation easier for untrusted actors.
- If a PR changes operational guidance, explain the threat model and the required lab controls.

## Repository layout

Key areas include:

- `src/` — Rust harness and validation logic
- `docs/` — research, reproduction, and analysis documentation
- `analysis/` — driver-specific evidence and reverse-engineering notes
- `metadata/` — machine-readable provenance and driver inventory
- `detection/` — Sigma/YARA/telemetry coverage
- `scripts/` — repository validation and automation

## Workflow

1. Fork the repository and create a branch for your change.
2. Keep the patch focused and easy to review.
3. Update documentation when behavior or assumptions change.
4. Validate the relevant build or script output before opening a PR.
5. Include a concise explanation of what changed and why it matters.

## Development setup

Build the project from the repository root:

```bash
cargo build --release --target x86_64-pc-windows-gnu
```

If you are working on validation or metadata changes:

```bash
python3 scripts/validate_metadata.py
```

If you add or update detection content, keep the rules consistent with the repository's documented threat model and evidence labeling.

## Pull request checklist

Before submitting a PR, confirm the following:

- The change is specific and scoped to the issue or improvement.
- Documentation is updated where behavior, provenance, or reproduction steps change.
- Evidence or validation is included when making new claims.
- Metadata remains consistent with any new or modified driver information.
- The patch avoids unsafe or irresponsible operational guidance.

## Reporting issues

Use the issue tracker to report:

- Documentation problems
- Incorrect provenance or metadata
- Broken reproduction steps
- Bugs in the Rust harness or scripts
- Requests for additional analysis or detection coverage

When filing a report, include a clear summary, reproduction steps, expected behavior, and actual behavior when relevant.

## Documentation standards

Please keep writeups consistent with the repository's style:

- Be precise.
- Distinguish confirmed from inferred claims.
- Cite the evidence source when practical.
- Avoid over-claiming compatibility or effectiveness.
- Prefer reproducible, lab-scoped language over broad generalizations.

## Questions

If you are unsure whether a change is appropriate, open a discussion or issue before writing a large patch. It is better to align early than to revise a PR after significant work.

Thank you for helping keep this research repository accurate, defensible, and useful.
