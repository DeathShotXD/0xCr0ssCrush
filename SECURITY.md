# Security

## Scope

This repository is a security research project. It demonstrates the
abuse of two signed Windows kernel drivers that have been observed in
threat-actor loaders. The intent is to study, document, and defend
against this class of behavior - not to facilitate it.

## Responsible use

- Only use the harness on systems you own or are explicitly
  authorized to test.
- Loading signed vulnerable drivers on systems you do not own is
  illegal in most jurisdictions, and is not supported by this
  project.
- The reproduction procedure (docs/reproduction.md) assumes a
  disposable lab environment.

## Reporting a vulnerability

Issues with the project itself (code defects, documentation errors)
can be opened on the issue tracker. Do not open issues asking for
assistance targeting third-party systems.

## Sample policy

The driver samples in `driver/` are cataloged vulnerable drivers
already tracked publicly by the LOLDrivers project and described by
eSentire TRU in their Cruciferra reporting (2026-08-19). Their
inclusion here is for hash-specific research; every sample is
validated against published digests before use, and the metadata
registry (metadata/drivers.json) records their provenance.

## Export and policy notes

Check local law before downloading or sharing this repository.
Security research tooling is regulated differently across
jurisdictions; the operator is responsible for compliance.