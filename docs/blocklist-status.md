# Blocklist status

Blocklist membership is timestamped and snapshot-specific. Microsoft's
vulnerable-driver blocklist is updated over time and is not guaranteed
to contain every vulnerable driver; absence from a snapshot means only
that the sample was not present in that snapshot.

## Snapshot

| Field | Value |
|---|---|
| Source | aka.ms/VulnerableDriverBlockList |
| Artifact | DriverPolicy_Enforced.xml |
| Policy version | 10.0.29545.0 |
| Snapshot date checked | 2026-09-08 |
| Verification method | SHA-256 membership search in the enforced policy XML |

## Results

| Sample | SHA-256 | Result |
|---|---|---|
| DCRCVDrv.sys | 87e8d39d... | Absent from snapshot 2026-09-08 |
| Alinubx.sys | 611b3ba6... | Absent from snapshot 2026-09-08 |

## Method

Both digest strings were searched in the full enforced policy XML
extracted from the snapshot artifact. A positive match would mean the
sample is covered by the enforced blocklist on systems receiving that
policy update. Both searches returned no match.

## Interpretation

Absence from the blocklist is not a statement about safety, and
presence on LOLDrivers does not imply blocklist coverage. These two
samples were cataloged on LOLDrivers on 2026-08-27; blocklist authors
publish their own timelines. Re-running the membership check against a
newer snapshot is part of the reproduction procedure
(docs/reproduction.md).