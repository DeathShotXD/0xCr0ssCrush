# IOCTL reference

Correlation matrix for the two drivers examined in this repository.

| Property | DCRCVDrv.sys | Alinubx.sys |
|---|---|---|
| Vendor / origin | MOCOMSYS / DCRC | CnCrypt |
| Device | `\\.\DCRCVDRV_U` | `\\.\Alinubx` |
| IOCTL | `0x2205C0` | `0x222024` |
| Input | PID (DWORD) | PID + status (2 x DWORD) |
| Primitive family | PROCESS_CONTROL | PROCESS_CONTROL |
| Primitive | PROCESS_TERMINATION | PROCESS_TERMINATION |
| Validation | this analysis + external reporting | this analysis + external reporting |
| Campaign context | Cruciferra loader (eSentire TRU) | Cruciferra-associated reporting |
| SHA-256 | 87e8d39d... | 611b3ba6... |

The DCRCVDrv.sys device, IOCTL, and termination chain were
independently described in eSentire TRU's Cruciferra report; this
table reproduces and correlates that chain against the second driver
in the same toolkit.

## Full DCRCVDrv.sys IOCTL surface (observed in disassembly)

| IOCTL | handler RVA | min input | notes |
|---|---|---|---|
| 0x2204FC | 0x149EB | 8 | state query |
| 0x220530 | 0x14A14 | 4..12 | config |
| 0x220534 | 0x14A5C | 4..12 | config |
| 0x220538 | 0x14A9F | 4..12 | config |
| 0x22053C | 0x14AD9 | 4..12 | config |
| 0x220540 | 0x14AF6 | 4..12 | config |
| 0x2205C0 | 0x149C3 | 4 | process termination |
| 0x220600 | 0x14B41 | - | additional surface |
| 0x22061C | 0x14DA6 | - | additional surface |

The sub/je chain structure is typical of switch-generated dispatch
code. Addresses are RVAs in the analyzed sample only.

## Full Alinubx.sys IOCTL surface (documented externally)

| IOCTL | notes |
|---|---|
| 0x222024 | process termination (PID + status) |

Additional Alinubx IOCTLs were not part of this analysis; the
interface is partially documented in eSentire/LOLDrivers reporting
and the driver carries additional WFP-like callout strings
suggesting a wider interface surface. [UNRESOLVED]