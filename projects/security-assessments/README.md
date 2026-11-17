# Mobile Data Loss Prevention — Layered Control Model

## Objective
Document a layered mobile data-protection model covering device trust, operating-system / UEM controls, managed application controls and network/data channels.

## Control layers
| Layer | Example controls | Analyst validation |
|---|---|---|
| Hardware root of trust | Secure boot, trusted execution environment, hardware-backed keys | Confirm device integrity and key-protection capabilities |
| OS / UEM | Device encryption, compliance policy, remote selective wipe | Check policy assignment, compliance state and audit evidence |
| App / MAM | Managed app container, clipboard restrictions, screen-capture controls | Test allowed and blocked data flows with an approved test profile |
| Network / data channels | Per-app VPN, transport encryption, Wi-Fi and Bluetooth policy | Review traffic paths, policy logs and exceptions |

## Lab note
The portfolio describes screen-capture blocking checks using Android Test DPC in lab drills. The broader four-layer matrix is an architecture model; it should not be read as proof that every control was deployed in a production UEM environment.

## Review questions
- Which data classes are protected, and which apps are in scope?
- Can users move managed data into unmanaged apps, screenshots, clipboard or external storage?
- Are exceptions approved, time-bound and auditable?
- What evidence demonstrates enforcement and what events are available to the SOC?
