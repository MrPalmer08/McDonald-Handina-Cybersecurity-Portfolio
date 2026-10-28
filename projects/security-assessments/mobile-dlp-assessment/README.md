# Mobile Data Loss Prevention (DLP) Assessment

## Goal
Assess mobile application security and data loss prevention controls on Android devices using static analysis and mobile device management policies.

## Environment
- Seneca Polytechnic, CYT230 Mobile Application Security Assessment, Project 2
- Android emulator connected via ADB
- Test DPC provisioned as Device Owner
- MobSF (Mobile Security Framework)

## What I did
- Connected an Android emulator via ADB and installed Test DPC, provisioning it as Device Owner.
- Enabled and tested the "Disable screen capture" policy; verified that screenshot attempts were blocked.
- Conducted static security analysis on a sample Android APK using MobSF [TODO: confirm APK name or source].
- Evaluated a layered DLP model spanning hardware/TEE, OS/MDM, application/MAM, network, radio, and physical layers.
- Formulated six DLP policy recommendations informed by case studies on T-Mobile (2021), Pegasus, SHAREit, and Strava.

## What I found or learned
- Static analysis identified dangerous permissions (coarse location, contacts, accounts) and manifest issues (outdated Android versions supported, debugging enabled, backup allowed).
- Identified a StrandHogg 2.0 task-hijacking flag on the PostLogin activity.
- No hardcoded credentials, insecure API calls, risky cryptography, exported activities, or network config issues were flagged in the scan.
- Understood that a clean scan does not prove an app is secure.

## Screenshots
- ADB check: [TODO: add screenshot]
- Test DPC provisioning: [TODO: add screenshot]
- Screen-capture policy: [TODO: add screenshot]
- Blocked screenshot: [TODO: add screenshot]
- MobSF permissions: [TODO: add screenshot]
- MobSF manifest: [TODO: add screenshot]

## Skills
MDM policy enforcement, Android Device Owner provisioning, ADB, MobSF, OWASP Mobile Top 10 mapping, DLP policy design
