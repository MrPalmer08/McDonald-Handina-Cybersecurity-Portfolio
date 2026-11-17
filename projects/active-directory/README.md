# Active Directory Identity Monitoring & Kerberoasting Detection

## Lab context
The portfolio documents an isolated Windows Server / Active Directory environment, with a `letsdefend.local` lab domain and BadBlood-generated test objects. The architecture view shows a Windows Server 2022 domain controller (`LAB-DC01`, `192.168.49.10`), pfSense as the network boundary and a controlled Kali test host (`192.168.49.130`).

## Kerberoasting detection query
```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
| search Service_Name!="*$" Service_Name!="krbtgt"
| stats count by Account_Name, Service_Name, Client_Address
```

[Open the Kerberoasting detection SPL](kerberoasting-rc4-detection.spl).

Event ID 4769 with RC4 encryption type `0x17` can be a useful hunting signal, but RC4 use alone does not prove Kerberoasting. Interpret it with service-account ownership, SPN, source host, request volume, encryption baseline and change history.

## False-positive tuning
For approved legacy service accounts that still require RC4:
- Maintain a narrow allowlist keyed to the specific account and SPN, with expected source hosts and a documented business owner.
- Apply an expiry or scheduled review date; do not broadly suppress all `0x17` events.
- Continue alerting on unexpected source hosts, unusual request volume, privileged accounts, new SPNs or deviations from the approved baseline.
- Reassess the exception when the service is upgraded and stronger encryption can be enabled.

## DCSync monitoring
Event ID 4662 can contribute to replication-rights monitoring. Correlate the subject identity, object access, source host and whether the source is an approved domain controller or authorized replication service. An event should be investigated in context rather than treated as proof by itself.

## Scope and limitations
This is educational lab documentation. The portfolio's sample output is illustrative/synthetic and does not represent a production domain or live incident.
