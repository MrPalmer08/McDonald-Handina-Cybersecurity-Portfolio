# SOC Alert Triage & Tier 2 Handoff

## Scenario
Synthetic training scenario `SOC-TRAIN-0042`: 27 Event ID 4625 failed-logon records and one Event ID 4648 explicit-credential-use record. The displayed source is `192.168.49.130`; target is `LAB-DC01`. This is not a live incident.

## Correlation query
```spl
index=windows sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4648)
| stats count min(_time) as first_seen max(_time) as last_seen values(EventCode) as event_ids values(TargetUserName) as accounts by Computer, IpAddress
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

## Validation checklist
- Confirm raw event details, source address, destination host, target account, timestamp and 4625 status/substatus.
- Search for Event ID 4624 from the same source/account and review logon type and authentication package.
- For 4648, review process name, caller context, logon type and approved administrative activity.
- Correlate 4672, Kerberos activity, directory-service events and endpoint telemetry.
- Record benign explanations, confidence and what evidence is still missing.

**Important:** Event ID 4648 alone does not prove compromise. A successful 4624 logon and corroborating activity must be checked before concluding that credentials were used successfully.

## Tier 2 handoff
**Affected host:** LAB-DC01 (`192.168.49.10`)  
**Source:** KALI-NODE (`192.168.49.130`, isolated lab source)  
**Initial assessment:** Suspicious authentication pattern; compromise not established.

Recommended handoff: preserve the event window and SPL; validate 4624 events; review account, logon type and process context; and, only if malicious activity is corroborated and approved, consider a temporary logged pfSense rule blocking the specific source-to-host traffic. Record the rule owner, rule ID, scope and rollback time, then verify firewall logs and business impact.
