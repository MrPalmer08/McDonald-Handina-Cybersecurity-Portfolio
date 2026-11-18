# SOC Alert Triage & Tier 2 Handoff

## Scenario
Synthetic training scenario `SOC-TRAIN-0042`: 27 Event ID 4625 failed-logon records. The displayed source (`192.168.49.130`) and target (`LAB-DC01`) are scenario metadata, not independently verified raw-event fields. This is not a live incident and does not establish a successful logon or compromise.

## Correlation query
```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4625
| stats count min(_time) as first_seen max(_time) as last_seen values(TargetUserName) as accounts by Computer, IpAddress
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

## Validation checklist
- Confirm the raw event details, source address, destination host, target account, timestamp and 4625 status/substatus.
- Search for Event ID 4624 from the same source/account and review logon type and authentication package.
- Correlate nearby 4672, Kerberos activity, directory-service events and endpoint telemetry.
- Record benign explanations, confidence and what evidence is still missing.
- Do not infer a source process or successful authentication from Event ID 4625 alone.

## Tier 2 handoff
**Affected host:** LAB-DC01 (`192.168.49.10`) — scenario label  
**Source:** `192.168.49.130` — scenario metadata  
**Initial assessment:** Suspicious authentication pattern; compromise not established.

Recommended handoff: preserve the event window and SPL; validate any related 4624 events; review account, logon type and endpoint context; and, only if malicious activity is corroborated and approved, consider a temporary logged pfSense rule scoped to the specific source-to-host traffic. Record the rule owner, rule ID, scope and rollback time, then verify firewall logs and business impact.

## Evidence limitations
The portfolio walkthrough is scripted. It does not connect to a live Splunk instance, and the 27 records are synthetic training data rather than a measured incident extracted from the separate 66,969-event collection.
