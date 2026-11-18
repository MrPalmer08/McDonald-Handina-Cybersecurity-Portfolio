# Technical Lab Case Studies

These case studies explain the security objective, lab method, observations, defensive value and limitations behind selected exercises. All work described here was performed in an isolated educational environment. No customer systems or production incidents are represented.

## 1. Active Directory lab: reconnaissance, enumeration and defensive visibility

### Objective
Build a small domain environment that could be used to understand how identity infrastructure is exposed to a network, what an unauthenticated or low-privilege observer can learn, and which Windows security events may be generated during reconnaissance.

### Environment
- VMware Workstation with an isolated `VMnet1` network.
- Windows Server 2022 domain controller: `LAB-DC01`, `192.168.49.10`.
- Active Directory domain: `letsdefend.local`.
- pfSense LAN/gateway/DNS: `192.168.49.2`.
- Kali test host: `192.168.49.130`.
- BadBlood-generated test users, groups, OUs and directory objects to make the domain more representative for security testing.

### Red-team perspective — what I did and why
I first confirmed basic reachability from Kali, then used Nmap service discovery to identify exposed domain services, including DNS, Kerberos, MSRPC, NetBIOS, LDAP and SMB. I used enum4linux to test what domain information could be obtained through unauthenticated/null-session enumeration.

The reason for this sequence was to move from basic network discovery to identity-service enumeration: an attacker needs to understand which services are reachable before deciding where to focus further testing. Directory metadata can reveal naming conventions, domain structure and potential attack paths even when no credentials are supplied.

### What I observed
- The domain controller responded to network discovery.
- Nmap identified services commonly associated with Windows domain infrastructure.
- enum4linux returned the Domain SID through a null session.
- Further enumeration attempts were restricted and returned `NT_STATUS_ACCESS_DENIED`.

The access-denied result matters: it is evidence of an enforced boundary, not a failed lab. It shows that some information was exposed while other queries were not permitted.

### Blue-team perspective — what should be monitored
- Unexpected SMB, LDAP, Kerberos and RPC access patterns from endpoints that do not normally administer or query directory services.
- Repeated connection attempts across multiple domain services from one source.
- Authentication failures and account lockout patterns around the same time window.
- Directory-service and Windows Security logs, correlated with firewall/network telemetry where available.

### What I learned
Reconnaissance is not automatically proof of compromise. A defender needs to distinguish authorised administration, vulnerability scanning and suspicious discovery by correlating source host, user context, timing and follow-on activity. A useful detection should identify abnormal behaviour without treating every LDAP or SMB connection as malicious.

### Limitations
This was an isolated training domain. The documented observations are the results recorded from this lab; this write-up does not claim a successful compromise or a production security assessment.

---

## 2. Windows Security telemetry and Splunk: investigating authentication activity

### Objective
Understand how Windows authentication events can be collected and searched, then practice turning a group of related events into an evidence-based triage decision.

### Environment and evidence
Splunk Enterprise was used with Windows Security event data from the domain controller. The separate indexed dataset contained **66,969 events**. The portfolio's guided alert scenario is a clearly labelled synthetic training example:
- 27 Event ID 4625 failed-logon records.
- One Event ID 4648 explicit-credential-use record.
- Source shown in the scenario: `192.168.49.130`.
- Target shown in the scenario: `LAB-DC01`.

The 66,969 indexed-event count and the 28-event synthetic scenario are different evidence sets; the scenario is not presented as a measured incident extracted from those 66,969 records.

### What I did and why
I used Splunk searches to filter Windows Security events by event code and group related activity by host, source address and account. The purpose was to reduce a large event collection into a timeline that an analyst can investigate.

Example correlation search (field and index names may need adjustment for a particular Splunk input):

```spl
index=windows sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4648)
| stats count min(_time) as first_seen max(_time) as last_seen values(EventCode) as event_ids values(TargetUserName) as accounts by Computer, IpAddress
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

### How I interpreted the events
- **4625** records a failed logon. I would inspect status/substatus, account, source, destination and timing to understand whether failures share a pattern.
- **4648** records an attempt to log on using explicit credentials. It does not prove that authentication succeeded or that an account was compromised.
- I would search for **4624** from the same source/account and review logon type and authentication package.
- I would correlate 4648 with process name and caller context, and review nearby privileged-logon, Kerberos and endpoint events before reaching a conclusion.

### Blue-team decision
The scenario is treated as suspicious authentication activity requiring validation; compromise is not established by the two event types alone. The appropriate analyst output is a documented investigation and, if corroborating evidence warrants it, an escalation to Tier 2.

A proposed containment step in this isolated lab is a narrowly scoped, logged pfSense rule for the specific source-to-target traffic. It should only be applied after validation and approval, with an owner, rollback time and post-change verification.

### What I learned
The important skill is not simply knowing event IDs. It is understanding what each event proves, what it does not prove, and what additional telemetry is needed before making a high-impact decision.

### Limitations
The on-page triage walkthrough is scripted and uses synthetic training records. It is not connected to a live Splunk instance, and the example SPL must be adapted to the actual data model.

---

## 3. Active Directory identity security: Kerberoasting and detection logic

### Objective
Explore how service-account ticket requests can be abused during an Active Directory attack path, and how defenders can hunt for suspicious Kerberos ticket activity without generating excessive false positives.

### Red-team perspective — the security concept
Kerberoasting targets service accounts associated with Service Principal Names (SPNs). A domain user can request a service ticket for an SPN; depending on the account and encryption configuration, material in the ticket can be taken offline for password-guessing attempts. The risk is greater when service accounts have weak, reused or overly privileged passwords.

In the lab work, I used Impacket's `GetUserSPNs.py` as part of the Active Directory attack exercises to examine this service-ticket attack path. The objective was to understand the identity exposure and why service-account hygiene matters.

### Blue-team perspective — the detection
The documented Splunk hunt uses Event ID 4769 and filters for RC4 ticket encryption type `0x17`, excluding machine accounts and the `krbtgt` service:

```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
| search Service_Name!="*$" Service_Name!="krbtgt"
| stats count by Account_Name, Service_Name, Client_Address
```

### Why this signal needs context
RC4 use can be a useful hunting lead, but it does **not** prove Kerberoasting. Legacy applications may legitimately use RC4. I would investigate:
- Whether the requested SPN and service account are expected.
- The requesting account and client address.
- Request volume and whether it deviates from the normal baseline.
- Whether the service account is privileged or has an unusually weak password policy.
- Recent SPN, service-account or encryption configuration changes.

### Tuning and response
For a verified legacy exception, use a narrow allowlist tied to the specific service account, SPN, expected source hosts and a named owner. Add an expiry/review date. Do not suppress all RC4 ticket events globally. Continue to investigate requests from unexpected hosts, unusual volumes, privileged accounts and newly registered SPNs.

### Related credential-access learning
The wider Active Directory exercises also included Impacket `secretsdump.py`. Credential-dumping activity should be treated as a high-risk action in an authorised lab only. On the defensive side, review process execution and endpoint telemetry, privileged access, directory replication rights and relevant Windows events. Event ID 4662 can contribute to DCSync/replication-rights monitoring, but must be correlated with the subject, object, source host and approved domain-controller or replication-service activity.

### What I learned
A useful detection is a hypothesis supported by multiple signals, not a single event ID or encryption value. Good tuning preserves visibility while accounting for legitimate legacy dependencies.

### Limitations
This is an educational lab and detection-engineering exercise. The query is a starting point; field names, index names and baselines depend on the deployed data source. The documented logic does not claim that every alert represents a successful credential compromise.

---

## 4. Android application security: MobSF static analysis

### Objective
Practice reviewing an Android application package for security-relevant configuration and permissions, then assess scanner findings instead of treating automated output as proof of exploitability.

### What I did and why
In a controlled Android emulator exercise, I prepared a test APK in the isolated Kali lab and reviewed it with MobSF. I examined the manifest, exported components and requested permissions. These areas matter because an application can expose components to other apps or request access to sensitive user data beyond what its function requires.

### Findings represented in the portfolio demonstration
- A possible StrandHogg 2.0 / task-hijacking concern associated with exported task/launcher behaviour.
- Sensitive permission flags including `READ_CONTACTS` and `ACCESS_COARSE_LOCATION`.

These are review leads, not confirmed exploits. A static scanner can identify risky patterns, but an analyst must validate the Android version, target SDK, manifest attributes, component export state and runtime behaviour.

### Blue-team / remediation perspective
- Apply least privilege: request only permissions required for the app's documented purpose.
- Review exported activities, services and receivers; explicitly protect components that should not be externally callable.
- Validate runtime permission prompts and how the app handles denied permissions.
- Confirm findings through manual review and controlled runtime testing where appropriate.
- Document the affected component, evidence, impact, confidence and recommended fix.

### What I learned
Static analysis is a starting point for investigation. A finding becomes actionable only after the analyst verifies the affected configuration and explains a realistic security impact.

### Limitations
The portfolio's MobSF panels are scripted demonstrations, not a live MobSF service. No raw APK or standalone MobSF report is published with this write-up. The visual risk score is illustrative and should not be interpreted as a universal severity rating.

---

## 5. Mobile data-loss prevention: validating layered controls

### Objective
Understand how enterprise mobile data protection depends on multiple control layers rather than one setting.

### What I explored
The lab notes include screen-capture restriction checks using Android Test DPC. The broader design review organises mobile DLP into four layers:

1. **Device trust:** secure boot, hardware-backed keys and device integrity.
2. **OS / UEM:** encryption, compliance policies and selective wipe.
3. **Application / MAM:** managed app containers, clipboard restrictions and screen-capture controls.
4. **Network and data channels:** per-app VPN, transport encryption and Wi-Fi/Bluetooth policy.

### How I would validate a control
For each control, define the protected data and test profile, perform an approved allowed/blocked data-flow check, collect policy or audit evidence, and record exceptions. A control is not considered effective merely because a policy is configured; its enforcement and logs need to be verified.

### What I learned
Mobile DLP is a layered risk-reduction strategy. The SOC needs enough audit evidence to distinguish a blocked policy violation from a legitimate exception or an enforcement failure.

### Limitations
The four-layer matrix is an architecture model. The lab notes document selected Android Test DPC screen-capture checks; they do not claim that every control was deployed in a production UEM environment.

---

## How to read these case studies
Each exercise separates observed lab results from detection hypotheses and recommended defensive actions. The goal is to show the reasoning process: scope the activity, collect evidence, validate assumptions, assess impact, document uncertainty and recommend a proportionate response.
