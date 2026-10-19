# Home Enterprise SOC & Active Directory Security Lab

Overview
This project documents a segmented home SOC lab used to practise detection engineering, AD monitoring, and incident triage. The lab was built on VMware Workstation with a pfSense firewall to isolate an Active Directory domain (letsdefend.local).

Architecture (high level)
- Network: pfSense firewall with internal segmented subnet for AD domain and separate attacker/researcher network
- Domain: Windows Server (Domain Controller), 1–2 member servers, and simulated workstations
- SIEM/EDR: Splunk Enterprise (indexers + search head in small lab), Sysmon on endpoints, Wazuh/EQL optional
- Attacker: Kali Linux for reconnaissance and attack simulations (Nmap, Impacket tools)

Key goals
- Generate realistic AD authentication and directory telemetry at scale
- Validate Splunk detections and tune alerts for noise and false positives
- Practice forensic log analysis and MITRE ATT&CK mapping

Quick start (lab notes)
1. Build VMware VMs: Windows Server (DC), Windows clients, Kali Linux. Snapshots recommended.
2. Install and configure pfSense with two internal networks: lab (AD) and attacker/researcher. Block outbound Internet from the lab unless required.
3. Deploy Windows Server and promote to Domain Controller (letsdefend.local). Configure AD with OUs and sample Group Policy objects.
4. Use BadBlood or a safe user-generation script to create large numbers of users/groups for telemetry (run in isolated lab only).
5. Install Sysmon on endpoints and configure to log process creation, network connections, and authentication events.
6. Install Splunk Enterprise, forward logs from endpoints and DC, and create indexes for Sysmon and Windows Security logs.

Sample Splunk queries (examples)
- NetExec / Enumeration (failed network logons)
index=security sourcetype=WinEventLog:Security EventCode=4625 LogonType=3 | stats count by src_ip, Account_Name | where count > 50

- Kerberoasting attempt (T1558.003 / T1003.006)
index=security EventCode=4769 "EncryptionType=0x17" OR "RC4" | stats count by Account_Name, Service_Name

Safety and ethics
- Run all offensive/recon tools in isolated lab environments only. Never run AD population scripts or Impacket tools against production systems.

Files in this folder
- detection examples (projects/splunk-detections)
- AD automation scripts (projects/ad-scripts)
