# Threat Hunt Azuki Import/Export
## Executive Summary
On 19 November 2025, an attacker gained unauthorized access to the environment via Remote Desktop Protocol (RDP) using compromised credentials. They staged malware, evaded defenses, harvested credentials, and laterally moved to a secondary system. Data was compressed and exfiltrated through Discord webhooks. The attacker also attempted anti‑forensics by clearing event logs and created a hidden administrator account for persistence.  
**Impact Level:** High  
**Status:** Contained

## Incident Details  
**Timeline**  
First Malicious Activity (UTC): 19 Nov 2025, 11:10 AM  
Last Observed Activity (UTC): 21 Nov 2025, 4:38 PM  
Total Duration: ~2.5 days  

## Attack Overview  
Initial Access Method: RDP from external IP
Compromised Account: kenji.sato
Affected System: Windows host staging malware in C:\ProgramData\WindowsCache
Attacker IP Address: 88.97.178.12

## Attack Chain (MITRE ATT&CK)
Initial Access (TA0001): RDP connection from 88.97.178.12 using compromised account kenji.sato.  
Execution (TA0002): Malicious PowerShell script wupdate.ps1 executed to automate attack chain.  
Persistence (TA0003): Scheduled task Windows Update Check created to run C:\ProgramData\WindowsCache\svchost.exe.  
Hidden admin account support added.  
Defense Evasion (TA0005): Malware staged in hidden directory C:\ProgramData\WindowsCache.  
Windows Defender exclusions added (3 file extensions, temp folder path).  
Download utility abuse via certutil.exe.  
Event logs cleared (Security log first).  
Discovery (TA0007): Network reconnaissance via arp -a.  
Credential Access (TA0006): Credential dumping tool mm.exe executed with sekurlsa::logonpasswords.  
Lateral Movement (TA0008): Credentials staged with cmdkey.exe.  
Remote access via mstsc.exe to secondary target 10.1.0.188.  
Collection (TA0009): Data compressed into archive export-data.zip.  
Command & Control (TA0011): Outbound connections from svchost.exe to C2 server 78.141.196.6 over port 443.  
Exfiltration (TA0010): Archive uploaded via Discord webhook.  
Impact (TA0040): Hidden administrator account support created for persistence.  

## Key Findings
**Primary IOCs**  
Malicious IPs: 88.97.178.12, 78.141.196.6, 10.1.0.188  
Malicious Files: mm.exe, svchost.exe, wupdate.ps1, export-data.zip  
Compromised Accounts: kenji.sato, support  
C2 Infrastructure: Discord webhook, IP 78.141.196.6:443  

## Recommendations
**Immediate Actions (Do Now):**  
Disable compromised accounts (kenji.sato, support).  
Block malicious IPs (88.97.178.12, 78.141.196.6).  
Remove staged malware and scheduled tasks from C:\ProgramData\WindowsCache.  

**Short-term (1–30 days):**  
Reset all affected credentials and enforce MFA.  
Review Defender exclusion policies and restore defaults.  
Monitor for outbound Discord webhook traffic.  
Long-term (Security Improvements)  
Harden RDP access (VPN, MFA, restricted IPs).  
Implement enhanced logging and alerting for event log clearing.  
Regularly audit for hidden accounts and scheduled tasks.  

## Appendix
A. Key Indicators of Compromise (IOCs)


B. MITRE ATT&CK Mapping 


C. Investigation Timeline
19 Nov 2025 11:10 — RDP login from 88.97.178.12 as kenji.sato.
19 Nov 2025 11:15 — wupdate.ps1 executed.
19 Nov 2025 11:20 — Malware staged in C:\ProgramData\WindowsCache.
19 Nov 2025 11:25 — Defender exclusions added.
19 Nov 2025 11:30 — certutil.exe abused for downloads.
19 Nov 2025 11:40 — mm.exe credential dumping with sekurlsa::logonpasswords.
19 Nov 2025 11:50 — Archive export-data.zip created.
19 Nov 2025 11:55 — Exfiltration via Discord webhook.
20 Nov 2025 — Scheduled task Windows Update Check created.
21 Nov 2025 — Lateral movement to 10.1.0.188 via cmdkey.exe + mstsc.exe.
21 Nov 2025 — Event logs cleared (Security first).
21 Nov 2025 — Hidden admin account support created.
D. Evidence — KQL Queries & Screenshots
Query 1 — Initial Access (RDP from 88.97.178.12, compromised account kenji.sato)
DeviceLogonEvents
| where LogonType == "RemoteInteractive" or ActionType in ("LogonSuccess","LogonFailed")
| where RemoteIP == "88.97.178.12"
| project Timestamp, DeviceName, AccountDomain, AccountName, RemoteIP, LogonType, ActionType
| order by Timestamp asc

Results: Shows successful RemoteInteractive logon from 88.97.178.12, account kenji.sato.
Screenshot:
—
Query 2 — Malicious Execution (PowerShell script wupdate.ps1)
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("wupdate.ps1", "-File", ".ps1")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc

Results: Identifies execution of wupdate.ps1 shortly after initial access.
Screenshot:
—
Query 3 — Persistence (Scheduled Task “Windows Update Check” → svchost.exe)
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc

Results: Shows scheduled task creation with name “Windows Update Check” and action path C:\ProgramData\WindowsCache\svchost.exe.
Screenshot: 
—
Query 4 — Defense Evasion (Hidden staging directory)
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where FolderPath has "C:\\ProgramData\\WindowsCache"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by Timestamp asc

Results: Shows creation and attribute changes for C:\ProgramData\WindowsCache.
Screenshot:
—
Query 5 — Defender Exclusions (3 extensions + temp path)
DeviceRegistryEvents
| where RegistryKey has @"Windows Defender\\Exclusions"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by Timestamp asc

Results: Lists added extension exclusions (count = 3) and path exclusion C:\Users\KENJI~1.SAT\AppData\Local\Temp.
Screenshot: 
—
Query 6 — Download Utility Abuse (certutil.exe)
DeviceRegistryEvents
| where RegistryKey has @"Microsoft\Windows Defender\Exclusions\Paths"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp asc

Results: Shows LOLBAS download via certutil.exe.
Screenshot: 
—
Query 7 — Discovery (arp -a)
DeviceProcessEvents
| where FileName in~ ("arp.exe","cmd.exe")
| where ProcessCommandLine has "arp -a"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc

Results: Captures execution of arp -a.
Screenshot: ☐ Attached

Query 8 — Credential Access (mm.exe + sekurlsa::logonpasswords)
DeviceProcessEvents
| where FileName =~ "mm.exe" or ProcessCommandLine has "mm.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc

Results: Shows renamed Mimikatz (mm.exe) running sekurlsa::logonpasswords.
Screenshot:---
Query 9 — Collection (export-data.zip)
DeviceFileEvents
| where FileName =~ "export-data.zip"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc

Results: Confirms creation of export-data.zip in staging directory.
Screenshot: 
—
Query 10 — Command & Control (svchost.exe → 78.141.196.6:443)
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "svchost.exe"
| where RemoteIP == "78.141.196.6" and RemotePort == 443
| project Timestamp, DeviceName, InitiatingProcessFileName, LocalIP, RemoteIP, RemotePort, Protocol
| order by Timestamp asc

Results: Validates outbound C2 to 78.141.196.6 over TLS.
Screenshot:
—
Query 11 — Exfiltration (Discord webhook)
DeviceProcessEvents
| where FileName =~ "curl.exe"
| where ProcessCommandLine has_all ("-F", "file=@", "discord.com/api/webhooks")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc

Results: Shows archive upload via Discord webhook.
Screenshot:
—
Query 12 — Anti‑Forensics (wevtutil.exe cl Security)
DeviceProcessEvents
| where FileName =~ "wevtutil.exe"
| where ProcessCommandLine has " cl "
| extend ClearedLog = extract(@"cl\s+(\w+)", 1, ProcessCommandLine)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, ClearedLog
| order by Timestamp asc

Results: Orders log clears; first occurrence shows Security.
Screenshot:
—
Query 13 — Impact (Hidden admin account support)
DeviceEvents
| where ActionType in ("UserAccountCreated","UserAddedToGroup","UserAccountModified")
| where AdditionalFields contains "support"
| project Timestamp, DeviceName, AccountName, ActionType, AdditionalFields
| order by Timestamp asc

Results: Shows creation of the hidden account support and its addition to the Administrators group.
Screenshot:
—
Query 14 — Lateral Movement (cmdkey.exe + mstsc.exe → 10.1.0.188)
DeviceProcessEvents
| where FileName in~ ("cmdkey.exe","mstsc.exe")
| extend TargetIP = extract(@"(\d{1,3}(?:\.\d{1,3}){3})", 1, ProcessCommandLine)
| where isnotempty(TargetIP)
| project Timestamp, AccountName, FileName, ProcessCommandLine, TargetIP
| order by Timestamp asc

Results: Confirms cmdkey/mstsc targeting 10.1.0.188.
Screenshot:
—
Report Completed By: Isaac Kasuske
Date: 11/23/2025
