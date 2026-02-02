
<p align="center">
  <img
    src="https://github.com/user-attachments/assets/a4a09fc7-07b8-419e-b324-50670881501f"
    width="1200"
    alt="Threat Hunt Cover Image"
  />
</p>






# 🛡️ Threat Hunt Report – Year-End Bonus Data Theft Campaign

---

## 📌 Executive Summary

This threat hunt uncovered a sophisticated multi-stage data theft operation targeting sensitive HR compensation and employee review data across multiple systems within the environment. What began as compromised credentials on workstation **sys1-dept** evolved into a coordinated campaign spanning five compromised endpoints, systematic targeting of year-end bonus matrices, employee scorecards, and candidate packages, culminating in staged data prepared for exfiltration.

The adversary demonstrated advanced operational security through methodical reconnaissance, dual persistence mechanisms, anti-forensic log clearing, and phased data collection across departmental boundaries. The attacker's focus on approved compensation data, combined with lateral movement to HR and Finance systems, indicates corporate espionage, insider threat activity, or ransomware operators seeking maximum leverage for extortion.

This investigation highlights how attackers can successfully exploit valid credentials to blend into legitimate business operations, systematically pillage sensitive data repositories, and prepare for bulk exfiltration while evading real-time detection through off-hours operations and social engineering file naming conventions.

---

## 🎯 Hunt Objectives

- Identify malicious activity across compromised endpoints and network telemetry
- Map attacker progression from initial access through data staging
- Correlate adversary behavior to MITRE ATT&CK techniques
- Document evidence, detection gaps, and remediation priorities
- Reconstruct the full attack timeline across multiple compromised systems

---

## 🧭 Scope & Environment

- **Environment:** Corporate Windows endpoint environment with HR, IT, and Finance departmental systems
- **Data Sources:** Microsoft Defender for Endpoint Advanced Hunting
  - DeviceProcessEvents
  - DeviceNetworkEvents
  - DeviceFileEvents
  - DeviceRegistryEvents
  - DeviceEvents (SensitiveFileRead telemetry)
  - IdentityLogonEvents
- **Timeframe:** 2025-12-01 03:13:33 UTC → 2025-12-04 08:29:21 UTC
- **Compromised Systems Identified:**
  - sys1-dept (Initial Access - Departmental Workstation)
  - YE-HELPDESKTECH (IT Helpdesk System)
  - YE-HRPLANNER (HR Planning Workstation)
  - YE-FINANCEREVIE (Finance Review Workstation)
  - main1-srvr (Primary Server - Centralized Data Repository)

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔥 Executive MITRE ATT&CK Heatmap](#-executive-mitre-attck-heatmap)
- [📊 Executive Takeaway](#-executive-takeaway)
- [⏱️ Attack Timeline](#️-attack-timeline)
- [🔍 Flag Analysis](#-flag-analysis)
  - [Phase 1: Initial Access & Reconnaissance (Flags 1-4)](#-flag-1)
  - [Phase 2: Data Discovery & Staging (Flags 5-7)](#-flag-5)
  - [Phase 3: Persistence Establishment (Flags 8-9)](#-flag-8)
  - [Phase 4: Lateral Movement & Expanded Collection (Flags 10-13)](#-flag-10)
  - [Phase 5: Secondary Staging & Exfiltration Prep (Flags 14-16)](#-flag-14)
  - [Phase 6: Server Compromise & Final Collection (Flags 17-22)](#-flag-17)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

This threat hunt reconstructed a full-spectrum data theft operation beginning with valid account compromise on **sys1-dept** and expanding through coordinated lateral movement to IT, HR, and Finance departmental systems, culminating in centralized collection on **main1-srvr**. The adversary demonstrated sophisticated tradecraft including:

**Operational Characteristics:**
- **Hands-on-keyboard activity:** Manual file browsing via notepad.exe, Explorer.exe
- **Phased collection:** 3+ day operation with distinct collection waves
- **Social engineering:** File and task names mimicking legitimate HR/payroll operations
- **Operational security:** Off-hours activity (3-7 AM local time), log clearing, connectivity pre-flight testing
- **Systematic targeting:** Repeated access to the same employee files (JavierR) across systems

**Attack Progression:**
1. Initial remote access using compromised credentials (account: 5y51-d3p7)
2. Execution of social-engineered PowerShell payload (PayrollSupportTool.ps1)
3. System and file reconnaissance to map sensitive data locations
4. Discovery and staging of bonus matrices, employee reviews, candidate packages
5. Dual persistence via registry Run keys and scheduled tasks
6. Lateral movement to 4 additional systems via internal pivot point (192.168.0.110)
7. Expanded collection from HR Planning, IT Helpdesk, Finance Review workstations
8. Server compromise (main1-srvr) for access to centralized archive repositories
9. Final staging of year-end review packages
10. Connectivity testing via httpbin.org before planned exfiltration
11. Anti-forensic activity (PowerShell operational log clearing)

This hunt matters because it demonstrates how determined attackers with valid credentials can systematically identify, access, and prepare high-value HR data for theft while evading perimeter defenses and blending into normal business operations. The focus on approved compensation data and systematic cross-departmental collection indicates sophisticated threat actors with specific intelligence objectives rather than opportunistic malware.

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority | System |
|-----:|-------------------|----------|----------|---------|
| 1 | Initial Access – Valid Accounts | T1078 | Critical | sys1-dept |
| 2 | Remote Services – Remote Desktop | T1021 | High | sys1-dept |
| 3 | Execution – Command & Scripting Interpreter (PowerShell) | T1059.001 | High | sys1-dept |
| 4 | Discovery – System Owner/User Discovery | T1033 | Medium | sys1-dept |
| 5 | Discovery – File and Directory Discovery | T1083 | High | sys1-dept |
| 6 | Collection – Archive Collected Data | T1560.001 | High | sys1-dept |
| 7 | Command and Control – Application Layer Protocol | T1071 | High | sys1-dept |
| 8 | Persistence – Registry Run Keys | T1547.001 | High | sys1-dept |
| 9 | Persistence – Scheduled Task | T1053.005 | High | sys1-dept |
| 10 | Lateral Movement – Remote Services | T1021 | Critical | sys1-dept |
| 11 | Lateral Movement – Internal Pivot | T1570 | Critical | sys1-dept |
| 12 | Discovery – User-Level File Access | T1083 | Medium | sys1-dept |
| 13 | Collection – Data from Local System (Sensitive) | T1005 | Critical | sys1-dept |
| 14 | Collection – Data Staging | T1074.001 | High | sys1-dept |
| 15 | Command and Control – Exfiltration Testing | T1048 | High | sys1-dept |
| 16 | Defense Evasion – Indicator Removal (Clear Logs) | T1070.001 | Critical | sys1-dept |
| 17 | Lateral Movement – Secondary System Compromise | T1021 | Critical | main1-srvr |
| 18 | Collection – Sensitive Archive Access | T1005 | Critical | main1-srvr |
| 19 | Lateral Movement – Finance System Access | T1021 | Critical | main1-srvr |
| 20 | Collection – Centralized Archive Staging | T1074.001 | Critical | main1-srvr |
| 21 | Collection – Final Phase Staging Timing | T1074 | High | main1-srvr |
| 22 | Command and Control – Final Exfiltration Test | T1048 | Critical | main1-srvr |

---

## 🔥 Executive MITRE ATT&CK Heatmap

| ATT&CK Phase | Techniques Observed | Severity | Analyst Notes |
|--------------|-------------------|----------|---------------|
| Initial Access | Valid Accounts (T1078), Remote Services | 🔴 Critical | Compromised credentials from external IP 4.150.155.223 |
| Execution | PowerShell Execution (T1059.001), Social Engineering | 🔴 Critical | PayrollSupportTool.ps1 with execution policy bypass |
| Persistence | Registry Run Keys (T1547.001), Scheduled Tasks (T1053.005) | 🔴 Critical | Dual persistence mechanisms established |
| Privilege Escalation | Valid Accounts | 🟠 High | Account 5y51-d3p7 likely has elevated privileges |
| Defense Evasion | Log Clearing (T1070.001), Social Engineering Names | 🔴 Critical | PowerShell operational logs deliberately cleared |
| Credential Access | Registry Inspection, Token Discovery | 🟠 Medium | Preparation for credential reuse evident |
| Discovery | File Discovery (T1083), User Discovery (T1033) | 🟠 High | Systematic enumeration of HR directories |
| Lateral Movement | Remote Services (T1021), Internal Pivoting (T1570) | 🔴 Critical | 5 systems compromised across 3 departments |
| Collection | Data Staging (T1074), Sensitive File Access (T1005) | 🔴 Critical | Targeted collection of bonus/compensation data |
| Command & Control | Application Layer Protocol (T1071), Testing Services | 🔴 High | httpbin.org used for exfiltration pre-flight |
| Exfiltration | Data Transfer (Preparation Phase) | 🟠 High | Staged but not confirmed exfiltrated |

---

## 📊 Executive Takeaway

This intrusion represents a **sophisticated, multi-phase data theft operation** targeting the organization's most sensitive HR and compensation data.

**Key Findings:**
- **Scope:** 5 compromised systems across IT, HR, and Finance departments
- **Duration:** 3+ day operation with phased collection activity
- **Target:** Year-end bonus matrices, employee performance reviews, candidate packages
- **Method:** Valid account compromise, social engineering, systematic lateral movement
- **Status:** Data staged and prepared for exfiltration; actual data loss not confirmed but highly likely

**Critical Indicators:**
1. **Systematic targeting of specific data types** across multiple systems indicates intelligence-driven operation
2. **Dual persistence mechanisms** demonstrate intent for long-term access
3. **Anti-forensic activity** (log clearing) shows sophistication and operational security awareness
4. **Off-hours operations** (3-7 AM) designed to evade real-time detection
5. **Social engineering naming** (PayrollSupportTool, BonusReviewAssist) successfully evaded initial scrutiny

**Business Impact:**
- **Confidential compensation data** compromised, including executive-level bonus allocations
- **Employee performance reviews** accessed, creating privacy and legal exposure
- **Candidate hiring packages** stolen, impacting competitive recruitment intelligence
- **Multiple department credentials** likely compromised, enabling future lateral movement
- **Regulatory exposure** under data protection laws (GDPR, CCPA) for employee PII theft

**Immediate Actions Required:**
1. Reset credentials for account 5y51-d3p7 and all accounts that authenticated from 192.168.0.110
2. Isolate and forensically image all 5 compromised systems
3. Review all scheduled tasks and registry Run keys across the environment
4. Implement emergency monitoring for httpbin.org and similar testing services
5. Notify legal/compliance teams of potential data breach
6. Conduct damage assessment to determine if exfiltration occurred

Early detection through correlation of remote session telemetry, sensitive file access patterns, and off-hours PowerShell activity is critical to disrupting similar intrusions before they achieve their objectives.

---

## ⏱️ Attack Timeline

### December 1, 2025
**03:13:33 UTC** - Initial access established on sys1-dept via compromised account 5y51-d3p7

### December 3, 2025
**01:24:53 UTC** - First outbound connection to external IP 4.150.155.223 from remote session  
**06:07:15 UTC** - PayrollSupportTool.ps1 executed with execution policy bypass  
**06:12:03 UTC** - Reconnaissance: `whoami /all` executed  
**06:27:10 UTC** - First data staging: export_stage.zip created  
**06:27:31 UTC** - Connectivity test: Connection to example.com  
**06:27:59 UTC** - Persistence: Registry Run key established  
**06:46:30 UTC** - Lateral movement: YE-HELPDESKTECH accesses Review_JavierR.lnk  
**06:47:40 UTC** - Persistence: Scheduled task "BonusReviewAssist" created  
**07:24:42 UTC** - Discovery: BonusMatrix_Draft_v3.xlsx.lnk accessed  
**07:25:15 UTC** - File access: Review_JavierR.lnk opened via notepad  
**07:25:39 UTC** - **Critical:** BonusMatrix_Q4_Approved.xlsx sensitive file read  
**07:26:03 UTC** - Lateral movement: YE-HRPLANNER accesses Q4Candidate_Pack.zip  
**07:26:28 UTC** - Connectivity test: Connection to httpbin.org (18.214.194.42)  
**08:18:58 UTC** - Anti-forensics: PowerShell operational logs cleared via wevtutil

### December 4, 2025
**03:11:58 UTC** - Server compromise: PowerShell process created on main1-srvr  
**03:14:03 UTC** - Lateral movement: YE-FINANCEREVIE accesses Scorecard_JavierR.txt  
**03:15:29 UTC** - Final staging: YearEnd_ReviewPackage_2025.zip created on main1-srvr  
**03:15:48 UTC** - Final connectivity test: httpbin.org (54.83.21.156) from main1-srvr  
**10:57:09 UTC** - Remote session from external IP 150.171.28.11 detected on main1-srvr

## 🔍 Flag Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: Initial Access via Compromised Service Account</strong></summary>

### 🎯 Objective
Establish initial foothold on target endpoint using compromised credentials.

### 📌 Finding
ProcessCreated event observed on sys1-dept endpoint initiated by account 5y51-d3p7. The activity represents the first recorded action in the attack chain, indicating successful credential compromise and initial access to the environment.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/1/2025, 3:13:33.708 AM |
| ActionType | ProcessCreated |
| DeviceId | 1d0e12b505d61c7eb1f1fd7842d905c99f6ae26a |
| Initiating Account | sys1-dept\5y51-d3p7 |
| AccountSid | S-1-5-21-805396643-3920266184-3816603331-500 |
| TenantId | 60c7f53e-249a-4077-b68e-55a4ae877d7c |

### 💡 Why it matters
This event marks the initial access phase of the intrusion, aligning with **MITRE ATT&CK T1078 (Valid Accounts)**. The use of account 5y51-d3p7 suggests credential theft or compromise occurred prior to this activity. The timing (early morning hours) and the fact this is the earliest observed event in the timeline indicates this is the attacker's entry point. The AccountSid ending in -500 indicates a built-in Administrator account, representing high-privilege access from the start of the compromise.

### 🖼️ Screenshot
<img width="883" height="225" alt="image" src="https://github.com/user-attachments/assets/78aeda9a-e124-4750-9002-05abdbd14c65" />


### 🛠️ Detection Recommendation
**Hunting Tip:**  
Pivot on the compromised account (5y51-d3p7) across all logs to identify the full scope of unauthorized activity. Query authentication logs (IdentityLogonEvents) to determine where and when this account authenticated prior to this event. Look for anomalous logon patterns such as impossible travel, unusual source IPs, or logons outside normal business hours. Correlate process creation events with this account to map the attack chain progression.

</details>


---

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: Remote Session Source Attribution</strong></summary>

### 🎯 Objective
Identify the remote session source information tied to the initiating access on the first endpoint.

### 📌 Finding
Remote session activity detected on sys1-dept originating from external IP address 192.168.0.110. The session was established under the compromised account 5y51-d3p7, with the `IsInitiatingProcessRemoteSession` flag confirming remote execution context. This metadata reveals the attacker's source infrastructure used to access the compromised endpoint.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 1:24:53.664 AM |
| InitiatingProcessAccountName | 5y51-d3p7 |
| IsInitiatingProcessRemoteSession | true |
| LocalIP | 10.0.0.12 |
| RemoteIPType | Public |
| RemoteIP | 192.168.0.110 |

### 💡 Why it matters
This finding maps to **MITRE ATT&CK T1021 (Remote Services)** and provides critical attribution intelligence. The remote IP 4.150.155.223 represents the attacker's infrastructure or compromised staging system used to access the environment. Remote session metadata is essential for identifying the attack origin, blocking active threat actor infrastructure, and correlating activity across multiple incidents. The public IP classification confirms external access rather than lateral movement from another internal system. This data point enables defenders to pivot across all telemetry sources to identify the full scope of connections from this malicious source.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-12-01T03:13:33.7087736Z');
let endTime = todatetime('2025-12-03T08:29:21.12468Z');
let badUser = "5y51-d3p7";
let firstCompromisedDevice = "sys1-dept";
DeviceNetworkEvents
| where DeviceName == firstCompromisedDevice
| where InitiatingProcessAccountName == badUser
| where TimeGenerated >= startTime + 24h
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, IsInitiatingProcessRemoteSession, LocalIP, RemoteIPType, RemoteIP
```

### 🖼️ Screenshot
<img src="uploads/1769913464418_image.png">

### 🛠️ Detection Recommendation
**Hunting Tip:**  
Pivot on the source IP 4.150.155.223 across all network telemetry to identify additional compromised accounts or systems. Query IdentityLogonEvents and DeviceLogonEvents for authentication attempts from this IP. Hunt for remote session indicators (`IsInitiatingProcessRemoteSession == true`) combined with external IPs to detect similar attack patterns. Correlate with threat intelligence feeds to determine if this IP is known malicious infrastructure. Check firewall logs for persistence of connections from this source and identify any other internal systems contacted.

</details>

---


<details>
<summary id="-flag-3">🚩 <strong>Flag 3: Support Script Execution Confirmation</strong></summary>

### 🎯 Objective
Confirm execution of a support-themed PowerShell script from a user-accessible directory.

### 📌 Finding
PowerShell execution detected on sys1-dept with an execution policy bypass executing a script named "PayrollSupportTool.ps1" from the user's Downloads directory. The command line indicates deliberate evasion of PowerShell security controls to execute the malicious payload.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 6:07:15.565 AM |
| AccountName | 5y51-d3p7 |
| ProcessCommandLine | "powershell.exe" -ExecutionPolicy Bypass -File C:\users\5y51-D3p7\Downloads\PayrollSupportTool.ps1 |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1059.001 (Command and Scripting Interpreter: PowerShell)** and **T1204.002 (User Execution: Malicious File)**. The use of `-ExecutionPolicy Bypass` is a classic defense evasion technique that circumvents PowerShell's built-in script execution restrictions. The script name "PayrollSupportTool.ps1" follows social engineering naming conventions designed to appear legitimate. Execution from the Downloads folder indicates the script was likely delivered via phishing, malicious download, or copied during the remote session. This marks a critical escalation point where the attacker transitions from remote access to executing custom tooling on the compromised system.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-12-01T06:27:31.1857946Z');
let endTime = todatetime('2025-12-03T08:29:21.12468Z');
let badUser = "5y51-d3p7";
let firstCompromisedDevice = "sys1-dept";
DeviceProcessEvents
| where DeviceName == firstCompromisedDevice
| where AccountName == badUser
| where TimeGenerated between (startTime .. endTime)
| where ProcessCommandLine has "powershell"
| project TimeGenerated, DeviceName, ProcessCommandLine
```

### 🖼️ Screenshot
<img src="uploads/1769915136997_image.png">

### 🛠️ Detection Recommendation
**Hunting Tip:**
Hunt for PowerShell executions with `-ExecutionPolicy Bypass`, `-ep bypass`, or `-exec bypass` flags across the environment. Query DeviceFileEvents to identify when PayrollSupportTool.ps1 was created or modified to determine delivery method. Extract and analyze the script contents from endpoint or backup sources. Pivot on Downloads directory executions combined with script file extensions (.ps1, .bat, .vbs, .js) to identify similar malicious script activity. Look for child processes spawned by this PowerShell execution to map post-exploitation activity.

</details>

---

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: System Reconnaissance Initiation</strong></summary>

### 🎯 Objective
Identify the first reconnaissance action used to gather host and user context.

### 📌 Finding
Execution of whoami.exe detected on sys1-dept with the /all parameter, representing the attacker's initial reconnaissance command to enumerate security context. This command provides comprehensive information about the current user's privileges, group memberships, and security identifiers.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 6:12:03.789 AM |
| DeviceName | sys1-dept |
| ProcessCommandLine | "whoami.exe" /all |

### 💡 Why it matters
This activity aligns with **MITRE ATT&CK T1033 (System Owner/User Discovery)** and **T1069 (Permission Groups Discovery)**. The `whoami /all` command is a standard post-exploitation reconnaissance technique used to assess current privilege level, group memberships, security tokens, and integrity levels. This information guides the attacker's next moves, including privilege escalation paths, lateral movement targets, and understanding what actions the compromised account can perform. The timing approximately 5 minutes prior to the PowerShell script execution suggests this was executed manually by the attacker to assess the environment before deploying additional tooling.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-12-01T06:27:31.1857946Z');
let endTime = todatetime('2025-12-03T08:29:21.12468Z');
let badUser = "5y51-d3p7";
let firstCompromisedDevice = "sys1-dept";
DeviceProcessEvents
| where DeviceName == firstCompromisedDevice
| where AccountName == badUser
| where TimeGenerated between (startTime .. endTime)
| where ProcessCommandLine has_any ("whoami", "net user", "net group", "query user")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img src="uploads/1769915438765_image.png">

### 🛠️ Detection Recommendation
**Hunting Tip:**
Hunt for native Windows reconnaissance binaries (whoami.exe, net.exe, ipconfig.exe, systeminfo.exe, tasklist.exe) executed within remote sessions or by service accounts. Look for rapid sequential execution of multiple discovery commands within short time windows, indicating scripted or manual enumeration. Correlate whoami execution with subsequent privilege escalation attempts or lateral movement activity. Query for command-line parameters like /all, /priv, or /groups that indicate thorough enumeration. Stack count executions by AccountName to identify accounts performing abnormal discovery activity.

</details>

---

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: Sensitive Bonus-Related File Exposure</strong></summary>

### 🎯 Objective
Identify the first sensitive year-end bonus-related file that was accessed during exploration.

### 📌 Finding
FileCreated event detected on sys1-dept for a file named "BonusMatrix_Draft_v3.xlsx.lnk" initiated by Explorer.exe under the compromised account. This shortcut file indicates the attacker discovered and interacted with sensitive compensation data, creating a link that could be used for later access or as evidence of file discovery.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 7:24:42.960 AM |
| ActionType | FileCreated |
| FileName | BonusMatrix_Draft_v3.xlsx.lnk |
| InitiatingProcess | Explorer.exe |
| InitiatingProcessAccountName | 5y51-d3p7 |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1083 (File and Directory Discovery)** and indicates progression toward **T1005 (Data from Local System)**. The creation of a .lnk (shortcut) file suggests interactive browsing behavior through Windows Explorer, indicating hands-on-keyboard activity rather than automated tooling. The file name "BonusMatrix_Draft_v3.xlsx" clearly contains sensitive compensation information that would be high-value for corporate espionage, insider threats, or ransomware operators seeking leverage. The "Draft_v3" naming convention suggests this is working documentation that may contain unredacted or preliminary bonus allocation data. This marks the transition from system reconnaissance to targeted data discovery.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-11-01T06:27:31.1857946Z');
let endTime = todatetime('2025-12-10T08:29:21.12468Z');
let badUser = "5y51-d3p7";
let firstCompromisedDevice = "sys1-dept";
DeviceFileEvents
| where DeviceName == firstCompromisedDevice
| where InitiatingProcessAccountName == badUser
| where TimeGenerated between (startTime .. endTime)
| project TimeGenerated, ActionType, DeviceName, FileName, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessUniqueId
```

### 🖼️ Screenshot
<img width="782" height="221" alt="image" src="https://github.com/user-attachments/assets/09c92ac0-7dae-4acd-8c6e-391ffd6bc749" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Query DeviceFileEvents for access to files containing sensitive keywords (bonus, salary, compensation, payroll, executive) by the compromised account. Look for FileCreated actions involving .lnk files as indicators of interactive file browsing. Pivot to identify the full path of the original BonusMatrix_Draft_v3.xlsx file and check for subsequent FileRead, FileModified, or FileCopied events. Hunt for file staging activity where sensitive documents are copied to temporary directories or compressed into archives. Review network telemetry for potential exfiltration of this file to external IPs or cloud storage services.

</details>

---

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: Data Staging Activity Confirmation</strong></summary>

### 🎯 Objective
Confirm that sensitive data was prepared for movement by staging into an export/archive output.

### 📌 Finding
FileCreated event detected for "export_stage.zip" on sys1-dept, initiated by powershell.exe under the compromised account. This archive file represents data staging activity where the attacker packaged sensitive files for exfiltration, confirming progression from discovery to collection and preparation for data theft.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 6:27:10.682 AM |
| ActionType | FileCreated |
| FileName | export_stage.zip |
| InitiatingProcessCommandLine | "powershell.exe" |
| InitiatingProcessId | 5632 |
| InitiatingProcessUniqueId | 2533274790396713 |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1560.001 (Archive Collected Data: Archive via Utility)** and **T1074.001 (Data Staged: Local Data Staging)**. The creation of a ZIP archive with the explicit name "export_stage" demonstrates clear intent to exfiltrate data. Staging files into compressed archives serves multiple adversary objectives: reducing file size for faster transfer, evading DLP controls that may not inspect compressed content, and consolidating multiple files into a single exfiltration package. The PowerShell initiation indicates the attacker used scripting to automate the compression process, likely part of the PayrollSupportTool.ps1 payload executed earlier. This marks a critical escalation from reconnaissance and discovery to active data theft preparation.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-11-01T06:27:31.1857946Z');
let endTime = todatetime('2025-12-10T08:29:21.12468Z');
let badUser = "5y51-d3p7";
let firstCompromisedDevice = "sys1-dept";
DeviceFileEvents
| where DeviceName == firstCompromisedDevice
| where InitiatingProcessAccountName == badUser
| where TimeGenerated between (startTime .. endTime)
| where FileName endswith ".zip" or FileName endswith ".rar" or FileName endswith ".7z"
| project TimeGenerated, ActionType, DeviceName, FileName, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessUniqueId
```

### 🖼️ Screenshot
<img width="791" height="213" alt="image" src="https://github.com/user-attachments/assets/d329e2e9-e0e4-4570-a7ee-1529b296caf6" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Hunt for archive file creation (.zip, .rar, .7z, .tar.gz) in non-standard locations or with suspicious naming patterns (export, stage, data, backup, temp). Correlate the InitiatingProcessUniqueId 2533274790396713 with DeviceProcessEvents to identify all actions taken by this specific PowerShell instance. Query DeviceFileEvents for files added to the archive immediately before creation to identify what sensitive data was packaged. Monitor for subsequent file transfer activity involving export_stage.zip via network connections, cloud uploads, or removable media. Use FileProfile enrichment to determine if the archive still exists and retrieve it for forensic analysis.

</details>

---

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: Outbound Connectivity Test</strong></summary>

### 🎯 Objective
Confirm that outbound access was tested prior to any attempted transfer.

### 📌 Finding
PowerShell-initiated network connection detected to example.com immediately following data staging activity. The connection occurred 21 seconds after the creation of export_stage.zip, confirming the attacker tested outbound connectivity before attempting exfiltration.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 6:27:31.185 AM |
| InitiatingProcessFileName | powershell.exe |
| InitiatingProcessCommandLine | "powershell.exe" |
| RemoteIP | 23.215.0.136 |
| RemoteUrl | example.com |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1016 (System Network Configuration Discovery)** and pre-exfiltration testing behavior. The use of example.com as a connectivity test target is significant because it is a benign, widely-accessible domain specifically reserved for documentation and testing purposes (RFC 2606). Attackers commonly use such domains to verify outbound network access without triggering threat intelligence alerts that malicious infrastructure would generate. The 21-second gap between data staging and connectivity testing demonstrates methodical, hands-on-keyboard behavior where the attacker validated the exfiltration path before transmitting sensitive data. This pre-flight check confirms the attacker's operational security awareness and intent to exfiltrate the staged archive.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-12-01T03:13:33.7087736Z');
let endTime = todatetime('2025-12-04T06:27:10.6828355Z');
let badUser = "5y51-d3p7";
let firstCompromisedDevice = "sys1-dept";
DeviceNetworkEvents
| where DeviceName == firstCompromisedDevice
| where InitiatingProcessAccountName == badUser
| where TimeGenerated between (startTime .. endTime)
| where isnotempty(RemoteIPType)
| where isnotempty(RemoteUrl)
| project TimeGenerated, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="930" height="166" alt="image" src="https://github.com/user-attachments/assets/d5875cf2-0202-4f8f-b5a1-fe05c964cf05" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Monitor for connections to benign testing domains (example.com, example.org, httpbin.org, ifconfig.me) from non-administrative accounts or servers, especially when preceded by data staging activity. Hunt for PowerShell network connections that occur within short time windows after archive file creation. Correlate this connectivity test with subsequent connections to the same or different external IPs to identify the actual exfiltration destination. Stack count by RemoteUrl to identify unusual testing domains across the environment. Query for similar patterns where file archiving is followed by network connectivity tests within 1-5 minutes.

</details>

---

<details>
<summary id="-flag-8">🚩 <strong>Flag 8: Registry-Based Persistence</strong></summary>

### 🎯 Objective
Identify evidence of persistence established via a user Run key.

### 📌 Finding
Registry modification detected in the HKEY_CURRENT_USER Run key on sys1-dept, establishing persistence for the malicious PayrollSupportTool.ps1 script. The registry value was set to execute the PowerShell payload with execution policy bypass on every user logon.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 6:27:59.603 AM |
| InitiatingProcessAccountName | 5y51-d3p7 |
| ActionType | RegistryValueSet |
| RegistryKey | HKEY_CURRENT_USER\S-1-5-21-805396643-3920266184-3816603331-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run |
| RegistryValueData | powershell.exe -ExecutionPolicy Bypass -File "C:\Users\5y51-D3p7\Downloads\PayrollSupportTool.ps1" |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder)**. Registry Run keys are one of the most common persistence mechanisms on Windows systems, ensuring the malicious script executes automatically whenever the compromised user logs on. The attacker placed the exact command used during initial execution into the persistence mechanism, maintaining the execution policy bypass to evade PowerShell restrictions. This occurs 28 seconds after the connectivity test, indicating the attacker followed a methodical checklist: stage data, test connectivity, establish persistence, then proceed with exfiltration. The use of the user-specific SID in the registry path ensures persistence survives across sessions for this specific account.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-12-01T03:13:33.7087736Z');
let endTime = todatetime('2025-12-04T06:27:10.6828355Z');
let badUser = "5y51-d3p7";
let firstCompromisedDevice = "sys1-dept";
DeviceRegistryEvents
| where TimeGenerated between (startTime .. endTime)
| where DeviceName == firstCompromisedDevice
| where InitiatingProcessAccountName == badUser
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has "Run"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ActionType, RegistryKey, RegistryValueData
```

### 🖼️ Screenshot
<img width="929" height="193" alt="image" src="https://github.com/user-attachments/assets/d7c56536-a0dd-4c10-b195-d6e387b227b4" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Monitor all RegistryValueSet actions under Run and RunOnce keys in both HKEY_CURRENT_USER and HKEY_LOCAL_MACHINE hives. Hunt for registry values containing PowerShell commands with execution policy bypasses, encoded commands, or scripts executing from user-writable directories like Downloads or Temp. Query for registry modifications occurring shortly after malicious script execution to identify persistence establishment patterns. Stack count RegistryValueData containing "powershell", "-enc", "-exec bypass", or suspicious file paths. Correlate registry persistence with subsequent logon events to identify when the persistence mechanism successfully triggered.

</details>

---

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: Scheduled Task Persistence</strong></summary>

### 🎯 Objective
Confirm a scheduled task was created or used to automate recurring execution.

### 📌 Finding
Scheduled task creation detected on sys1-dept using schtasks.exe to establish daily execution of the malicious PayrollSupportTool.ps1 script. The task named "BonusReviewAssist" was configured to run daily with execution policy bypass, ensuring persistent access beyond the current session.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 6:47:40.825 AM |
| AccountName | 5y51-d3p7 |
| ProcessCommandLine | "schtasks.exe" /Create /SC DAILY /TN BonusReviewAssist /TR "powershell.exe -ExecutionPolicy Bypass -File C:\Users\5y51-D3p7\Downloads\PayrollSupportTool.ps1" /F |
| InitiatingProcessCommandLine | "powershell.exe" |
| Task Name | BonusReviewAssist |
| Schedule | DAILY |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1053.005 (Scheduled Task/Job: Scheduled Task)**. The attacker established a second persistence mechanism approximately 20 minutes after the registry Run key, demonstrating defense-in-depth from an adversary perspective. Scheduled tasks provide persistence that survives user logoff, system reboots, and even if the registry Run key is discovered and removed. The task name "BonusReviewAssist" employs social engineering to appear legitimate within a corporate environment, particularly during year-end bonus cycles. The `/F` flag indicates the attacker forcefully overwrote any existing task with the same name. The daily schedule ensures the malicious script executes repeatedly, maintaining access and potentially exfiltrating updated data on an ongoing basis.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-12-01T03:13:33.7087736Z');
let endTime = todatetime('2025-12-04T06:27:10.6828355Z');
let badUser = "5y51-d3p7";
let firstCompromisedDevice = "sys1-dept";
DeviceProcessEvents
| where TimeGenerated between (startTime .. endTime)
| where DeviceName == firstCompromisedDevice
| where AccountName == badUser
| where ProcessCommandLine has "schtasks"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine
```

### 🖼️ Screenshot
<img width="937" height="315" alt="image" src="https://github.com/user-attachments/assets/a98a4c91-7d45-4ee1-8067-2fabc624c610" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Monitor for schtasks.exe executions with `/Create` parameter, especially when initiated by PowerShell or script interpreters. Hunt for scheduled tasks configured to execute PowerShell with execution policy bypasses or scripts from user-writable directories. Query Security event logs (Event ID 4698) for scheduled task creation events. Stack count task names across the environment to identify suspicious naming patterns that mimic legitimate services. Correlate scheduled task creation with registry persistence mechanisms occurring within the same timeframe to identify layered persistence strategies. Use `Get-ScheduledTask` or query the Task Scheduler service to enumerate all tasks and identify those executing from non-standard paths.

</details>

---

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: Secondary Access to Employee Scorecard Artifact</strong></summary>

### 🎯 Objective
Identify evidence that a different remote session context accessed an employee-related scorecard file.

### 📌 Finding
File access detected for employee review artifact "Review_JavierR.lnk" on sys1-dept from a secondary remote session originating from device YE-HELPDESKTECH at IP address 192.168.0.110. This represents lateral movement from a different compromised system accessing sensitive employee performance data.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 6:46:30.922 AM |
| FileName | Review_JavierR.lnk |
| IsInitiatingProcessRemoteSession | true |
| InitiatingProcessRemoteSessionIP | 192.168.0.110 |
| InitiatingProcessRemoteSessionDeviceName | YE-HELPDESKTECH |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1021 (Remote Services)** and **T1570 (Lateral Tool Transfer)**. The remote session from YE-HELPDESKTECH indicates the attacker compromised multiple systems within the environment and is conducting coordinated data collection operations. The internal IP address 192.168.0.110 confirms this is lateral movement within the network, not external access. The device naming convention "HELPDESKTECH" suggests the attacker targeted IT support infrastructure, which typically has elevated privileges and broad network access. Access to employee review files from a different system demonstrates the attacker's awareness of where sensitive HR data resides and their ability to pivot across the environment to collect it. This secondary access occurring shortly before the scheduled task creation suggests the attacker was simultaneously operating from multiple footholds.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-11-01T06:27:31.1857946Z');
let endTime = todatetime('2025-12-10T08:29:21.12468Z');
let firstCompromisedDevice = "sys1-dept";
DeviceFileEvents
| where TimeGenerated between (startTime .. endTime)
| where DeviceName == firstCompromisedDevice
| where IsInitiatingProcessRemoteSession == true
| where FileName has_any ("review", "scorecard", "employee", "performance")
| project TimeGenerated, DeviceName, FileName, InitiatingProcessRemoteSessionIP, InitiatingProcessRemoteSessionDeviceName
```

### 🖼️ Screenshot
<img width="693" height="188" alt="image" src="https://github.com/user-attachments/assets/ca432535-b3f1-46d6-89b2-4064a58662b6" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Pivot on the device name YE-HELPDESKTECH to identify all systems it has accessed and all accounts used from this device. Query DeviceLogonEvents and IdentityLogonEvents for authentication activity from 192.168.0.110 to map the full scope of lateral movement. Hunt for remote session access to file shares, especially those containing HR, financial, or executive data. Look for other employee review files accessed during this timeframe to determine the breadth of data collection. Correlate this secondary access pattern with the primary attacker activity timeline to understand if this represents a second operator or automated lateral movement tooling.

</details>

---

<details>
<summary id="-flag-11">🚩 <strong>Flag 11: Bonus Matrix Activity by a New Remote Session Context</strong></summary>

### 🎯 Objective
Identify another remote session device name that is associated with higher level related activities later in the chain.

### 📌 Finding
File access detected for "Q4Candidate_Pack.zip" on sys1-dept from a third remote session originating from device YE-HRPLANNER at IP address 192.168.0.110. This represents continued lateral movement targeting bonus and candidate-related sensitive data from what appears to be a compromised HR planning workstation.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 7:26:03.976 AM |
| FileName | Q4Candidate_Pack.zip |
| IsInitiatingProcessRemoteSession | true |
| InitiatingProcessRemoteSessionIP | 192.168.0.110 |
| InitiatingProcessRemoteSessionDeviceName | YE-HRPLANNER |

### 💡 Why it matters
This activity represents continued **MITRE ATT&CK T1021 (Remote Services)** and **T1005 (Data from Local System)**. The attacker has now compromised at least three systems: the initial sys1-dept endpoint, YE-HELPDESKTECH, and YE-HRPLANNER. The device naming "HRPLANNER" indicates this is a workstation used by HR personnel for planning activities, likely with access to highly sensitive compensation, hiring, and organizational planning data. The same source IP (192.168.0.110) suggests the attacker is using a central staging or pivot point to access multiple targets. The file "Q4Candidate_Pack.zip" indicates pre-packaged sensitive data, potentially containing candidate information, hiring plans, or compensation packages. This access occurred 40 minutes after the employee review file access, demonstrating systematic progression through HR-related data sources.

### 🖼️ Screenshot
<img width="915" height="199" alt="image" src="https://github.com/user-attachments/assets/e7df45c7-be4d-4b76-a420-ae7c7588e678" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Investigate the 192.168.0.110 source IP to identify what system is serving as the pivot point for these lateral movement operations. Query all file access events from both YE-HELPDESKTECH and YE-HRPLANNER to determine the full scope of compromised HR infrastructure. Hunt for authentication activity showing how the attacker gained access to these HR systems, particularly focusing on credential dumping or pass-the-hash techniques. Look for data staging and exfiltration attempts involving files accessed from these remote sessions. Correlate the timeline of lateral movement with network connections to identify if data from multiple systems was aggregated before exfiltration.

</details>

---

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: Performance Review Access Validation</strong></summary>

### 🎯 Objective
Confirm access to employee performance review material through user-level tooling.

### 📌 Finding
Process execution of notepad.exe detected opening the file "Review_JavierR.lnk" located in the HR\PerformanceReviews directory. The access was initiated by PowerShell under the compromised account, indicating the attacker was actively exploring employee performance review materials stored in a dedicated HR directory structure.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 7:25:15.628 AM |
| DeviceName | sys1-dept |
| AccountName | 5y51-d3p7 |
| ProcessCommandLine | "notepad.exe" C:\Users\5y51-D3p7\HR\PerformanceReviews\Review_JavierR.lnk |
| InitiatingProcessCommandLine | "powershell.exe" |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1083 (File and Directory Discovery)** and **T1005 (Data from Local System)**. The use of notepad.exe to open the file indicates manual, interactive exploration of the performance review directory rather than automated data collection. The file path reveals the attacker discovered a structured HR directory at `C:\Users\5y51-D3p7\HR\PerformanceReviews\`, suggesting systematic organization of sensitive personnel data on the compromised endpoint. This access occurred approximately 40 minutes after the employee review shortcut was first accessed from the remote session (YE-HELPDESKTECH), indicating the attacker returned to investigate the actual contents after initial discovery. The PowerShell initiation suggests this may have been part of a scripted enumeration routine that opened files for review.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-12-01T03:13:33.7087736Z');
let endTime = todatetime('2025-12-04T06:27:10.6828355Z');
let badUser = "5y51-d3p7";
let firstCompromisedDevice = "sys1-dept";
DeviceProcessEvents
| where TimeGenerated between (startTime .. endTime)
| where DeviceName == firstCompromisedDevice
| where AccountName == badUser
| where ProcessCommandLine contains "review"
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine
```

### 🖼️ Screenshot
<img src="uploads/1769939764404_image.png">

### 🛠️ Detection Recommendation
**Hunting Tip:**
Monitor for notepad.exe, wordpad.exe, or other text/document viewers opening files from sensitive directories (HR, Finance, Executive, Legal). Hunt for process command lines containing paths to performance review, compensation, or personnel directories. Correlate notepad.exe executions initiated by scripting engines (PowerShell, cmd.exe) as indicators of automated reconnaissance. Query DeviceFileEvents for all files within the HR\PerformanceReviews directory to identify the full scope of accessible employee data. Look for patterns where files are opened via notepad shortly after being discovered through file browsing or search operations.

</details>

---


<details>
<summary id="-flag-13">🚩 <strong>Flag 13: Approved/Final Bonus Artifact Access</strong></summary>

### 🎯 Objective
Confirm access to a finalized year-end bonus artifact with sensitive-read classification.

### 📌 Finding
SensitiveFileRead event detected for the approved Q4 bonus matrix file "BonusMatrix_Q4_Approved.xlsx" located in the HR\Bonus2025 directory. The file was accessed by PowerShell under the compromised account, representing unauthorized access to finalized executive compensation data.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 7:25:39.165 AM |
| ActionType | SensitiveFileRead |
| FileName | BonusMatrix_Q4_Approved.xlsx |
| FolderPath | C:\Users\5y51-D3p7\HR\Bonus2025 |
| InitiatingProcessFileName | powershell.exe |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1005 (Data from Local System)** and represents the most critical data theft event in the attack chain. Unlike the earlier "Draft_v3" file, this is the **approved, finalized** bonus matrix containing authoritative Q4 compensation decisions. The "SensitiveFileRead" ActionType indicates this file has been tagged with Microsoft Information Protection sensitivity labels, confirming organizational awareness of its confidential nature. The PowerShell initiation suggests this was part of an automated data collection script targeting specifically labeled sensitive files. This access occurred immediately after the attacker opened performance reviews via notepad, indicating systematic progression through increasingly sensitive HR data. The approved bonus matrix represents the ultimate target for corporate espionage, insider threats, or ransomware operators seeking maximum leverage.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-11-01');
let endTime = todatetime('2025-12-10');
DeviceEvents
| where DeviceName == "sys1-dept"
| where TimeGenerated between (startTime .. endTime)
| where ActionType == "SensitiveFileRead"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName, AdditionalFields
```

### 🖼️ Screenshot
<img width="932" height="149" alt="image" src="https://github.com/user-attachments/assets/6dc10497-f2e1-4cfd-9842-b68f02d35985" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Monitor all SensitiveFileRead events across the environment, prioritizing files with "approved", "final", or "confidential" in their names. Hunt for PowerShell or scripting engines accessing files with Microsoft Information Protection labels. Correlate SensitiveFileRead events with subsequent network connections or archive file creation to identify potential exfiltration. Query for accounts accessing multiple sensitive files within short time windows to detect bulk data collection. Implement alerts for SensitiveFileRead actions occurring outside business hours or from service accounts. Review data loss prevention (DLP) policies to ensure sensitive files trigger appropriate controls when accessed, copied, or transferred.

</details>

---

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: Candidate Archive Creation Location</strong></summary>

### 🎯 Objective
Identify where a suspicious candidate-related archive was created.

### 📌 Finding
FileCreated event detected for "Q4Candidate_Pack.zip" in the Documents directory on sys1-dept. The archive was created at the file path C:\Users\5y51-D3p7\Documents\Q4Candidate_Pack.zip, representing staged candidate recruitment data prepared for exfiltration.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 7:26:03.976 AM |
| ActionType | FileCreated |
| FileName | Q4Candidate_Pack.zip |
| FolderPath | C:\Users\5y51-D3p7\Documents\Q4Candidate_Pack.zip |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1560.001 (Archive Collected Data: Archive via Utility)** and **T1074.001 (Data Staged: Local Data Staging)**. The Documents directory location is significant because it differs from the earlier export_stage.zip which was created in the user profile root. This separation suggests the attacker is organizing different data categories into distinct staging locations, potentially to facilitate selective exfiltration or to evade detection rules that monitor only common staging directories like Temp or Downloads. The Q4 timeframe in the filename indicates this archive targets fourth-quarter candidate hiring data, which would contain sensitive information about potential employees, compensation offers, and competitive hiring intelligence. This staging occurred immediately after the attacker accessed the approved bonus matrix file, demonstrating rapid progression from data discovery to collection and packaging.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-11-01');
let endTime = todatetime('2025-12-10');
let firstCompromisedDevice = "sys1-dept";
DeviceFileEvents
| where DeviceName == firstCompromisedDevice
| where TimeGenerated between (startTime .. endTime)
| where FileName has_any (".zip")
| where FileName has "candidate"
| project TimeGenerated, FileName, ActionType, FolderPath
```

### 🖼️ Screenshot
<img width="924" height="133" alt="image" src="https://github.com/user-attachments/assets/e6f67935-ddb1-4035-8368-d3417b48775b" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Monitor for zip file creation in user profile directories, especially Documents, Desktop, and Downloads folders. Hunt for archive files with business-related naming patterns (candidate, hiring, Q1-Q4, finance, payroll) as these indicate targeted data collection rather than benign user activity. Query for multiple archive files created within close proximity to identify systematic data staging operations. Correlate archive creation with SensitiveFileRead events to determine what sensitive data was packaged. Look for archives created in locations that differ from typical malware staging paths to detect evasion techniques.

</details>

---


<details>
<summary id="-flag-15">🚩 <strong>Flag 15: Outbound Transfer Attempt Timestamp</strong></summary>

### 🎯 Objective
Confirm an outbound transfer attempt occurred after staging activity.

### 📌 Finding
PowerShell-initiated network connection detected to httpbin.org (18.214.194.42) occurring 25 seconds after the Q4Candidate_Pack.zip archive was created. The connection to httpbin.org, a service commonly used for testing HTTP requests including POST operations, confirms the attacker validated data transfer capabilities before exfiltration.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 7:26:28.595 AM |
| InitiatingProcessFileName | powershell.exe |
| InitiatingProcessCommandLine | "powershell.exe" |
| RemoteIP | 18.214.194.42 |
| RemoteUrl | httpbin.org |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1048 (Exfiltration Over Alternative Protocol)** pre-flight testing. The connection to httpbin.org is significant because it is a legitimate HTTP request testing service that provides endpoints for testing POST, PUT, and file upload operations. Attackers commonly use httpbin.org to validate their exfiltration scripts can successfully transmit data before sending it to their actual command and control infrastructure. The 25-second gap between archive creation and this connectivity test demonstrates methodical operational security where the attacker validates the transfer mechanism immediately after packaging sensitive data. This follows the same pattern observed earlier with the example.com connectivity test, confirming the attacker's systematic approach to validating network egress before committing to data exfiltration.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-12-03T07:26:03.9765516Z');
let endTime = todatetime('2025-12-04T06:27:10.6828355Z');
let badUser = "5y51-d3p7";
let firstCompromisedDevice = "sys1-dept";
DeviceNetworkEvents
| where DeviceName == firstCompromisedDevice
| where InitiatingProcessAccountName == badUser
| where TimeGenerated between (startTime .. endTime)
| where RemoteIPType == "Public"
| project TimeGenerated, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="882" height="254" alt="image" src="https://github.com/user-attachments/assets/cbe16653-7881-4ae1-9e30-a1d60894cb39" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Monitor for connections to testing and debugging services (httpbin.org, webhook.site, requestbin.com, postb.in) from production systems, especially when initiated by PowerShell or scripting engines. Hunt for network connections occurring within 1-5 minutes after archive file creation to identify exfiltration preparation activity. Query for HTTP POST requests to external endpoints following data staging events. Correlate connections to benign testing services with subsequent connections to unfamiliar or suspicious domains to identify the actual exfiltration destination. Implement network egress controls to block or alert on connections to known testing services from endpoints that should not require external debugging capabilities.

</details>

---

<details>
<summary id="-flag-16">🚩 <strong>Flag 16: Local Log Clearing Attempt Evidence</strong></summary>

### 🎯 Objective
Identify command-line evidence of attempted local log clearing.

### 📌 Finding
Execution of wevtutil.exe detected with command-line parameters targeting the PowerShell Operational event log for clearing. The command was initiated by PowerShell under the compromised account, representing an attempt to erase evidence of PowerShell-based malicious activity from Windows event logs.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | sys1-dept |
| Timestamp (UTC) | 12/3/2025, 8:18:58.783 AM |
| ProcessCommandLine | "wevtutil.exe" cl Microsoft-Windows-PowerShell/Operational |
| AccountName | 5y51-d3p7 |
| InitiatingProcessCommandLine | "powershell.exe" |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1070.001 (Indicator Removal: Clear Windows Event Logs)**. The wevtutil utility with the "cl" (clear log) parameter is the standard Windows method for erasing event logs. Targeting the PowerShell Operational log specifically demonstrates the attacker's awareness that their PowerShell-based activities (script execution, file staging, network connections) would generate telemetry in this log. This log clearing occurred approximately 52 minutes after the outbound transfer test to httpbin.org, suggesting the attacker attempted to cover their tracks after validating exfiltration capabilities. The PowerShell initiation indicates this was part of an automated cleanup script rather than manual command execution. Clearing logs is a strong indicator of malicious intent, as legitimate administrative activities rarely require wholesale log deletion.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-11-01');
let endTime = todatetime('2025-12-10');
let firstCompromisedDevice = "sys1-dept";
DeviceProcessEvents
| where DeviceName == firstCompromisedDevice
| where TimeGenerated between (startTime .. endTime)
| where ProcessCommandLine has_any ("wevtutil", "Clear-EventLog", "clear-log", "cl Security", "cl Application", "cl System")
| project TimeGenerated, ProcessCommandLine, AccountName, InitiatingProcessCommandLine
```

### 🖼️ Screenshot
<img width="924" height="145" alt="image" src="https://github.com/user-attachments/assets/ca1fb295-8d4c-4fbf-8289-4d9f2b505a1a" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Monitor for all wevtutil.exe executions with "cl" or "clear-log" parameters, treating these as high-severity indicators of anti-forensic activity. Hunt for Clear-EventLog PowerShell cmdlet usage across the environment. Look for log clearing attempts targeting Security, System, or PowerShell Operational logs as these contain the most valuable forensic evidence. Correlate log clearing with other suspicious activity from the same account within the preceding hours to identify what the attacker is attempting to hide. Implement Sysmon or centralized log forwarding to ensure event data is preserved externally even if local logs are cleared. Alert on any log clearing outside of approved maintenance windows or by non-administrative accounts.

</details>

---

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: Second Endpoint Scope Confirmation</strong></summary>

### 🎯 Objective
Identify the second endpoint involved in the chain based on similar telemetry patterns.

### 📌 Finding
Network telemetry identified a second compromised endpoint named "main1-srvr" exhibiting remote session activity. The server shows an active remote session connection to external IP 150.171.28.11, indicating lateral movement from the initial sys1-dept workstation compromise to critical server infrastructure.

### 🔍 Evidence
| Field | Value |
|------|-------|
| DeviceName | main1-srvr |
| Timestamp (UTC) | 12/3/2025, 10:57:09.238 AM |
| InitiatingProcessAccountName | main1-srvr |
| IsInitiatingProcessRemoteSession | true |
| LocalIP | 10.0.0.12 |
| RemoteIPType | Public |
| RemoteIP | 150.171.28.11 |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1021 (Remote Services)** and **T1570 (Lateral Tool Transfer)**. The compromise of main1-srvr represents a critical escalation from endpoint to server infrastructure. Servers typically have elevated privileges, access to centralized data repositories, and network visibility across the enterprise. The device naming "main1-srvr" suggests this is a primary server, potentially hosting critical business services, databases, or file shares. The external remote session IP (150.171.28.11) differs from the previous external IP (4.150.155.223), indicating the attacker may be using multiple command and control infrastructure points or has established a multi-hop proxy chain. The shared LocalIP (10.0.0.12) with sys1-dept suggests these systems are on the same network segment, facilitating lateral movement.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-12-01T03:13:33.7087736Z');
let endTime = todatetime('2025-12-04T08:29:21.12468Z');
DeviceNetworkEvents
| where TimeGenerated between (startTime .. endTime)
| where InitiatingProcessRemoteSessionIP == "192.168.0.110"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, IsInitiatingProcessRemoteSession, LocalIP, RemoteIPType, RemoteIP
```

### 🖼️ Screenshot
<img width="902" height="224" alt="image" src="https://github.com/user-attachments/assets/146bea65-dbc8-476f-9d18-51f960e833cc" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Pivot on main1-srvr to identify all malicious activity on this second compromised system. Query DeviceProcessEvents, DeviceFileEvents, and DeviceRegistryEvents for main1-srvr using the same hunting techniques applied to sys1-dept. Investigate how lateral movement occurred from sys1-dept to main1-srvr by searching for authentication events, SMB connections, or remote execution attempts between these systems. Hunt for the external IP 150.171.28.11 across all network telemetry to identify other potentially compromised systems communicating with this infrastructure. Assess the criticality of main1-srvr and prioritize containment and forensic analysis given its likely elevated role in the environment.

</details>

---

<details>
<summary id="-flag-18">🚩 <strong>Flag 18: Approved Bonus Artifact Access on Second Endpoint</strong></summary>

### 🎯 Objective
Confirm the approved bonus artifact is accessed again on the second endpoint.

### 📌 Finding
SensitiveFileRead event detected on main1-srvr for "YearEnd_ReviewPackage_2025.zip" located in the internal archive directory. The file was accessed by a PowerShell process that was created at 3:11:58.602 AM UTC, demonstrating continued targeting of year-end compensation and review materials on the compromised server infrastructure.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | main1-srvr |
| Timestamp (UTC) | 12/4/2025, 3:15:48.361 AM |
| ActionType | SensitiveFileRead |
| FileName | YearEnd_ReviewPackage_2025.zip |
| FolderPath | C:\Users\Main1-Srvr\Documents\InternalReferences\ArchiveBundles |
| InitiatingProcessFileName | powershell.exe |
| InitiatingProcessCreationTime (UTC) | 12/4/2025, 3:11:58.602 AM |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1005 (Data from Local System)** on the second compromised endpoint. The access to year-end review package materials on main1-srvr demonstrates the attacker's systematic targeting of sensitive HR and compensation data across multiple systems. The file location in "InternalReferences\ArchiveBundles" suggests this server hosts centralized archive storage, making it a high-value target containing historical sensitive data beyond what was available on the workstation. The PowerShell process creation timestamp (3:11:58 AM) occurring approximately 4 minutes before the file read indicates the attacker launched a data discovery or collection script that subsequently identified and accessed this sensitive archive. This represents the third distinct year-end/bonus-related artifact accessed across the attack chain, confirming compensation data as the primary intelligence objective.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-11-01');
let endTime = todatetime('2025-12-10');
DeviceEvents
| where DeviceName == "main1-srvr"
| where TimeGenerated between (startTime .. endTime)
| where ActionType == "SensitiveFileRead"
| project TimeGenerated, ActionType, InitiatingProcessCreationTime, FileName, FolderPath, InitiatingProcessFileName, AdditionalFields
```

### 🖼️ Screenshot
<img width="936" height="191" alt="image" src="https://github.com/user-attachments/assets/2e08662a-39e0-4bfe-9a4e-006706aab023" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Hunt for SensitiveFileRead events across both compromised systems to identify the full scope of sensitive data access. Correlate InitiatingProcessCreationTime with DeviceProcessEvents to identify what spawned the PowerShell process and what command-line parameters were used. Query for files in "Archive" or "Reference" directories as these often contain historical sensitive data that may not be actively monitored. Look for patterns where the same attacker targets similar file types (bonus, review, compensation) across multiple systems, indicating focused intelligence gathering. Investigate whether YearEnd_ReviewPackage_2025.zip was subsequently staged or exfiltrated by querying for file copy, network transfer, or additional archive creation events following this access.

</details>

---

<details>
<summary id="-flag-19">🚩 <strong>Flag 19: Employee Scorecard Access on Second Endpoint</strong></summary>

### 🎯 Objective
Confirm employee-related scorecard access occurs again on the second endpoint and identify the remote session device context.

### 📌 Finding
Notepad execution detected on main1-srvr opening the file "Scorecard_JavierR.txt" from the DepartmentReviews directory. The access originated from a remote session associated with device "YE-FINANCEREVIE", representing a fourth compromised system in the attack chain and indicating the attacker's continued focus on employee performance and compensation data.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | main1-srvr |
| Timestamp (UTC) | 12/4/2025, 3:14:03.712 AM |
| ProcessCommandLine | "notepad.exe" C:\Users\Main1-Srvr\Documents\DepartmentReviews\Scorecard_JavierR.txt |
| AccountName | main1-srvr |
| InitiatingProcessCommandLine | "powershell.exe" |
| ProcessRemoteSessionDeviceName | YE-FINANCEREVIE |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1021 (Remote Services)** and **T1083 (File and Directory Discovery)** from a fourth compromised endpoint. The device name "YE-FINANCEREVIE" indicates this is a Finance department workstation used for employee reviews, suggesting the attacker has systematically compromised systems across multiple departments (IT Helpdesk, HR Planning, Finance Review). The targeting of the same employee's scorecard (JavierR) that was previously accessed on sys1-dept demonstrates persistent intelligence gathering on specific individuals, potentially indicating this employee holds a sensitive role or has access the attacker wants to compromise. The use of notepad for file viewing initiated by PowerShell suggests automated or scripted browsing behavior. The structured directory path "DepartmentReviews" on the server indicates main1-srvr serves as a centralized repository for cross-departmental personnel data.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-11-01');
let endTime = todatetime('2025-12-10');
let firstCompromisedDevice = "main1-srvr";
DeviceProcessEvents
| where DeviceName == firstCompromisedDevice
| where TimeGenerated between (startTime .. endTime)
| where FileName =~ "notepad.exe"
| where ProcessCommandLine has "scorecard"
| project TimeGenerated, ProcessCommandLine, AccountName, InitiatingProcessCommandLine, ProcessRemoteSessionDeviceName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="920" height="167" alt="image" src="https://github.com/user-attachments/assets/ba9320ad-bcca-4cba-bc3b-3bd958a136a5" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Pivot on YE-FINANCEREVIE to identify all systems it has accessed and all accounts used from this device. Query authentication logs for lateral movement from YE-FINANCEREVIE to map the full attack path. Hunt for access to employee scorecards, performance reviews, or personnel files from Finance department systems as these should typically be restricted to HR. Correlate the targeting of specific individuals (like JavierR) across multiple systems to identify if the attacker is building dossiers on high-value targets. Investigate whether the Finance Review workstation has elevated access to compensation, budget, or financial planning data that could be the attacker's ultimate objective. Review network segmentation to determine why Finance workstations have access to HR server infrastructure.

</details>

---

<details>
<summary id="-flag-20">🚩 <strong>Flag 20: Staging Directory Identification on Second Endpoint</strong></summary>

### 🎯 Objective
Identify the directory used for consolidation of internal reference materials and archived content.

### 📌 Finding
FileCreated event detected on main1-srvr for "YearEnd_ReviewPackage_2025.zip" in the InternalReferences\ArchiveBundles directory structure. This location represents the attacker's staging area on the compromised server for consolidating sensitive year-end review and compensation materials before exfiltration.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | main1-srvr |
| Timestamp (UTC) | 12/4/2025, 3:15:29.259 AM |
| ActionType | FileCreated |
| FolderPath | C:\Users\Main1-Srvr\Documents\InternalReferences\ArchiveBundles\YearEnd_ReviewPackage_2025.zip |
| FileName | YearEnd_ReviewPackage_2025.zip |
| InitiatingProcessAccountName | main1-srvr |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1074.001 (Data Staged: Local Data Staging)** on the compromised server infrastructure. The directory path "InternalReferences\ArchiveBundles" indicates the attacker leveraged existing organizational structure for storing reference materials to blend their staging activity with legitimate file operations. Creating the archive in an established "ArchiveBundles" directory provides operational camouflage, as security monitoring may overlook zip file creation in locations designated for archival purposes. This staging occurred approximately 90 seconds before the same file was accessed via SensitiveFileRead (Flag 18), indicating a create-then-read workflow. The consolidation of year-end review materials into a single archive demonstrates the attacker's preparation for bulk exfiltration of sensitive HR and compensation data collected across multiple compromised systems.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-12-01');
let endTime = todatetime('2025-12-05');
DeviceFileEvents
| where DeviceName == "main1-srvr"
| where TimeGenerated between (startTime .. endTime)
| where FileName endswith ".zip"
| where InitiatingProcessAccountName !in~ ("system", "local service", "network service")
| where InitiatingProcessAccountName !startswith "NT AUTHORITY"
| project TimeGenerated, ActionType, FolderPath, FileName, InitiatingProcessAccountName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="910" height="198" alt="image" src="https://github.com/user-attachments/assets/1a36156d-bcc9-4a02-9f1e-bd52abf76d94" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Monitor for zip file creation in directories with names suggesting legitimate archival purposes (Archive, Backup, Reference, Historical) as attackers exploit these locations for staging. Hunt for file creation followed by SensitiveFileRead events within short time windows to identify create-then-access patterns indicative of staging operations. Query for archives created in user profile Documents folders on servers, as servers typically don't require user-level document archiving. Correlate staging directory locations with subsequent network connections to identify exfiltration attempts. Implement file integrity monitoring on sensitive data repositories to detect unexpected archive creation activity.

</details>

---

<details>
<summary id="-flag-21">🚩 <strong>Flag 21: Staging Activity Timing on Second Endpoint</strong></summary>

### 🎯 Objective
Determine when staging activity occurred during the final phase on the second endpoint.

### 📌 Finding
File staging activity on main1-srvr occurred at 3:15:29.259 AM UTC on December 4th, 2025. This timestamp marks the creation of the YearEnd_ReviewPackage_2025.zip archive in the InternalReferences\ArchiveBundles directory, representing the final data consolidation phase before exfiltration.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | main1-srvr |
| Timestamp (UTC) | 12/4/2025, 3:15:29.259 AM |
| ActionType | FileCreated |
| FileName | YearEnd_ReviewPackage_2025.zip |
| FolderPath | C:\Users\Main1-Srvr\Documents\InternalReferences\ArchiveBundles |

### 💡 Why it matters
This timestamp represents a critical inflection point in the attack timeline, marking the transition from data collection to preparation for exfiltration on the server infrastructure. The timing at 3:15:29 AM occurred approximately 3 minutes after the PowerShell process was created (3:11:58 AM from Flag 18) and 90 seconds before the sensitive file read event (3:15:48 AM), revealing a compressed operational tempo during the final phase. The early morning timing (3:15 AM local time) demonstrates the attacker's operational security awareness, choosing hours with minimal security analyst coverage and reduced likelihood of real-time detection. This staging event on main1-srvr occurred approximately 20 hours after the initial staging activity on sys1-dept (7:26 AM on December 3rd), indicating the attacker conducted phased collection operations across multiple days to avoid triggering volume-based detection thresholds.

### 🛠️ Detection Recommendation
**Hunting Tip:**
Analyze the timing patterns of staging events across both compromised systems to understand the attacker's operational rhythm and identify potential time-based detection opportunities. Hunt for archive creation during off-hours (late night/early morning) as indicators of malicious activity rather than legitimate business operations. Correlate this timestamp with network telemetry to determine if exfiltration occurred immediately after staging or if the attacker waited for additional operational windows. Query for other suspicious activities occurring within the same time window (3:00-4:00 AM) to identify potentially related attack actions. Use this timing information to prioritize threat hunting during historical gaps in security monitoring coverage.

</details>

---

<details>
<summary id="-flag-22">🚩 <strong>Flag 22: Outbound Connection Remote IP (Final Phase)</strong></summary>

### 🎯 Objective
Identify the remote IP associated with the final outbound connection attempt.

### 📌 Finding
PowerShell-initiated network connection detected from main1-srvr to httpbin.org (54.83.21.156) on port 443 occurring 19 seconds after the YearEnd_ReviewPackage_2025.zip staging activity. This connection represents the final outbound transfer attempt, confirming the attacker validated exfiltration capabilities from the compromised server.

### 🔍 Evidence
| Field | Value |
|------|-------|
| Host | main1-srvr |
| Timestamp (UTC) | 12/4/2025, 3:15:48.347 AM |
| InitiatingProcessFileName | powershell.exe |
| RemoteIP | 54.83.21.156 |
| RemoteUrl | httpbin.org |
| RemotePort | 443 |

### 💡 Why it matters
This activity represents **MITRE ATT&CK T1048 (Exfiltration Over Alternative Protocol)** and mirrors the same connectivity testing pattern observed on sys1-dept (Flag 7 and 15). The use of httpbin.org for the second time confirms this is the attacker's standard operational procedure for validating HTTP/HTTPS exfiltration capabilities before transmitting actual data. The connection to port 443 (HTTPS) indicates the attacker is preparing encrypted exfiltration to evade network inspection. The timing 19 seconds after staging demonstrates the same rapid operational tempo seen previously: stage data, immediately test connectivity, then exfiltrate. The different IP address (54.83.21.156 vs 23.215.0.136 from Flag 7) suggests httpbin.org uses multiple backend servers or the attacker is routing through different infrastructure. This represents the final observable phase before data leaves the environment.

### 🔧 KQL Query Used
```kql
let startTime = todatetime('2025-12-04T03:15:29Z');
let endTime = todatetime('2025-12-05');
DeviceNetworkEvents
| where DeviceName == "main1-srvr"
| where TimeGenerated >= startTime
| where RemoteIPType == "Public"
| where InitiatingProcessAccountName !in~ ("system", "local service", "network service")
| where InitiatingProcessAccountName !startswith "NT AUTHORITY"
| project TimeGenerated, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<img width="919" height="169" alt="image" src="https://github.com/user-attachments/assets/0b12d531-9df1-4e9a-815a-c1f78ac9779e" />


### 🛠️ Detection Recommendation
**Hunting Tip:**
Investigate the remote IP 54.83.21.156 across all network telemetry to identify if other systems successfully exfiltrated data to this endpoint. Hunt for connections to httpbin.org followed by connections to other external IPs within minutes, as the testing service connection may precede actual exfiltration to attacker-controlled infrastructure. Query for HTTPS (port 443) connections from servers to external IPs, as server-to-internet traffic is often anomalous and may indicate data theft. Correlate this connection with subsequent file deletion, log clearing, or other anti-forensic activities to complete the attack timeline. Implement network monitoring for data volume transferred to identify if actual exfiltration occurred or if this was only a connectivity test that was interrupted by detection or remediation.

</details>

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps

* **Insufficient Remote Session Monitoring:** Remote sessions from internal IP 192.168.0.110 to multiple systems (sys1-dept, main1-srvr) went undetected despite serving as the primary pivot point for lateral movement. No alerting existed for unusual remote session patterns or cross-departmental access from IT/Finance systems to HR data repositories.

* **Lack of Sensitive File Access Correlation:** Multiple SensitiveFileRead events for bonus matrices and employee reviews across different systems were not correlated into a unified detection. The organization lacked behavioral analytics to identify the same employee data (JavierR) being accessed repeatedly across unrelated systems within short timeframes.

* **Social Engineering Filename Evasion:** Files and scheduled tasks using HR-related naming conventions (PayrollSupportTool.ps1, BonusReviewAssist, BonusMatrix_Draft_v3.xlsx) successfully evaded detection. No content inspection or behavioral analysis existed to validate whether "payroll" or "bonus" themed scripts were legitimate administrative tools.

* **Off-Hours Activity Baseline Gaps:** Critical operations occurring between 3:00-7:00 AM local time (file staging, log clearing, server access) did not trigger anomaly detection. The organization lacked time-of-day baselines for administrative accounts and service accounts accessing sensitive data.

* **Log Clearing Detection Failure:** The use of `wevtutil.exe` to clear PowerShell operational logs (T1070.001) was not detected in real-time, allowing the attacker to eliminate forensic evidence. No compensating controls existed such as centralized log forwarding or immutable log storage.

* **Connectivity Testing Service Blind Spot:** Repeated connections to httpbin.org and example.com for exfiltration pre-flight testing were not flagged as suspicious. Network monitoring lacked signatures for common testing/debugging services frequently abused by attackers.

* **Dual Persistence Mechanism Oversight:** The establishment of both registry Run keys and scheduled tasks within 20 minutes was not correlated as a persistence layering technique. Each mechanism was potentially logged but not analyzed as part of a coordinated attack pattern.

* **Cross-Department Lateral Movement Visibility:** Movement from IT Helpdesk (YE-HELPDESKTECH) to HR data, and Finance workstations (YE-FINANCEREVIE) accessing HR servers, violated implicit trust boundaries but generated no alerts. Network segmentation and lateral movement detection were insufficient.

---

### Recommendations

#### **Immediate (0-30 days)**

* **Deploy Centralized Log Forwarding:** Implement immediate forwarding of Security, System, and PowerShell logs to SIEM or centralized logging platform with immutable storage. Prioritize PowerShell operational logs (Event ID 4104) to prevent log clearing from eliminating evidence.

* **Create High-Fidelity Detections:**
  - Alert on `wevtutil.exe` execution with "cl" or "clear-log" parameters (T1070.001)
  - Alert on SensitiveFileRead events for files containing "bonus", "salary", "compensation" outside business hours
  - Alert on remote sessions from IT/Finance systems accessing HR file shares or servers
  - Alert on connections to httpbin.org, example.com, webhook.site from production systems

* **Implement Emergency Credential Rotation:** Force password resets for account 5y51-d3p7 and all accounts that authenticated from 192.168.0.110. Conduct forensic review of accounts with access to compromised systems to identify potential credential harvesting.

* **Enable Enhanced PowerShell Logging:** Deploy PowerShell script block logging and module logging across all endpoints. Configure alerts for execution policy bypass (`-ExecutionPolicy Bypass`) combined with scripts from user-writable directories.

#### **Short-Term (30-90 days)**

* **Deploy Behavioral Analytics for Sensitive Data:** Implement user and entity behavior analytics (UEBA) to baseline normal access patterns for HR data repositories. Alert on deviations including: off-hours access, cross-departmental access, rapid sequential file access, same-file access from multiple systems.

* **Implement File Access Correlation:** Create detection logic that correlates SensitiveFileRead events across systems within configurable time windows (e.g., same filename accessed on 3+ systems within 24 hours). Prioritize files containing PII, compensation, or executive content.

* **Network Segmentation Enforcement:** Implement microsegmentation or firewall rules preventing IT Helpdesk and Finance workstations from directly accessing HR file servers. Require privileged access workstations (PAWs) or jump boxes for cross-departmental administrative tasks.

* **Deploy EDR Behavioral Detections:** Configure endpoint detection and response (EDR) platform to alert on:
  - Multiple persistence mechanisms created within short time windows
  - Archive file creation followed by network connections to public IPs
  - Notepad/Explorer execution of files from network shares or unusual directories
  - Registry Run key modifications outside approved change windows

#### **Long-Term (90+ days)**

* **Implement Data Loss Prevention (DLP):** Deploy DLP controls on endpoints and network egress points to detect and block exfiltration of files containing sensitive keywords (bonus, salary, SSN patterns, employee IDs). Prioritize monitoring of archive file transfers and uploads to cloud storage services.

* **Establish Privileged Access Management (PAM):** Implement just-in-time privileged access for administrative accounts. Require MFA and session recording for any account accessing HR, Finance, or Executive data repositories. Eliminate persistent administrative rights from standard user accounts.

* **Deploy Deception Technology:** Place honeypot files (fake bonus matrices, employee records) in HR directories to detect unauthorized access. Implement honeytoken credentials in registry/memory that trigger alerts if accessed or used.

* **Conduct Adversary Emulation Exercises:** Perform purple team exercises simulating this attack pattern (credential compromise → lateral movement → data staging → exfiltration prep) to validate detection coverage and refine alerting thresholds. Test both technical controls and SOC analyst response procedures.

* **Implement Zero Trust Architecture:** Transition to zero-trust principles requiring continuous authentication and authorization for all resource access. Remove implicit trust between departmental systems and implement least-privilege access controls for all data repositories.

* **Enhance Security Awareness Training:** Develop targeted training for HR, Finance, and IT staff on social engineering techniques, suspicious file naming patterns, and proper handling of sensitive data. Include specific scenarios around fake "payroll support" or "bonus review" tools.

---

## 🧾 Final Assessment

This intrusion represents a **sophisticated, intelligence-driven data theft operation** executed by a capable threat actor with clear objectives, operational discipline, and advanced tradecraft. The attacker successfully compromised five systems across three departments over a 72-hour period, systematically identifying, accessing, and staging the organization's most sensitive HR compensation data while evading real-time detection.

**Risk Severity: CRITICAL**

The compromise of approved bonus matrices, employee performance reviews, and candidate packages creates significant business risk including competitive intelligence loss, regulatory exposure under data protection laws, employee privacy violations, and potential for follow-on extortion or ransomware attacks. The attacker's establishment of dual persistence mechanisms and demonstrated ability to clear forensic logs indicates intent for long-term access rather than opportunistic data theft.

**Attacker Sophistication: ADVANCED**

The adversary demonstrated capabilities consistent with sophisticated cybercrime groups, corporate espionage actors, or insider threats with technical expertise. Key indicators of advanced capability include: phased operations over multiple days, social engineering of filenames and task names to evade detection, operational security through off-hours activity, systematic lateral movement via internal pivot infrastructure, anti-forensic log clearing, and exfiltration pre-flight testing. This was not automated malware but rather hands-on-keyboard activity by a skilled operator.

**Defensive Posture: INSUFFICIENT**

Current defensive capabilities failed to detect or prevent this intrusion at multiple critical junctures. Detection gaps exist across initial access, lateral movement, persistence, data collection, and exfiltration preparation phases. The absence of behavioral analytics, sensitive data access monitoring, cross-system correlation, and real-time alerting on anti-forensic activity created an environment where a determined attacker could operate for days without interdiction.

**Immediate Priorities:**

1. **Containment:** Assume data exfiltration occurred and notify affected stakeholders, legal counsel, and potentially regulatory bodies
2. **Eradication:** Complete credential rotation, persistence removal, and forensic imaging of all compromised systems
3. **Recovery:** Implement emergency detections for similar attack patterns while longer-term improvements are developed
4. **Lessons Learned:** Conduct comprehensive post-incident review to identify root causes and systemic defensive weaknesses

The organization must treat this incident as a watershed moment requiring fundamental improvements to identity and access management, data protection controls, network segmentation, and security monitoring capabilities. Without significant investment in detection engineering, behavioral analytics, and privileged access controls, similar intrusions will continue to succeed.

---
