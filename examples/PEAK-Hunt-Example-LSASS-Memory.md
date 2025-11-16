*This is an example PEAK Framework hunt report demonstrating behavioral hunting for LSASS memory access (T1003.001). This hunt focuses on the BEHAVIOR of credential dumping, not specific tools or hashes.*

Reference: [PEAK Template Guide](https://dispatch.thorcollective.com/p/the-peak-threat-hunting-template)

---

# Threat Hunting Report - PEAK Framework

## Hunt ID: `H-20241115-001`
*(H for Hypothesis-driven, B for Baseline, M for Model-Assisted)*

## Hunt Title:
Hunt for LSASS Memory Access Behavior (Credential Dumping)

---

## PREPARE: Define the Hunt

| **Hunt Information**            | **Details** |
|----------------------------------|-------------|
| **Hypothesis**                  | Adversaries are accessing LSASS memory to extract credentials, regardless of the tool used (Mimikatz, ProcDump, custom malware, etc.) |
| **Threat Hunter Name**          | THOR Threat Hunting Team |
| **Date**                        | 2024-11-15 |
| **Requestor**                   | Security Operations Center |
| **Timeframe for hunt**          | 2 days |

## Scoping with the ABLE Methodology

Clearly define your hunt scope using the ABLE framework. Replace all placeholders (`[ ]`) with relevant details for your scenario.

| **Field**   | **Description**                                                                                                                                                                                                                                                                             | **Your Input**                   |
|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------|
| **Actor**   | *(Optional)* Identify the threat actor involved with the behavior, if applicable. This step is optional because hunts aren't always tied to a specific actor. You may be investigating techniques used across multiple adversaries or looking for suspicious activity regardless of attribution. Focus on the what and how before the who, unless actor context adds meaningful value to the hunt.  | `N/A - Hunting behaviors across all threat actors`          |
| **Behavior**| Describe the actions observed or expected, including tactics, techniques, and procedures (TTPs). Specify methods or tools involved.                                                                                                                                                 | `LSASS Memory Access (T1003.001) - Process opening handle to lsass.exe with PROCESS_VM_READ access rights to extract credentials from memory` |
| **Location**| Specify where the activity occurred, such as an endpoint, network segment, or cloud environment.                                                                                                                                 | `All Windows endpoints and servers in corporate environment`            |
| **Evidence**| Clearly list logs, artifacts, or telemetry supporting your hypothesis. For each source, provide critical fields required to validate the behavior, and include specific examples of observed or known malicious activity to illustrate expected findings. | `- Source: Sysmon Event ID 10 (ProcessAccess)`<br>`- Key Fields: SourceImage, SourceProcessId, TargetImage, GrantedAccess, CallTrace`<br>`- Example: SourceImage="C:\temp\unknown.exe" TargetImage="C:\Windows\System32\lsass.exe" GrantedAccess="0x1010"`<br><br>`- Source: Windows Security Event ID 4656 (Handle to Object Requested)`<br>`- Key Fields: ProcessName, ObjectName, AccessMask, HandleId`<br>`- Example: ProcessName="unknown.exe" ObjectName="\Device\HarddiskVolume2\Windows\System32\lsass.exe" AccessMask="0x1410"` |

**Example ABLE Inputs**

| **Field**   | **Example Input**                                                                                                                                             |
|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Actor**   | `N/A - Behavioral hunt independent of specific threat actor`                                                                                                                                            |
| **Behavior**| `Credential Dumping via LSASS Memory Access (T1003.001) - Any process accessing LSASS memory with read permissions`                                                                                                                 |
| **Location**| `Corporate Windows Servers and Domain Controllers`                                                                                                                                   |
| **Evidence**| `- Source: Sysmon Logs (Event ID 10 - ProcessAccess)`<br>`- Key Fields: SourceImage, TargetImage, GrantedAccess, CallTrace, SourceUser`<br>`- Example: Non-system process accessing lsass.exe with GrantedAccess 0x1010 or 0x1410 (PROCESS_VM_READ + PROCESS_QUERY_INFORMATION)`<br><br>`- Source: Windows Security Event Logs (Event ID 4656)`<br>`- Key Fields: ProcessName, ObjectName, AccessMask, SubjectUserName`<br>`- Example: Suspicious process requesting handle to lsass.exe with read permissions` |

## Related Tickets (detection coverage, previous incidents, etc.)

| **Role**                        | **Ticket and Other Details** |
|----------------------------------|------------------------------|
| **SOC/IR**                      | Previous incidents: INC-2024-089 (Mimikatz detection), INC-2024-103 (ProcDump usage) |
| **Threat Intel (TI)**            | APT29 known to use LSASS dumping, APT28 uses custom credential stealers |
| **Detection Engineering (DE)**   | Existing SIEM rule: "Suspicious LSASS Access" (needs tuning for false positives) |
| **Red Team / Pen Testing**       | Red Team Exercise 2024-Q2 successfully dumped credentials using custom tool |
| **Other**                        | Vulnerability Management: Credential Guard not enabled on 30% of endpoints |

## **Threat Intel & Research**
- **MITRE ATT&CK Techniques:**
  - `TA0006 - Credential Access`
  - `T1003.001 - OS Credential Dumping: LSASS Memory`
  - `T1003 - OS Credential Dumping`
- **Related Reports, Blogs, or Threat Intel Sources:**
  - `https://attack.mitre.org/techniques/T1003/001/`
  - `https://www.microsoft.com/security/blog/lsass-credential-theft`
  - `MITRE ATT&CK: Groups using T1003.001 - APT29, APT28, APT3, APT41, Carbanak, etc.`
- **Historical Prevalence & Relevance:**
  - **Previous detections:** We have existing detections for Mimikatz specifically (hash-based and string-based), but custom tools bypass these
  - **Gap identified:** No behavioral detection for LSASS access - only signature-based detection of known tools
  - **Recent incidents:** 2 incidents in past 90 days involving credential dumping (both used Mimikatz)
  - **Environment relevance:** HIGH - Domain environment with privileged accounts, high-value target for credential theft

---

## EXECUTE: Run the Hunt

### Hunting Queries
*(Document queries for Splunk, Sigma, KQL, or another query language to execute the hunt. Capture any adjustments made during analysis and iterate on findings.)*

#### Initial Query
```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
TargetImage="C:\\Windows\\System32\\lsass.exe"
| stats count by SourceImage, SourceUser, Computer, GrantedAccess
| where SourceImage!="C:\\Windows\\System32\\svchost.exe"
  AND SourceImage!="C:\\Windows\\System32\\taskmgr.exe"
  AND SourceImage!="C:\\Program Files\\Windows Defender\\MsMpEng.exe"
```

- **Notes:**
  - **Results:** Query returned 45 events across 12 endpoints
  - **False positives:** TaskManager (legitimate admin use), some Windows Defender scans
  - **True positives:** 3 suspicious unknown executables accessing LSASS
  - **Gaps:** Need to filter more legitimate system processes, add GrantedAccess refinement

#### Refined Query (if applicable)
```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
TargetImage="C:\\Windows\\System32\\lsass.exe"
(GrantedAccess="0x1010" OR GrantedAccess="0x1410" OR GrantedAccess="0x1438")
| eval is_suspicious=if(match(SourceImage, "(?i)(system32|syswow64|defender|microsoft)"), 0, 1)
| where is_suspicious=1
| stats count earliest(_time) as first_seen latest(_time) as last_seen by SourceImage, SourceUser, Computer, GrantedAccess
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| sort -count
```

- **Rationale for Refinement:**
  - Added `GrantedAccess` filtering for specific memory access patterns (0x1010 = PROCESS_VM_READ, 0x1410 adds PROCESS_QUERY_INFORMATION)
  - Created `is_suspicious` field to automatically filter known-good system paths
  - Added temporal analysis (first_seen/last_seen) to identify persistence vs one-time events
  - Sorted by count to identify potential automated/persistent access

#### Advanced Behavioral Analysis Query
```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
TargetImage="C:\\Windows\\System32\\lsass.exe"
(GrantedAccess="0x1010" OR GrantedAccess="0x1410" OR GrantedAccess="0x1438")
| eval is_system=if(match(SourceImage, "(?i)(\\\\system32\\\\|\\\\syswow64\\\\|\\\\defender\\\\)"), 1, 0)
| where is_system=0
| join type=left SourceImage [
  search index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  | stats earliest(_time) as process_created by Image, ParentImage
  | rename Image as SourceImage
]
| table _time Computer SourceImage ParentImage SourceUser GrantedAccess process_created
| sort -_time
```

- **Rationale:**
  - Correlates LSASS access (Event ID 10) with process creation (Event ID 1) to see parent-child relationships
  - Identifies if LSASS-accessing process was spawned from suspicious parent (e.g., Office, browser, script interpreter)
  - Provides fuller behavioral context beyond just the access event

### Visualization or Analytics
*(Describe any dashboards, anomaly detection methods, or visualizations used. Capture observations and note whether visualizations revealed additional insights.)*

**Dashboard Created: "LSASS Access Behavioral Analysis"**

1. **Time-series chart: LSASS Access Over Time**
   - Shows spike in activity on 2024-11-13 03:00-04:00 UTC (3 unique processes, same source user)
   - Normal baseline: 0-2 events per hour from legitimate admin tools
   - **Observation:** Spike coincides with maintenance window, likely legitimate but worth investigating

2. **Heatmap: LSASS Access by User and Computer**
   - Identified 3 user accounts with unusual LSASS access patterns:
     - `svc-backup` account accessing LSASS on 5 different servers (unusual for service account)
     - `jdoe` (standard user) accessed LSASS from `WS-MARKETING-042` (standard user shouldn't have this access)
   - **Observation:** `jdoe` event is highest priority for investigation

3. **Rare Process Analysis**
   - Used SPL `rare` command to identify infrequently-seen processes accessing LSASS:
     - `backup-agent.exe` - legitimate backup software (whitelisted)
     - `temp_23847.exe` - **SUSPICIOUS** - executed from `C:\Users\jdoe\AppData\Local\Temp`
     - `system-update.exe` - **SUSPICIOUS** - masquerading as Windows update, located in `C:\temp`

### Detection Logic
*(How would this be turned into a detection rule? Thresholds, tuning considerations, etc.)*

- **Initial Detection Criteria:**
  - **Trigger:** Any non-system process accessing lsass.exe with GrantedAccess containing VM_READ (0x1010, 0x1410, 0x1438)
  - **Exclusions:** Legitimate system paths (system32, Windows Defender, SCCM, EDR agents)
  - **Severity:** HIGH if source process is from temp directory or user profile; MEDIUM otherwise

- **Refinements After Review:**
  - **Whitelist additions:** Added legitimate backup software (`Veeam`, `Acronis`) and monitoring tools (`SolarWinds`, `PRTG`)
  - **Contextual enrichment:** Cross-reference with user privileges (Domain Admin, local admin) - standard users triggering this = critical alert
  - **Temporal analysis:** Multiple LSASS accesses within 60 seconds from same process = potential automated credential dumping

**Proposed Detection Rule (Splunk)**:
```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
TargetImage="C:\\Windows\\System32\\lsass.exe"
(GrantedAccess="0x1010" OR GrantedAccess="0x1410" OR GrantedAccess="0x1438")
NOT [| inputlookup lsass_access_whitelist.csv]
| lookup user_privileges SourceUser OUTPUT privilege_level
| eval severity=case(
    match(SourceImage, "(?i)(\\\\temp\\\\|\\\\appdata\\\\local\\\\temp)"), "CRITICAL",
    privilege_level="standard_user", "HIGH",
    1=1, "MEDIUM"
)
| where severity IN ("CRITICAL", "HIGH")
| stats count values(SourceImage) as processes by Computer, SourceUser, severity
| where count >= 1
```

### Capturing Your Analysis & Iteration
- **Summarize insights gained from each query modification and visualization.**
  - Initial query was too noisy (45 events, many false positives from legitimate tools)
  - Refining with GrantedAccess filtering and path-based exclusions reduced noise by 80%
  - Correlation with process creation (Event ID 1) revealed parent-child relationships critical for understanding attack chain
  - Visualizations (especially heatmap and rare analysis) identified 2 high-priority IOCs that pure query wouldn't have surfaced

- **Reiterate key findings:**
  - **Found 2 confirmed suspicious LSASS access events:**
    1. `temp_23847.exe` executed by user `jdoe` on `WS-MARKETING-042`
    2. `system-update.exe` on `SRV-FILE-03` by unknown origin
  - **Identified detection gap:** Existing signature-based rules only catch known tools (Mimikatz, ProcDump) - behavioral detection needed
  - **False positive sources:** Legitimate admin tools (TaskManager during troubleshooting), backup software, monitoring agents

- **If this hunt were repeated:**
  - Start with refined query (skip initial broad query)
  - Establish whitelist of legitimate LSASS-accessing processes FIRST to reduce noise
  - Add enrichment for user privilege level upfront (saves time triaging)
  - Consider additional correlation: network connections immediately after LSASS access (potential credential exfiltration)

- **Follow-up hunts generated:**
  - Hunt for process injection targeting lsass.exe (Event ID 8, CreateRemoteThread)
  - Hunt for credential dumping via registry (SAM/SECURITY hive access)
  - Hunt for Kerberoasting (Event ID 4769 with RC4 encryption)

---

## ACT: Findings & Response

### Hunt Review Template

### **Hypothesis / Topic**
**Hypothesis:** Adversaries are accessing LSASS memory to extract credentials, regardless of the tool used.

**Result:** ✅ **HYPOTHESIS CONFIRMED**

### **Executive Summary**
**Key Points:**
1. Hunt successfully identified **2 high-confidence LSASS memory access events** bypassing existing signature-based detections
2. Both events originated from suspicious executables in temporary directories, indicating potential custom credential dumping tools
3. Behavioral hunting approach (focusing on LSASS access behavior rather than known tool signatures) proved effective at catching unknown/custom tools
4. **Detection gap closed:** Created new behavioral detection rule reducing reliance on IOC-based signatures
5. **Immediate action:** Isolated affected endpoints, initiated incident response for credential theft

### **Findings**
*(Summarize key results, including any unusual activity.)*
| **Finding** | **Ticket Number and Link** | **Description** |
|------------|----------------------------|-----------------|
| Suspicious LSASS access by unknown executable | INC-2024-142 | `temp_23847.exe` executed by user `jdoe` accessed LSASS memory on `WS-MARKETING-042`. Investigation revealed post-compromise credential theft attempt. User account `jdoe` compromised via phishing. |
| LSASS access from masquerading process | INC-2024-143 | `system-update.exe` located in `C:\temp` (not legitimate Windows path) accessed LSASS on `SRV-FILE-03`. Binary analysis revealed custom credential stealer, unknown to existing AV/EDR. |
| Detection gap - behavioral vs signature | DE-2024-089 | Existing detections rely on known tool signatures (Mimikatz strings, ProcDump hash). Custom tools bypass these. New behavioral detection rule created to catch LSASS access behavior regardless of tool. |
| Credential Guard not deployed | VM-2024-057 | 30% of endpoints lack Credential Guard, leaving LSASS memory vulnerable. Vulnerability Management tasked with deployment plan. |

## K - Knowledge: Lessons Learned & Documentation

### **Adjustments to Future Hunts**
- **What worked well?**
  - Behavioral focus (hunting for LSASS access behavior, not specific tools) successfully identified unknown/custom credential dumpers
  - ABLE methodology helped scope the hunt precisely - focusing on behavior across all threat actors was the right approach
  - Correlation with process creation events (EventID 1) provided critical context for parent-child relationships
  - Visualization (heatmap, rare analysis) surfaced anomalies not obvious from query results alone

- **What could be improved?**
  - Whitelist development took significant time - future hunts should leverage existing legitimate process baselines
  - Should have included network activity correlation from the start (to detect credential exfiltration after dump)
  - User privilege enrichment should be automated in the hunt query (manually correlating slowed analysis)

- **Should this hunt be automated as a detection?**
  - ✅ **YES** - Detection rule created and deployed to production SIEM
  - Rule name: "Behavioral Detection - Suspicious LSASS Memory Access"
  - Severity: HIGH/CRITICAL based on process path and user privilege
  - Expected alert volume: 2-5 alerts per week (based on hunt baseline)

- **Are there any follow-up hunts that should be conducted?**
  - Hunt for credential dumping via registry (SAM/SECURITY hive access)
  - Hunt for PtH (Pass-the-Hash) activity using dumped credentials
  - Hunt for Kerberoasting (complementary credential theft technique)
  - Hunt for process injection into lsass.exe (alternative credential access method)

- **What feedback should be shared with other teams (SOC, IR, Threat Intel, Detection Engineering, etc.)?**
  - **SOC:** New detection rule deployed - expect HIGH severity alerts for LSASS access, prioritize investigation
  - **IR:** 2 active incidents created from hunt findings - compromised user account and custom malware on file server
  - **Threat Intel:** Custom credential stealer identified (`system-update.exe`) - request external threat intel lookup
  - **Detection Engineering:** Behavioral detection rule created, recommend expanding approach to other credential theft techniques
  - **Vulnerability Management:** Credential Guard deployment critical - accelerate rollout to remaining 30% of endpoints
  - **Red Team:** Test new behavioral detection rule in next exercise to validate effectiveness

### **Sharing Knowledge & Documentation**

- **Knowledge Base (KB) Articles**
  - [x] Write an internal KB article that captures:
    - [x] Hunt objective: Detect LSASS memory access behavior (T1003.001) independent of specific tools
    - [x] Key findings: 2 suspicious LSASS access events, detection gap identified
    - [x] Detection logic: Behavioral rule focusing on GrantedAccess patterns and process paths
    - [x] Lessons learned: Behavioral hunting > signature-based detection for credential theft
  - [x] KB Article: KB-2024-089 "Hunting for Credential Dumping: LSASS Memory Access Patterns"
  - [x] Documented behavioral hunting approach for future hunts targeting other credential theft techniques

- **Threat Hunt Readouts**
  - [x] Scheduled readout with SOC, IR, and Threat Intel teams (2024-11-16 14:00 UTC)
  - [x] Presented key findings: 2 incidents, new detection rule, behavioral hunting methodology
  - [x] Shared refined query and whitelist with SOC for future triage

- **Reports & External Sharing**
  - [x] Internal hunt report published: "PEAK Hunt H-20241115-001: Behavioral LSASS Memory Access Detection"
  - [ ] External sharing: Consider submitting anonymized findings to HEARTH community repository
  - [ ] Industry sharing: Malware sample (`system-update.exe`) submitted to VirusTotal and MISP for community benefit

### **References**
- MITRE ATT&CK T1003.001: https://attack.mitre.org/techniques/T1003/001/
- Microsoft Security Blog - LSASS Credential Theft: https://www.microsoft.com/security/blog/
- PEAK Framework Template: https://dispatch.thorcollective.com/p/the-peak-threat-hunting-template
- Pyramid of Pain: https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
- Sysmon Event ID 10 Documentation: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
