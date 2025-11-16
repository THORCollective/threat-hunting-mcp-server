*This template provides a structured and consistent way to document threat hunting activities using the PEAK Framework (Prepare, Execute, Act with Knowledge). It guides threat hunters through defining clear hypotheses, scoping the hunt precisely using the ABLE methodology, executing targeted queries, and documenting findings to ensure thorough and actionable results. Replace all placeholders (`[ ]`) with specific details relevant to your hunt scenario.*

Want more info? Check out the post here - https://dispatch.thorcollective.com/p/the-peak-threat-hunting-template

---

# Threat Hunting Report - PEAK Framework

## Hunt ID: `H/B/M-XXXX`
*(H for Hypothesis-driven, B for Baseline, M for Model-Assisted)*

## Hunt Title:
*A concise, descriptive name for this hunt.*

---

## PREPARE: Define the Hunt

| **Hunt Information**            | **Details** |
|----------------------------------|-------------|
| **Hypothesis**                  | [What are you hunting for and why?] |
| **Threat Hunter Name**          | [Name of the threat hunter] |
| **Date**                        | [Date of hunt] |
| **Requestor**                   | [Person or team requesting the hunt] |
| **Timeframe for hunt**          | [Expected duration for the hunt] |

## Scoping with the ABLE Methodology

Clearly define your hunt scope using the ABLE framework. Replace all placeholders (`[ ]`) with relevant details for your scenario.

| **Field**   | **Description**                                                                                                                                                                                                                                                                             | **Your Input**                   |
|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------|
| **Actor**   | *(Optional)* Identify the threat actor involved with the behavior, if applicable. This step is optional because hunts aren't always tied to a specific actor. You may be investigating techniques used across multiple adversaries or looking for suspicious activity regardless of attribution. Focus on the what and how before the who, unless actor context adds meaningful value to the hunt.  | `[Threat Actor or N/A]`          |
| **Behavior**| Describe the actions observed or expected, including tactics, techniques, and procedures (TTPs). Specify methods or tools involved.                                                                                                                                                 | `[Describe observed or expected behavior]` |
| **Location**| Specify where the activity occurred, such as an endpoint, network segment, or cloud environment.                                                                                                                                 | `[Location]`            |
| **Evidence**| Clearly list logs, artifacts, or telemetry supporting your hypothesis. For each source, provide critical fields required to validate the behavior, and include specific examples of observed or known malicious activity to illustrate expected findings. | `- Source: [Log Source]`<br>`- Key Fields: [Critical Fields]`<br>`- Example: [Expected Example of Malicious Activity]`<br><br>`- Source: [Additional Source]`<br>`- Key Fields: [Critical Fields]`<br>`- Example: [Expected Example of Malicious Activity]` |

**Example ABLE Inputs**

| **Field**   | **Example Input**                                                                                                                                             |
|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Actor**   | `APT29 (Cozy Bear)`                                                                                                                                            |
| **Behavior**| `Credential dumping via mimikatz.exe (T1003)`                                                                                                                 |
| **Location**| `Corporate Windows Servers`                                                                                                                                   |
| **Evidence**| `- Source: Sysmon Logs (Event ID 1 - Process Creation)`<br>`- Key Fields: process_name, command_line, parent_process, user, hash`<br>`- Example: Execution of mimikatz.exe with command line arguments such as "privilege::debug sekurlsa::logonpasswords"`<br><br>`- Source: Windows Security Event Logs (Event IDs 4624, 4625)`<br>`- Key Fields: user, source_ip, destination_ip, event_id, timestamp`<br>`- Example: Successful logon followed by immediate high-privilege process launches consistent with credential extraction attempts` |

## Related Tickets (detection coverage, previous incidents, etc.)

| **Role**                        | **Ticket and Other Details** |
|----------------------------------|------------------------------|
| **SOC/IR**                      | [Insert related ticket or incident details] |
| **Threat Intel (TI)**            | [Insert related ticket] |
| **Detection Engineering (DE)**   | [Insert related ticket] |
| **Red Team / Pen Testing**       | [Insert related ticket] |
| **Other**                        | [Insert related ticket] |

## **Threat Intel & Research**
- **MITRE ATT&CK Techniques:**
  - `TAxxxx - Tactic Name`
  - `Txxxx - Technique Name`
- **Related Reports, Blogs, or Threat Intel Sources:**
  - `[Link]`
  - `[Reference]`
- **Historical Prevalence & Relevance:**
  - *(Has this been observed before in your environment? Are there any detections/mitigations for this activity already in place?)*

---

## EXECUTE: Run the Hunt

### Hunting Queries
*(Document queries for Splunk, Sigma, KQL, or another query language to execute the hunt. Capture any adjustments made during analysis and iterate on findings.)*

#### Initial Query
`index=main sourcetype=linux:audit "sudo" OR "pkexec"
| stats count by user, command, parent_process `

- **Notes:**
  - Did this query return expected results?
  - Were there false positives or gaps?
  - How did you refine the query based on findings?

#### Refined Query (if applicable)
`index=main sourcetype=linux:audit "sudo" OR "pkexec"
| stats count by user, command, parent_process, _time
| sort - _time `

- **Rationale for Refinement:**
  - Added `_time` for better event sequencing.
  - Applied `sort` to identify patterns in privilege escalation attempts.

### Visualization or Analytics
*(Describe any dashboards, anomaly detection methods, or visualizations used. Capture observations and note whether visualizations revealed additional insights. **Add screenshots!**)*

- **Examples:**
  - Time-series charts to detect activity spikes
  - Heatmaps of unusual application installs

### Detection Logic
*(How would this be turned into a detection rule? Thresholds, tuning considerations, etc.)*

- **Initial Detection Criteria:**
  - What conditions would trigger an alert?
  - Are there threshold values that indicate malicious activity?

- **Refinements After Review:**
  - Did certain legitimate activities cause false positives?
  - How can you tune the rule to focus on real threats?

### Capturing Your Analysis & Iteration
- **Summarize insights gained from each query modification and visualization.**
- **Reiterate key findings:**
  - Did this query lead to any findings, false positives, or hypotheses for further hunting?
  - If this hunt were repeated, what changes should be made?
  - Does this hunt generate ideas for additional hunts?

- **Document the next steps for refining queries for detections and other outputs.**

---

## ACT: Findings & Response

### Hunt Review Template

### **Hypothesis / Topic**
*(Restate the hypothesis and topic of the investigation.)*

### **Executive Summary**
**Key Points:**
- 3-5 sentences summarizing the investigation.
- Indicate whether the hypothesis was proved or disproved.
- Summarize the main findings (e.g., "We found..., we did not find..., we did not find... but we did find...").

### **Findings**
*(Summarize key results, including any unusual activity.)*
| **Finding** | **Ticket Number and Link** | **Description** |
|------------|----------------------------|-----------------|
| [Describe finding] | [Insert Ticket Number] | [Brief description of the finding, such as suspicious activity, new detection idea, data gap, etc.] |
| [Describe finding] | [Insert Ticket Number] | [Brief description of the finding] |
| [Describe finding] | [Insert Ticket Number] | [Brief description of the finding] |

## K - Knowledge: Lessons Learned & Documentation

### **Adjustments to Future Hunts**
- **What worked well?**
- **What could be improved?**
- **Should this hunt be automated as a detection?**
- **Are there any follow-up hunts that should be conducted?**
- **What feedback should be shared with other teams (SOC, IR, Threat Intel, Detection Engineering, etc.)?**

### **Sharing Knowledge & Documentation**
*(Ensure insights from this hunt are shared with the broader security team to improve future hunts and detections.)*

- **Knowledge Base (KB) Articles**
  - [ ] Write an internal KB article that captures:
    - [ ] The hunt's objective, scope, and key findings
    - [ ] Any detection logic or rule improvements
    - [ ] Lessons learned that are relevant for future hunts or incident response
  - [ ] Document newly uncovered insights or patterns that could benefit SOC, IR, or Detection Engineering teams, especially anything that could inform future detections, playbooks, or tuning decisions.

- **Threat Hunt Readouts**
  - [ ] Schedule a readout with SOC, IR, and Threat Intel teams.
  - [ ] Present key findings and suggested improvements to detections.

- **Reports & External Sharing**
  - [ ] Publish findings in an internal hunt report.
  - [ ] Share relevant insights with stakeholders, vendors, or industry communities if applicable.

### **References**
- [Insert link to related documentation, reports, or sources]
- [Insert link to any external references or articles]
