# PEAK Framework Quick Reference

*Extracted from "The PEAK Threat Hunting Framework" by Splunk SURGe*

## Core Definition

**Threat Hunting**: Any manual or machine-assisted process for finding security incidents that your automated detection systems missed.

**Purpose**: Drive improvements to security posture (not just find incidents)

## PEAK = Prepare + Execute + Act + Knowledge

Three hunt types, same three phases:
- **Prepare**: Select topic, research, plan
- **Execute**: Gather data, analyze, find patterns
- **Act**: Document, create detections, communicate

**Knowledge** flows through all phases (two-way integration)

---

## Three Hunt Types

### 1. Hypothesis-Driven (H)
**When**: You have a specific threat behavior in mind
**Process**: Topic → Research → Hypothesis → Scope → Hunt
**Example**: "Threat actor may be exfiltrating financial data using DNS tunneling"

### 2. Baseline (B)
**When**: Understanding normal behavior in a data source
**Process**: Select data source → Create data dictionary → Find outliers
**Example**: Baseline Windows Security logs, identify anomalous auth patterns

### 3. Model-Assisted (M-ATH)
**When**: Complex patterns requiring ML/algorithms
**Process**: Select algorithms → Develop model → Apply → Analyze
**Example**: Unsupervised clustering to find behavioral anomalies

---

## Choosing the Right Hunt Type

```
START
  ↓
Is this about a new data source?
  YES → Baseline Hunt
  NO → Continue
  ↓
Does it have implicit complexity (hard to code explicitly)?
  YES → M-ATH Hunt
  NO → Hypothesis-Driven Hunt
```

---

## ABLE Methodology (Scoping)

**A**ctor (Optional): Threat actor or group (behavior-first, not actor-first)
**B**ehavior (Required): TTPs you're hunting - at TOP of Pyramid of Pain
**L**ocation: Where to hunt (endpoints, network, cloud, specific systems)
**E**vidence: Data sources + key fields + examples of malicious activity

### Example ABLE Scope
```
Actor: N/A - Hunting behavior across all actors
Behavior: T1059.002 AppleScript execution via Script Editor spawning shell chains
Location: macOS endpoints (focus on Finance, Executive systems)
Evidence:
  - Source: EDR process logs
  - Key Fields: parent_process, process_name, command_line, network_conn
  - Example: Script Editor → bash → curl http://evil.com
```

---

## Hunt Deliverables

1. **Security Incidents**: Escalate immediately to IR team
2. **Hunt Documentation**: Hypothesis, queries, analysis, findings, lessons learned
3. **Detections**: New or improved automated detection
4. **Gaps and Risks**: Data visibility issues, missing controls
5. **Vulnerabilities**: Misconfigurations, unpatched systems
6. **Hunt Ideas**: Out-of-scope leads for future hunts
7. **Stakeholder Reports**: Technical readouts, executive summaries

---

## Detection Hierarchy (Highest to Lowest)

**Level 1: Signatures and Rules** ← *Best (fully automated)*
- Splunk ES, Suricata, SIEM rules
- Automated, easy to manage

**Level 2: Analytics in Code**
- Python, Splunk MLTK, custom algorithms
- Automated but complex, needs maintenance

**Level 3: Dashboards and Visualizations**
- Human reviews distilled information
- Some automation, regular manual review

**Level 4: Reports** ← *Least desirable (manual)*
- Saved searches with minimal processing
- Human extracts meaning from results

**Goal**: Create detections as high in hierarchy as feasible

---

## Key Metrics to Track

1. **Detections created/updated**: New rules, improved existing rules
2. **Incidents opened**: During hunt + from new detections afterward
3. **Gaps identified/closed**: Data visibility, access, tools
4. **Vulnerabilities identified/closed**: Misconfigs, unpatched systems
5. **Techniques hunted**: Map to MITRE ATT&CK, Kill Chain, Pyramid of Pain

**Philosophy**: Measure *effect* of hunting, not just *effort*
❌ "We did 9 hunts" → ✅ "We created 12 new detections for cloud exfiltration"

---

## Hunting Maturity Model (HMM)

**HMM0 - Initial**
- Relies on automated alerting only
- Little/no data collection

**HMM1 - Minimal**
- Threat intel indicator searches
- Moderate data collection

**HMM2 - Procedural** ← *Minimum for most orgs*
- Follows hunt procedures from others
- High data collection

**HMM3 - Innovative**
- Creates new hunt procedures
- High data collection
- May use M-ATH

**HMM4 - Leading** ← *Target state*
- Automates majority of hunts into detections
- High data collection
- Continuous improvement

---

## Hypothesis Creation (3 Steps)

1. **Select Topic**: Type of activity (e.g., "data exfiltration")
2. **Make It Testable**: Falsifiable statement (e.g., "Exfiltrating via DNS tunneling")
3. **Refine as Necessary**: Scope until feasible (e.g., "Financial data via DNS tunneling")

### Good Hypothesis Criteria
✅ Testable (can prove or disprove)
✅ Scoped to available data and time
✅ Focuses on behavior (TTPs), not indicators
✅ Uses ABLE framework for completeness

---

## PEAK Phases Detail

### PREPARE
**Hypothesis-Driven**: Topic → Research → Hypothesis → Scope → Plan
**Baseline**: Select data source → Research → Scope → Plan
**M-ATH**: Topic → Research → Identify datasets → Select algorithms

### EXECUTE
**All Types**: Gather data → Pre-process data
**Hypothesis-Driven**: Analyze → Refine hypothesis → Escalate findings
**Baseline**: Create data dictionary → Review distributions → Investigate outliers → Gap analysis → Identify relationships
**M-ATH**: Develop model → Refine → Apply model → Analyze

### ACT
**All Types**:
- Preserve hunt (archive data, tools, techniques)
- Document findings (whether proved/disproved)
- Create detections (use hierarchy)
- Re-add topics to backlog (new hunt ideas)
- Communicate findings (technical + executive readouts)

**Baseline Only**: Document baseline (data dictionary, known benign outliers)

---

## Behavioral Hunting Principles

### Pyramid of Pain (Hunt at the TOP)
```
        ↑ HARD for adversary to change
      -----
     | TTPs |  ← HUNT HERE (Techniques, Tactics, Procedures)
     -------
    | Tools  |
    ---------
   | Network |
   | & Host  |
   | Artifacts|
   -----------
  | Domain   |
  | Names    |
  ------------
 | IP Address |
 --------------
| Hash Values | ← Easy for adversary to change
--------------
```

### Why Hunt Behaviors (TTPs)?
- **Durable**: Adversaries can't easily change their TTPs
- **Detectable**: Same behavior regardless of tool used
- **Preventable**: Can build controls around behaviors
- **Scalable**: One behavioral detection catches many variants

### Why NOT Hunt IOCs?
- **Ephemeral**: Hashes, IPs, domains change constantly
- **Cat and mouse**: Adversary creates new IOC, you update detection, repeat
- **Not scalable**: Each IOC requires separate detection

### Actor Field is Optional
- Focus on **behavior first**, actor second
- Many behaviors apply across multiple threat actors
- Actor context is helpful but not required
- Don't let lack of attribution stop behavioral hunting

---

## Common Analytic Techniques

**Hypothesis-Driven**:
- Filtering and searching
- Least/most frequency (stacking)
- Clustering
- Visualization
- Temporal analysis

**Baseline**:
- Stack counting (LFO - Least Frequency of Occurrence)
- Z-scores (statistical outliers)
- Descriptive statistics (mean, median, cardinality)
- Machine learning (isolation forests, density functions)

**M-ATH**:
- Classification (supervised: predict malicious/benign)
- Clustering (unsupervised: group similar events)
- Time series analysis (forecast, detect deviations)
- Anomaly detection (autoencoders, single-class SVM)

---

## Data Dictionary Components

**Baseline hunts require documenting**:
- **Field names**: Identifiers in the data
- **Description**: What each field represents
- **Data types**: Numeric (continuous/discrete), Categoric (nominal/ordinal), Text, Date/time, Boolean
- **Field values**: How to interpret values
- **Distributions**: Average, median, top values, cardinality

---

## Turning Hunts into Detections

### Decision Tree
1. Did you figure out how to find the activity?
   NO → Re-hunt or research more
   YES → Continue

2. Would you be confident enough to alert on it?
   YES → Use Level 1 (Rules) or Level 2 (Analytics)
   NO → Use Level 3 (Dashboard) or Level 4 (Report)

3. Choose the **highest level** in the detection hierarchy you can implement

4. Revisit Level 3/4 detections periodically to see if they can move up

---

## Stakeholder Communication

### Technical Readouts (Blue Team)
**Audience**: Threat Hunt, Detection Engineering, Threat Intel, SOC, IR
**Content**: Hypothesis, queries, analysis process, findings, new detections
**Frequency**: After each hunt or monthly/quarterly highlight reel

### Executive Readouts (Leadership)
**Audience**: CISO, Security leadership, System owners
**Content**: Hypotheses, high-level process, incidents found, gaps closed, metrics
**Frequency**: Quarterly or hunt highlight emails

### Hunt Documentation
**Medium**: Wiki pages, ticket systems, document repos, GitHub
**Includes**: Links to data, analysis descriptions, key findings, metrics
**Purpose**: Repeatability, knowledge sharing, training

---

## Best Practices

### Do:
✅ Focus on behavioral hunting (top of Pyramid of Pain)
✅ Create detections from every hunt (move up hierarchy over time)
✅ Document thoroughly (future you will thank current you)
✅ Track metrics that show security posture improvement
✅ Share findings widely across security teams
✅ Refine hypotheses during the hunt (iteration is normal)
✅ Escalate critical findings immediately

### Don't:
❌ Hunt for specific IOCs (hashes, IPs) - hunt behaviors instead
❌ Measure success by incident count alone
❌ Skip documentation ("I'll remember this")
❌ Create detections that require attribution to work
❌ Ignore scope creep (capture new ideas for later)
❌ Re-hunt the same thing repeatedly without automation
❌ Work in isolation (communicate with stakeholders)

---

## Quick Hunt Checklist

### Before Hunt
- [ ] Hunt type selected (H/B/M-ATH)
- [ ] Hypothesis created (if H or M-ATH)
- [ ] ABLE scope defined
- [ ] Data sources identified
- [ ] Timeframe set
- [ ] Tools and techniques planned

### During Hunt
- [ ] Data gathered and pre-processed
- [ ] Analysis techniques applied
- [ ] Findings documented in real-time
- [ ] Critical findings escalated immediately
- [ ] Hypothesis refined as needed

### After Hunt
- [ ] Hunt archived (data, queries, tools)
- [ ] Findings documented (proved/disproved)
- [ ] Detections created (highest hierarchy level feasible)
- [ ] Gaps/risks reported to stakeholders
- [ ] New hunt ideas added to backlog
- [ ] Technical readout scheduled
- [ ] Executive summary prepared (if applicable)
- [ ] Metrics updated

---

## Resources

**Official PEAK Resources**:
- Splunk PEAK Framework Ebook (this reference source)
- THOR Collective HEARTH: https://github.com/THORCollective/HEARTH
- PEAK Template: https://dispatch.thorcollective.com/p/the-peak-threat-hunting-template

**Historical Frameworks**:
- Sqrrl Framework (2015): Hypothesis-driven loop
- TaHiTI (2018): CTI integration, data-driven hunts

**Related Frameworks**:
- MITRE ATT&CK: https://attack.mitre.org/
- Pyramid of Pain: https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
- Lockheed Martin Cyber Kill Chain

**Splunk SURGe Team**:
- Authors: David Bianco, Ryan Fetterman, Sydney Marrone
- Research: https://www.splunk.com/en_us/blog/author/surge.html

---

*This quick reference is derived from "The PEAK Threat Hunting Framework" ebook by Splunk (2023).*
*For complete details, see the full ebook in `knowledge/ebooks/splunk-peak-threat-hunting-framework.pdf`*
