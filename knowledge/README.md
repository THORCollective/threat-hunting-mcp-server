# Threat Hunting Knowledge Base

This directory contains reference materials, ebooks, and documentation for the Threat Hunting MCP Server.

## Ebooks

### 1. The PEAK Threat Hunting Framework (Splunk)

**Location**: `ebooks/splunk-peak-threat-hunting-framework.pdf`

**Source**: Splunk SURGe Security Research Team

**Authors**: David Bianco, Ryan Fetterman, Sydney Marrone

**Description**: Comprehensive guide to the PEAK (Prepare, Execute, Act with Knowledge) threat hunting framework. This is the official Splunk publication that provides the complete methodology for behavioral threat hunting.

**Key Topics**:
- **Three Hunt Types**: Hypothesis-driven, Baseline, Model-Assisted (M-ATH)
- **PEAK Phases**: Prepare → Execute → Act (with Knowledge integration)
- **ABLE Methodology**: Actor, Behavior, Location, Evidence (scoping framework)
- **Hunt Deliverables**: Documentation, detections, gap analysis, stakeholder reports
- **Detection Hierarchy**: Signatures/Rules → Analytics in Code → Dashboards → Reports
- **Key Metrics**: Detections created, incidents opened, gaps closed, vulnerabilities fixed, techniques hunted
- **Hunting Maturity Model (HMM)**: HMM0 (Initial) → HMM4 (Leading)

**Table of Contents**:
1. What is threat hunting? (pg 4)
2. Why hunt? (pg 4)
3. Threat hunting frameworks (pg 5)
4. PEAK hunt types and structure (pg 6)
5. Hypothesis-driven threat hunting (pg 7)
6. Baseline threat hunting (pg 10)
7. Model-assisted threat hunting (M-ATH) (pg 15)
8. Choosing the best path (pg 19)
9. Creating hunting hypotheses (pg 20)
10. Are you ABLE to hunt your hypothesis? (pg 21)
11. Threat hunting deliverables (pg 22)
12. Turning hunts into automated detection (pg 24)
13. The hierarchy of detection outputs (pg 25)
14. Key threat hunting metrics (pg 27)
15. Adopting PEAK in your hunting program (pg 30)

**Integration with MCP Server**:
- The PEAK template (`templates/PEAK-Template.md`) is directly from the THOR Collective HEARTH repository
- PEAK tools are available via MCP: `create_behavioral_hunt`, `create_custom_peak_hunt`, `get_peak_template`
- Hunt generator implements PEAK framework: `src/peak/hunt_generator.py`
- Example hunts follow PEAK structure: `examples/PEAK-Hunt-Example-LSASS-Memory.md`

**Behavioral Hunting Focus**:
This ebook emphasizes:
- Hunting at the **top of the Pyramid of Pain** (TTPs, not IOCs)
- Behavioral patterns over atomic indicators
- Durable detections that survive adversary tool changes
- Actor field is **optional** in ABLE - behavior comes first

### 2. The Threat Hunter's Cookbook (Splunk)

**Location**: `ebooks/threat-hunters-cookbook.pdf`

**Summary**: `ebooks/COOKBOOK_SUMMARY.md`

**Source**: Splunk SURGe Security Research Team

**Authors**: Dr. Ryan Fetterman, Sydney Marrone

**Foreword**: Ryan Kovar

**Description**: A practical, recipe-based guide for conducting threat hunting using Splunk's Search Processing Language (SPL). This cookbook bridges the gap between the theoretical PEAK Threat Hunting Framework and practical implementation, providing specific SPL queries and techniques for 7 core hunting methods.

**Key Topics**:
- **7 Hunting Methods**: Searching/Filtering, Sorting/Stacking, Grouping, Forecasting/Anomaly Detection, Clustering, EDA/Visualization, Combined Methods
- **Decision Flow Chart**: Guidance for selecting the right hunting method based on your goals
- **Practical SPL Recipes**: 40+ concrete examples with syntax and use cases
- **Anomaly Detection Methods**: Standard Deviation, IQR, Z-Score, Modified Z-Score comparisons
- **Model-Assisted Hunting**: MLTK algorithms (DensityFunction, OneClassSVM, ARIMA, StateSpaceForecast)
- **Classification Algorithms**: DecisionTree, GradientBoosting, LogisticRegression, RandomForest
- **Deep Learning Models**: Pre-trained models for DNS analysis, process detection, DGA detection
- **Splunkbase Add-ons**: URL Toolbox, PSTree, and other security-focused tools
- **Advanced Recipes**: C2 beaconing, DNS exfiltration, baseline detection, geographic analysis

**Table of Contents**:
1. Allez Cuisine (Introduction) - pg 3
2. Mise en Place (Getting Started) - pg 4
3. Choosing the Right Recipe (Decision Flow) - pg 4
4. Method 1: Searching and Filtering - pg 5-6, 22-25
5. Method 2: Sorting and Stacking - pg 7-8, 26-27
6. Method 3: Grouping - pg 9-10, 27-28
7. Method 4: Forecasting and Anomaly Detection - pg 11-13, 29-31
8. Method 5: Clustering - pg 14-16, 31-32
9. Method 6: Exploratory Data Analysis and Visualization - pg 17-18, 33-36
10. Method 7: Combined Methods - pg 19-20, 37-43
11. Special Ingredients: Splunkbase Add-Ons - pg 42-43
12. Quick Reference Chart - pg 44
13. More Splunkbase Favorites - pg 45

**Integration with MCP Server**:
- The Cookbook provides **practical SPL implementation** patterns that complement the PEAK Framework
- Both resources created by the same Splunk SURGe team (Ryan Fetterman, Sydney Marrone, David Bianco)
- Cookbook recipes can inform MCP tool development and hunt strategy selection
- Decision flow chart (pg 4) helps map hunt goals to appropriate methods
- Advanced recipes demonstrate multi-method combinations for complex hunts

**Relationship to PEAK Framework**:
- **PEAK** = Strategic framework (Prepare, Execute, Act with Knowledge)
- **Cookbook** = Tactical implementation (7 methods with SPL recipes)
- **Hunt Type Correlations**:
  - Hypothesis-based → Searching/Filtering, Grouping
  - Baseline → EDA, Sorting/Stacking
  - Model-Assisted (M-ATH) → Anomaly Detection, Clustering, Classification

**Core Philosophy**:
Like baking bread, threat hunting involves simple ingredients (questions):
- Are you looking for a deviation?
- Are you working with new data?
- Are you searching for commonalities?
- Are you hunting for a known indicator?

**Notable Examples**:
- C2 Beaconing Detection (pg 37) - Low variance time between connections
- DNS Exfiltration (pg 37-38) - High packet size + high event volume
- New Domain Baseline (pg 25) - First-time domain visit detection
- Egress Communication Baseline (pg 39-40) - First-time internal-to-external connections
- Homoglyph Domain Detection (pg 43) - Levenshtein distance for spoofing
- Process Tree Analysis (pg 43) - PSTree visualization for suspicious execution paths

## How to Use This Knowledge Base

### For Threat Hunters

1. **Starting a New Hunt**:
   - Review **PEAK Framework** ebook (pg 6-18 for hunt type selection)
   - Use **ABLE methodology** (pg 21) to scope your hunt
   - Reference hunt type-specific workflows (Hypothesis pg 7, Baseline pg 10, M-ATH pg 15)
   - Consult **Cookbook decision flow chart** (pg 4) to select the right hunting method

2. **Creating Hypotheses**:
   - See PEAK pg 20 for hypothesis creation process
   - Use ABLE framework to ensure your hypothesis is testable
   - Focus on behaviors (TTPs) not indicators (IOCs)
   - Review **Cookbook recipes** for implementation patterns

3. **Implementing Hunts** (NEW - from Cookbook):
   - Select method based on hunt goals:
     - **Known indicators** → Searching/Filtering (Cookbook pg 22-25)
     - **High/low volume** → Sorting/Stacking (Cookbook pg 26-27)
     - **Linked activity** → Grouping (Cookbook pg 27-28)
     - **Deviations** → Anomaly Detection (Cookbook pg 29-31)
     - **Undefined patterns** → Clustering (Cookbook pg 31-32)
     - **New data** → EDA (Cookbook pg 33-36)
   - Adapt SPL recipes to your environment's field names
   - Combine methods for complex hunts (Cookbook pg 37-43)

4. **Documentation**:
   - Follow PEAK template structure
   - Include all hunt deliverables (PEAK pg 22-23)
   - Use detection hierarchy (PEAK pg 25) to prioritize automation
   - Document SPL queries and thresholds used

5. **Measuring Success**:
   - Track key metrics (PEAK pg 27-28)
   - Assess maturity with HMM (PEAK pg 29)
   - Focus on security posture improvements, not just incident count

### For MCP Server Integration

The knowledge in these ebooks is embedded in the MCP server through:

1. **PEAK Framework Implementation**:
   ```python
   # Available MCP tools
   await create_behavioral_hunt(
       technique_id="T1059.002",
       technique_name="AppleScript",
       tactic="Execution",
       hypothesis="...",
       hunter_name="...",
       location="...",
       data_sources=[...]
   )
   ```

2. **Hunt Templates**:
   - `templates/PEAK-Template.md` - Official template from THOR Collective
   - Implements all PEAK phases (Prepare, Execute, Act, Knowledge)
   - Includes ABLE scoping methodology

3. **Behavioral Hunting Guidance**:
   - `BEHAVIORAL_HUNTING_GUIDE.md` - Derived from PEAK principles
   - `BEHAVIORAL_HUNTING_QUICK_REF.md` - Quick reference for behavioral focus
   - Emphasis on Pyramid of Pain (top = TTPs, bottom = IOCs)

4. **Hunt Generator**:
   - `src/peak/hunt_generator.py` - Programmatic PEAK hunt creation
   - `src/tools/peak_tools.py` - MCP tool interface
   - Automated report generation following PEAK structure

## References

### PEAK Framework
- **Official Splunk Ebook**: `ebooks/splunk-peak-threat-hunting-framework.pdf`
- **THOR Collective HEARTH**: https://github.com/THORCollective/HEARTH
- **PEAK Template Source**: https://github.com/THORCollective/HEARTH/blob/main/Kindling/PEAK-Template.md
- **PEAK Blog Post**: https://dispatch.thorcollective.com/p/the-peak-threat-hunting-template

### Pyramid of Pain
- **Original Blog**: https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
- **Concept**: Detection hierarchy from easy-to-change (hashes, IPs) to hard-to-change (TTPs)

### MITRE ATT&CK
- **Website**: https://attack.mitre.org/
- **Usage**: Map hunt techniques to ATT&CK framework for coverage analysis

### Historical Frameworks
- **Sqrrl Framework (2015)**: First hypothesis-driven hunting framework
- **TaHiTI (2018)**: Targeted Hunting Integrating Threat Intelligence
- **PEAK (2023)**: Modern framework incorporating lessons learned

## Contributing

To add new knowledge resources:

1. Add ebooks/PDFs to `ebooks/` directory
2. Add reference documents to appropriate subdirectories
3. Update this README with:
   - Resource description
   - Key topics covered
   - How it integrates with MCP server
   - Usage guidance

## Version History

- **2024-11-15**: Initial knowledge base setup
  - Added Splunk PEAK Framework ebook
  - Created knowledge directory structure
  - Documented PEAK integration with MCP server
