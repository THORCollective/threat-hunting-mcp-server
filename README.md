# Threat Hunting MCP Server

A next-generation Model Context Protocol (MCP) server that **hunts for behaviors, not indicators**. Built on the philosophy that effective threat hunting focuses on adversary **Tactics, Techniques, and Procedures (TTPs)** at the top of the Pyramid of Pain—the behaviors that are hardest for attackers to change.

## Philosophy: Hunt Behaviors, Not Indicators

This MCP server is designed around a core principle from the **[Pyramid of Pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)**:

```
        TOUGH (Hunt Here!)
       /                  \
      /   TTPs (Behaviors) \   ← We focus HERE
     /______________________\
    /   Tools (Capabilities) \
   /__________________________\
  /   Host/Network Artifacts  \
 /______________________________\
/     Domain Names (Annoying)    \
/_________________________________\
/      IP Addresses (Easy)         \
/____________________________________\
          Hash Values (Trivial)
```

**Why behavioral hunting?**
- **Hash values** → Adversaries change in seconds
- **IP addresses** → Adversaries change in minutes
- **Domain names** → Adversaries change in hours
- **Network/Host artifacts** → Adversaries change in days
- **Tools** → Adversaries change in weeks
- **TTPs (Behaviors)** → Adversaries change in months/years ✅ **Hunt for these!**

When you hunt for *how* adversaries behave rather than *what* specific indicators they use, you create durable detections that survive indicator rotation and force adversaries to fundamentally change their operations.

## Features

### Behavioral Hunting Focus
- **TTP-First Approach**: All hunts prioritize behavioral patterns over atomic indicators
- **MITRE ATT&CK Integration**: Deep integration with technique-level behavioral analytics
- **Behavior Pattern Library**: Pre-built detection logic for common adversary behaviors
- **Anti-Evasion Design**: Hunt for behaviors that persist across tool/infrastructure changes

### Core Hunting Frameworks
- **PEAK Methodology**: Prepare, Execute, Act with Knowledge - state-of-the-art framework
- **SQRRL Framework**: Hunting Maturity Model (HMM0-HMM4) progression
- **TaHiTI Framework** ⭐ NEW: Targeted Hunting integrating Threat Intelligence (3 phases, 6 steps)
- **Intelligence-Driven**: Hypothesis-driven hunting using behavioral threat intelligence

### Advanced Cognitive Capabilities ⭐ NEW
- **Bias Detection & Mitigation**: Identifies confirmation, anchoring, and availability biases
- **Competing Hypotheses Generation**: Analysis of Competing Hypotheses (ACH) methodology
- **Confidence Scoring**: Multi-factor assessment **prioritizing TTP-based detections**
- **Hunt Stopping Criteria**: Prevents tunnel vision with objective completion metrics
- **Expert Pattern Recognition**: Built-in behavioral heuristics from elite threat hunters (88.3% accuracy)

### Graph-Based Threat Detection ⭐ NEW
- **Attack Path Analysis**: Identifies critical paths from initial compromise to crown jewels
- **Living-off-the-Land Detection**: Behavioral detection of LOLBin abuse
- **Pivot Point Identification**: Betweenness centrality analysis for key attack nodes
- **Provenance Tracking**: Complete data lineage and ancestry chains
- **Multi-Stage Attack Correlation**: Reveals patterns invisible in isolation

### Deception Technology Integration ⭐ NEW
- **Honeytoken Deployment**: Fake AWS keys, passwords, SSH keys, API tokens
- **Strategic Placement**: Browser history, .env files, config files, memory dumps
- **Decoy Systems**: Indistinguishable fake servers, workstations, databases
- **Canary Files**: Executive documents, credentials, source code with embedded beacons
- **High-Confidence Detection**: 95-99% confidence with <1% false positive rate

### Community Knowledge Base ⭐ NEW
- **HEARTH Integration**: Access 50+ community-curated threat hunting hypotheses
- **Hypothesis-Driven Hunts (Flames)**: Real-world attack scenarios from practitioners
- **Baseline Hunts (Embers)**: Environmental baselining and exploratory analysis
- **Model-Assisted Hunts (Alchemy)**: ML and algorithmic detection approaches
- **AI-Powered Recommendations**: Personalized hunt suggestions for your environment
- **Tactic Coverage Analysis**: Identify gaps across MITRE ATT&CK tactics
- **Incident-Based Suggestions**: Get relevant hunts based on incident descriptions

### Traditional Capabilities
- **Natural Language Processing**: Convert behavioral hunt requests into executable queries
- **Atlassian Integration**: Confluence and Jira for knowledge management
- **Splunk Integration**: TTP-focused hunting queries using Splunk SDK
- **MITRE ATT&CK Framework**: Comprehensive technique and sub-technique mapping
- **Security Controls**: Authentication, encryption, audit logging, rate limiting
- **Caching & Performance**: Redis-based caching for optimal performance

## Behavioral Hunting Examples

### What We Hunt For (Top of Pyramid)

**✅ Good: Behavioral Patterns (TTPs)**
- Process injection techniques (T1055.*) - behavior persists across tools
- LSASS memory access patterns - fundamental credential theft behavior
- Lateral movement via remote services - core post-compromise behavior
- Living-off-the-Land binaries (LOLBins) - detection-evasion behavior
- Parent-child process anomalies - execution pattern behaviors
- Kerberoasting patterns - Active Directory attack behaviors

**❌ Avoid: Atomic Indicators (Easy to Change)**
- Specific malware hashes - trivial to modify
- Known-bad IP addresses - adversaries rotate rapidly
- C2 domain names - disposable infrastructure
- Specific file paths - easily changed

### Behavioral Hunt Examples

**Example 1: Credential Access Behavior**
```
Hunt for: Any process accessing LSASS memory (T1003.001)
Why: This behavior is required for credential theft, regardless of the tool
Tools that use it: Mimikatz, ProcDump, custom malware
Detection persists: Even when tools change
```

**Example 2: Lateral Movement Behavior**
```
Hunt for: Remote execution patterns via WMI/DCOM/SMB (T1021.*)
Why: Fundamental behavior for spreading through networks
Tools that use it: PsExec, Impacket, WMIC, custom tools
Detection persists: Even with infrastructure/tool rotation
```

**Example 3: Defense Evasion Behavior**
```
Hunt for: Process injection patterns (T1055.*)
Why: Core evasion technique requiring specific OS API calls
Tools that use it: Cobalt Strike, Metasploit, custom loaders
Detection persists: API call patterns remain consistent
```

## Getting Started with Behavioral Hunting

**New to behavioral hunting?** Start with these resources:

1. **[Quick Reference Card](BEHAVIORAL_HUNTING_QUICK_REF.md)** - One-page behavioral hunting cheat sheet
2. **[Behavioral Hunting Guide](BEHAVIORAL_HUNTING_GUIDE.md)** - Complete guide to hunting behaviors vs indicators
3. **[PEAK Hunt Example](examples/PEAK-Hunt-Example-LSASS-Memory.md)** - Complete example hunt report using PEAK Framework
4. **[HEARTH Community Hunts](#hearth-community-integration)** - 50+ real-world behavioral hunt hypotheses
5. **[PEAK Template](templates/PEAK-Template.md)** - Official PEAK Framework template from THOR Collective

### Quick Behavioral Hunt Examples

Try these natural language queries focused on behaviors:

```bash
# Credential Access Behaviors
"Hunt for any process accessing LSASS memory (T1003.001)"
"Find credential dumping patterns regardless of tool used"

# Lateral Movement Behaviors
"Detect lateral movement via remote execution (T1021.*)"
"Hunt for RDP/WMI/PsExec execution patterns"

# Process Injection Behaviors
"Find process injection into system processes (T1055)"
"Detect CreateRemoteThread patterns across all tools"

# Living-off-the-Land Behaviors
"Hunt for PowerShell download cradles (T1059.001)"
"Detect LOLBin abuse patterns (certutil, bitsadmin, etc.)"

# Command and Control Behaviors
"Find C2 beaconing patterns regardless of infrastructure"
"Detect DNS tunneling behaviors (T1071.004)"
```

**Notice:** These focus on **adversary behaviors** that persist across tool/infrastructure changes, not specific IOCs that change hourly.

---

## Architecture

### Core Components

1. **Hunt Frameworks**
   - **PEAK/SQRRL** ([src/frameworks/hunt_framework.py](src/frameworks/hunt_framework.py))
     - PEAK methodology implementation
     - SQRRL framework components
     - Intelligence-driven hunting approach
   - **TaHiTI** ([src/frameworks/tahiti.py](src/frameworks/tahiti.py)) ⭐ NEW
     - 3-phase methodology (Initialize, Hunt, Finalize)
     - 6-step process with continuous threat intelligence integration
     - Hunt backlog management and prioritization
     - Automated handover to security processes

2. **Cognitive Module** ([src/cognitive/hunter_brain.py](src/cognitive/hunter_brain.py)) ⭐ NEW
   - Expert threat hunter cognitive patterns
   - Bias detection (confirmation, anchoring, availability)
   - Competing hypotheses generation (ACH methodology)
   - Multi-factor confidence scoring
   - Hunt stopping criteria and decision engine
   - Investigation question generation

3. **Graph Correlation Engine** ([src/correlation/graph_engine.py](src/correlation/graph_engine.py)) ⭐ NEW
   - Attack graph construction and analysis
   - Living-off-the-Land (LOLBin) detection
   - Attack path identification (initial compromise → crown jewels)
   - Pivot point detection via betweenness centrality
   - Provenance tracking and lineage analysis
   - Process relationship analysis

4. **Deception Manager** ([src/deception/honeytokens.py](src/deception/honeytokens.py)) ⭐ NEW
   - Honeytoken generation and deployment
   - Decoy system management
   - Canary file deployment
   - High-confidence threat detection
   - Deception trigger monitoring and response

5. **Integrations**
   - **Atlassian** ([src/integrations/atlassian.py](src/integrations/atlassian.py)): Confluence/Jira integration
   - **Splunk** ([src/integrations/splunk.py](src/integrations/splunk.py)): Query execution and ML analysis

6. **Intelligence Engine**
   - **MITRE ATT&CK** ([src/intelligence/threat_intel.py](src/intelligence/threat_intel.py))
     - MITRE ATT&CK framework
     - Pyramid of Pain implementation
     - Diamond Model analysis
     - Cyber Kill Chain mapping
   - **HEARTH Integration** ([src/intelligence/hearth_integration.py](src/intelligence/hearth_integration.py)) ⭐ NEW
     - Community hunt repository access
     - Hunt search and recommendation engine
     - Tactic coverage analysis
     - Incident-based hunt suggestions
     - 50+ curated threat hunting hypotheses
   - **THOR Collective** ([src/intelligence/thor_collective.py](src/intelligence/thor_collective.py))
     - Community threat hunting knowledge
     - THRF (Threat Hunting Relevancy Factors)
     - Thrunting philosophy integration

7. **NLP Processing** ([src/nlp/hunt_nlp.py](src/nlp/hunt_nlp.py))
   - Natural language query processing
   - Intent classification
   - Entity extraction
   - Query generation
   - Integration with cognitive capabilities

8. **Security Manager** ([src/security/security_manager.py](src/security/security_manager.py))
   - JWT authentication
   - Data encryption
   - Audit logging
   - Rate limiting

## Quick Start (HEARTH Integration Only)

The fastest way to get started with community hunt knowledge:

1. **Clone repositories**:
   ```bash
   git clone https://github.com/THORCollective/threat-hunting-mcp-server
   cd threat-hunting-mcp-server

   # Clone HEARTH repository (required for community hunts)
   git clone https://github.com/THORCollective/HEARTH ../HEARTH
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment** (minimal setup):
   ```bash
   cp .env.example .env
   # The .env file is already configured with HEARTH_PATH
   # You can use it as-is for HEARTH features
   ```

4. **Connect to Claude Code**:

   Add to your Claude Code settings (`.claude/config.json` or settings UI):
   ```json
   {
     "mcpServers": {
       "threat-hunting": {
         "command": "python3",
         "args": ["-u", "/path/to/threat_hunting_mcp/run_server.py"]
       }
     }
   }
   ```

5. **Start using it**:

   Open Claude Code and try natural language queries:
   - "Show me HEARTH hunts for credential access"
   - "Recommend threat hunts for my Windows AD environment"
   - "What's the tactic coverage in HEARTH?"

## Production Deployment

For production deployment features including health monitoring, testing, optimization, and structured logging, see **[PRODUCTION.md](PRODUCTION.md)**.

**Production Features:**
- 🏥 Health monitoring with `get_server_health()` MCP tool
- 🛡️ Input validation and security (Pydantic models)
- ⚡ Token optimization (40-50% reduction)
- ✅ Automated testing (38 tests, 100% pass rate)
- 📊 Structured JSON logging to stderr
- 🔄 Graceful degradation for optional features

## Full Installation

For complete functionality including Splunk, Atlassian, and ML features:

1. **Clone the repository**:
   ```bash
   git clone https://github.com/THORCollective/threat-hunting-mcp-server
   cd threat-hunting-mcp-server
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install spaCy model** (if using NLP features):
   ```bash
   python -m spacy download en_core_web_lg
   ```

4. **Configure environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your Splunk/Atlassian credentials
   ```

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

- **Atlassian**: URL, username, and API token
- **Splunk**: Host, port, and authentication token  
- **Security**: JWT secret and encryption key
- **Redis**: Connection details (optional)
- **Logging**: Paths and levels

### Atlassian Setup

1. Create API token in Atlassian account settings
2. Set up Confluence space for threat hunting documentation
3. Create Jira project for hunt tracking
4. Configure custom fields for hunt metadata (optional)

### Splunk Setup

1. Create authentication token in Splunk
2. Ensure user has search permissions
3. Configure appropriate indexes for hunting

## Usage

### Starting the Server

```bash
python -m src.server
```

### MCP Tools

#### `hunt_threats`
Natural language threat hunting interface.

```python
# Example usage
result = await hunt_threats(
    query="Find lateral movement using RDP in the last 24 hours",
    framework="PEAK"
)
```

#### `create_baseline`
Establish baselines for normal behavior.

```python
result = await create_baseline(
    environment="production",
    metrics=["login_count", "process_count"]
)
```

#### `analyze_with_ml`
Model-Assisted Threat Hunting using machine learning.

```python
result = await analyze_with_ml(
    data_source="endpoint_logs",
    algorithm="isolation_forest"
)
```

#### `analyze_adversary`
Comprehensive threat actor analysis.

```python
result = await analyze_adversary(adversary_id="G0016")  # APT29
```

#### HEARTH Community Hunts ⭐ NEW

##### `search_community_hunts`
Search community-curated threat hunting hypotheses.

```python
result = await search_community_hunts(
    tactic="Credential Access",
    tags=["lateral_movement", "powershell"],
    keyword="brute force",
    hunt_type="flame",  # or "ember", "alchemy"
    limit=20
)
```

##### `get_hunt_by_id`
Retrieve specific community hunt.

```python
result = await get_hunt_by_id(hunt_id="H001")
```

##### `recommend_hunts`
Get AI-powered hunt recommendations.

```python
result = await recommend_hunts(
    tactics=["Credential Access", "Lateral Movement"],
    techniques=["T1110", "T1078"],
    keywords=["active directory", "kerberos"],
    environment="Windows AD environment",
    limit=10
)
```

##### `suggest_hunts_for_incident`
Get hunt suggestions based on incident.

```python
result = await suggest_hunts_for_incident(
    incident_description="Suspicious PowerShell activity detected on domain controller"
)
```

##### `analyze_tactic_coverage`
Analyze MITRE ATT&CK tactic coverage.

```python
result = await analyze_tactic_coverage()
```

#### PEAK Framework Tools ⭐ NEW

##### `create_behavioral_hunt`
Create a behavioral PEAK hunt focused on a MITRE ATT&CK technique.

```python
result = await create_behavioral_hunt(
    technique_id="T1003.001",
    technique_name="LSASS Memory",
    tactic="Credential Access",
    hypothesis="Hunt for processes accessing LSASS memory for credential theft",
    hunter_name="Alice Hunter",
    location="Corporate Windows Servers",
    data_sources=[
        {
            "source": "Sysmon Event ID 10 (ProcessAccess)",
            "key_fields": "SourceImage, TargetImage, GrantedAccess, CallTrace",
            "example": 'TargetImage="*lsass.exe" with GrantedAccess=0x1010'
        },
        {
            "source": "Windows Security Event 4656",
            "key_fields": "ProcessName, ObjectName, AccessMask",
            "example": "Process accessing lsass.exe with handle access"
        }
    ],
    actor="APT29",  # Optional
    threat_intel_sources=["MITRE ATT&CK", "CISA Alert AA21-148A"],
    related_tickets={"SOC/IR": "INC-2024-001"}
)
```

##### `create_custom_peak_hunt`
Create a custom PEAK hunt with full control over all fields.

```python
result = await create_custom_peak_hunt(
    hunt_title="Hunt for Kerberoasting Activity",
    hypothesis="Detect Kerberoasting by hunting for RC4 TGS requests",
    hunter_name="Bob Hunter",
    behavior_description="Kerberoasting (T1558.003) - RC4 ticket requests for service accounts",
    location="Active Directory Domain Controllers",
    data_sources=[
        {
            "source": "Windows Event 4769",
            "key_fields": "ServiceName, TicketEncryptionType, IpAddress",
            "example": "TicketEncryptionType=0x17 (RC4) for service accounts"
        }
    ],
    mitre_techniques=["T1558.003 - Kerberoasting"],
    mitre_tactics=["Credential Access"],
    hunt_type="H"  # H = Hypothesis-driven, B = Baseline, M = Model-Assisted
)
```

##### `get_peak_template`
Get the PEAK Framework template for reference.

```python
result = await get_peak_template()
# Returns template content, usage instructions, and reference link
```

##### `list_peak_hunts`
List all created PEAK hunts.

```python
result = await list_peak_hunts()
# Returns list of hunts with IDs, filenames, and creation dates
```

##### `suggest_behavioral_hunt_from_ioc`
**KEY TOOL**: Pivot from IOCs to behavioral hunts (Pyramid of Pain philosophy).

```python
# When you receive an IOC, pivot to behavioral hunting
result = await suggest_behavioral_hunt_from_ioc(
    ioc="192.168.1.100",
    ioc_type="ip"
)
# Returns behavioral hunt suggestions focusing on TTPs instead of the IOC
```

**Example Response**:
```json
{
  "pyramid_warning": "⚠️  IP is at the BOTTOM of the Pyramid of Pain. Adversaries change these rapidly.",
  "behavioral_alternatives": [
    {
      "technique": "T1071.001 - Application Layer Protocol (Web)",
      "hunt_focus": "C2 beaconing behavior patterns",
      "hypothesis": "Hunt for regular interval communication patterns...",
      "pyramid_level": "TTPs (Top)"
    }
  ],
  "recommendation": "Create a behavioral PEAK hunt using one of the suggestions above"
}
```

### MCP Resources

- `hunting_playbooks`: Retrieve playbooks from Confluence
- `threat_intelligence`: Get threat intelligence data
- `mitre_attack_matrix`: Access MITRE ATT&CK framework
- `hunting_methodologies`: Framework documentation

### MCP Prompts

- `hypothesis_builder`: Interactive hypothesis creation
- `hunt_planner`: Comprehensive hunt planning

## Hunting Methodologies

### TaHiTI Framework ⭐ NEW

Developed by the Dutch Payments Association (Betaalvereniging), TaHiTI (Targeted Hunting integrating Threat Intelligence) provides a standardized, repeatable methodology combining threat intelligence with threat hunting practices.

**Three Phases**:
1. **Initialize**: Process input
   - Step 1: Trigger - Receive initial hunt trigger
   - Step 2: Abstract - Create hunt abstract and add to backlog

2. **Hunt**: Execution phase
   - Step 3: Hypothesis - Formulate focused hypothesis using intelligence
   - Step 4: Investigation - Execute targeted hunting with continuous TI enrichment

3. **Finalize**: Process output
   - Step 5: Validation - Validate hypothesis based on evidence
   - Step 6: Handover - Hand over results to relevant processes

**Core Principles**:
- **Intelligence-Driven Focus**: Threat intelligence drives all hunting activities
- **Contextual Enrichment**: Continuous intelligence enrichment throughout investigation
- **Risk-Based Prioritization**: Focus on highest-risk threats aligned with TI
- **Collaborative Foundation**: Information sharing within security communities

**Trigger Sources**:
- Threat intelligence reports
- Security incidents
- Vulnerability disclosures
- Anomaly detection alerts
- Peer intelligence sharing
- Scheduled baseline hunts
- Red team exercises

**Handover Processes**:
- Incident Response (with IOCs and priority)
- Security Monitoring (with detection rules)
- Threat Intelligence (with intelligence gaps identified)
- Vulnerability Management
- Detection Engineering
- Risk Management
- Security Architecture

**Supporting Tool**: MaGMa for Threat Hunting provides process guidance and improvement insights.

### PEAK Framework

**Phases**:
1. **Prepare**: Research, understand data, frame hypotheses
2. **Execute**: Analyze data, follow leads, connect dots
3. **Act with Knowledge**: Document findings, create detections

**Hunt Types**:
- **Hypothesis-Driven**: Test specific hypotheses about adversary behavior
- **Baseline**: Establish normal patterns to identify anomalies
- **Model-Assisted (M-ATH)**: Use ML for anomaly detection

### SQRRL Framework

**Components**:
- **Hunting Maturity Model**: HMM0-HMM4 capability levels
- **Hunt Loop**: Hypothesis → Investigate → Patterns → Analytics
- **Hunt Matrix**: Activities mapped to maturity levels

### Intelligence-Driven Methodology

**Requirements**:
1. **Adversary Understanding**: Know threat actors and TTPs
2. **Telemetry and Data**: Comprehensive visibility
3. **Business Impact Analysis**: Understand crown jewels

## HEARTH Community Integration ⭐ NEW

The MCP server integrates with **[HEARTH](https://github.com/THORCollective/HEARTH)** (Hunting Exchange and Research Threat Hub), a community-driven repository of 50+ curated threat hunting hypotheses.

### What is HEARTH?

HEARTH is an open-source platform where security professionals share, discover, and collaborate on threat hunting ideas. It uses the PEAK framework to categorize hunts:

- **🔥 Flames (H-prefix)**: Hypothesis-driven hunts with clear, testable objectives
- **🪵 Embers (B-prefix)**: Baselining and exploratory analysis to understand environments
- **🔮 Alchemy (M-prefix)**: Model-assisted and algorithmic approaches to detection

### Integration Features

1. **Community Hunt Access**: Query 50+ professionally-curated hunt hypotheses
2. **Search & Filter**: Find hunts by tactic, technique, tags, or keywords
3. **AI Recommendations**: Get personalized hunt suggestions based on your environment
4. **Tactic Coverage**: Identify gaps in your hunting program across MITRE ATT&CK
5. **Incident Response**: Get relevant hunts based on incident descriptions
6. **Real-Time Updates**: Access the latest community contributions

### Example Usage

Search for credential access hunts:
```python
hunts = await search_community_hunts(
    tactic="Credential Access",
    tags=["brute_force", "vpn"],
    limit=10
)
```

Get recommendations for your environment:
```python
recommendations = await recommend_hunts(
    tactics=["Lateral Movement", "Persistence"],
    keywords=["active directory", "domain controller"],
    environment="Windows enterprise"
)
```

Analyze your tactic coverage:
```python
coverage = await analyze_tactic_coverage()
# Returns hunt counts across all MITRE ATT&CK tactics
```

### HEARTH Resources

- **Live Database**: [https://thorcollective.github.io/HEARTH/](https://thorcollective.github.io/HEARTH/)
- **GitHub Repository**: [https://github.com/THORCollective/HEARTH](https://github.com/THORCollective/HEARTH)
- **Submit Hunts**: [https://github.com/THORCollective/HEARTH/issues/new/choose](https://github.com/THORCollective/HEARTH/issues/new/choose)

### Contributing to HEARTH

The MCP server reads from your local HEARTH repository. To contribute new hunts:

1. Clone HEARTH: `git clone https://github.com/THORCollective/HEARTH.git`
2. Submit via [CTI Submission](https://github.com/THORCollective/HEARTH/issues/new?template=cti_submission.yml) (AI-powered)
3. Or submit via [Manual Hunt](https://github.com/THORCollective/HEARTH/issues/new?template=hunt_submission_form.yml)
4. Your contributions become available to the entire community!

## Security

### Authentication
- JWT token-based authentication
- Role-based access control (RBAC)
- Token binding support

### Data Protection
- AES encryption for sensitive data
- Secure credential storage
- Input sanitization and validation

### Audit Logging
- Comprehensive activity logging
- Structured JSON format
- Security event monitoring
- SIEM integration ready

### Rate Limiting
- Redis-based sliding window
- Per-user and per-endpoint limits
- Configurable thresholds

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines, project structure, and how to add new features.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Responsible Use

This is a defensive security tool designed for:
- Threat hunting and detection
- Security monitoring and analysis
- Incident response and investigation
- Security research and education

By using this software, you agree to use it only for lawful and authorized security purposes. Always obtain proper authorization before conducting security activities in any environment.

## Support

For support and questions:
- Create GitHub issues for bugs
- Check documentation first
- Follow security disclosure policy
- Provide detailed reproduction steps

---

**Note**: This is a defensive security tool designed for threat hunting and detection. Use responsibly and in accordance with your organization's security policies.