# Threat Hunting MCP Server

A next-generation Model Context Protocol (MCP) server that **hunts for behaviors, not indicators**. Built on the philosophy that effective threat hunting focuses on adversary **Tactics, Techniques, and Procedures (TTPs)** at the top of the Pyramid of Pain—the behaviors that are hardest for attackers to change.

## Philosophy: Hunt Behaviors, Not Indicators

This MCP server is designed around a core principle from the **[Pyramid of Pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)**:

```
                            ▲
                           ╱ ╲
                          ╱   ╲ 🎯 TOUGH
                         ╱ TTPs╲ ← WE FOCUS HERE
                        ╱———————╲
                       ╱         ╲
                      ╱ 🛠️  Tools ╲
                     ╱—————————————╲
                    ╱               ╲
                   ╱ 📊 Host/Network ╲
                  ╱———————————————————╲
                 ╱                     ╲
                ╱  🌐 Domain Names      ╲
               ╱—————————————————————————╲
              ╱                           ╲
             ╱     🔢 IP Addresses         ╲
            ╱———————————————————————————————╲
           ╱                                 ╲
          ╱       #️⃣  Hash Values             ╲
         ╱—————————————————————————————————————╲
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

Copy `.env.example` to `.env` and configure required integrations: **Atlassian** (URL, username, API token) • **Splunk** (host, port, auth token) • **Security** (JWT secret, encryption key) • **Redis** (connection details, optional).

See [PRODUCTION.md](PRODUCTION.md) for detailed configuration examples, security hardening, and deployment best practices.

## Usage

### Starting the Server

```bash
python -m src.server
```

### Key MCP Tools

**Core Hunting Tools:**
- `hunt_threats(query, framework)` - Natural language threat hunting interface
- `get_server_health()` - Server diagnostics and feature availability
- `analyze_adversary(adversary_id)` - Threat actor analysis (e.g., G0016 for APT29)

**HEARTH Community Tools:**
- `search_community_hunts(tactic, tags, keyword)` - Search 50+ community hunt hypotheses
- `recommend_hunts(tactics, keywords, environment)` - AI-powered hunt recommendations
- `suggest_hunts_for_incident(description)` - Incident-driven hunt suggestions

**PEAK Framework Tools:**
- `create_behavioral_hunt(technique_id, hypothesis, ...)` - Create PEAK hunt reports
- `suggest_behavioral_hunt_from_ioc(ioc, ioc_type)` - Pivot IOCs to behavioral hunts
- `list_peak_hunts()` - List created hunt reports

**20+ additional tools available** - see full API documentation for complete tool reference with examples.

### Example: Search Community Hunts

```python
# Search for credential access hunts
hunts = await search_community_hunts(
    tactic="Credential Access",
    tags=["lateral_movement"],
    limit=5
)
```

### Example: Create Behavioral Hunt

```python
# Pivot from IOC to behavioral detection
behavioral_hunt = await suggest_behavioral_hunt_from_ioc(
    ioc="192.168.1.100",
    ioc_type="ip"
)
# Returns TTP-focused hunt suggestions instead of IOC-based detection
```

## Hunting Methodologies

### TaHiTI Framework ⭐ NEW

Developed by the Dutch Payments Association, TaHiTI (Targeted Hunting integrating Threat Intelligence) provides a standardized methodology combining threat intelligence with hunting practices. The framework features three phases: **Initialize** (trigger and abstract), **Hunt** (hypothesis and investigation), and **Finalize** (validation and handover). Built on intelligence-driven focus with continuous enrichment, risk-based prioritization, and collaborative information sharing.

### PEAK Framework

Simple, practical framework with three phases: **Prepare** (research and hypotheses), **Execute** (analyze and investigate), **Act with Knowledge** (document and detect). Supports three hunt types: Hypothesis-Driven, Baseline, and Model-Assisted (M-ATH).

### SQRRL Framework

Features a Hunting Maturity Model (HMM0-HMM4), Hunt Loop (Hypothesis → Investigate → Patterns → Analytics), and Hunt Matrix mapping activities to maturity levels.

**See [FRAMEWORKS.md](FRAMEWORKS.md) for detailed framework documentation, examples, and implementation guidance.**

## HEARTH Community Integration ⭐ NEW

Integrates with **[HEARTH](https://github.com/THORCollective/HEARTH)** (Hunting Exchange and Research Threat Hub), an open-source repository of 50+ professionally-curated threat hunting hypotheses. HEARTH uses PEAK framework categories: 🔥 **Flames** (hypothesis-driven), 🪵 **Embers** (baseline), 🔮 **Alchemy** (model-assisted).

**Key Features:** Search by tactic/technique/tags • AI-powered hunt recommendations • Tactic coverage analysis • Incident-driven hunt suggestions • Real-time community updates

**Quick Example:**
```python
hunts = await search_community_hunts(tactic="Credential Access", tags=["brute_force"])
recommendations = await recommend_hunts(environment="Windows AD")
```

**Resources:** [Live Database](https://thorcollective.github.io/HEARTH/) • [GitHub Repo](https://github.com/THORCollective/HEARTH) • [Submit Hunts](https://github.com/THORCollective/HEARTH/issues/new/choose)

## Security

Enterprise-grade security features including JWT authentication, AES encryption, comprehensive audit logging, and rate limiting. See **[SECURITY.md](SECURITY.md)** for complete security documentation, hardening guidelines, and responsible disclosure policy.

**Key Features:** JWT auth • AES encryption • Audit logging • Rate limiting • Input validation • SIEM integration

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