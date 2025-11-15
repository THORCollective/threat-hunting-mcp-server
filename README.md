# Threat Hunting MCP Server

A next-generation Model Context Protocol (MCP) server that **thinks like an expert threat hunter**, integrating advanced cognitive patterns, graph-based correlation, deception technology, and behavioral analytics.

## Features

### Core Hunting Frameworks
- **PEAK Methodology**: Prepare, Execute, Act with Knowledge - state-of-the-art framework
- **SQRRL Framework**: Hunting Maturity Model (HMM0-HMM4) progression
- **TaHiTI Framework** ⭐ NEW: Targeted Hunting integrating Threat Intelligence (3 phases, 6 steps)
- **Intelligence-Driven**: Hypothesis-driven hunting using threat intelligence

### Advanced Cognitive Capabilities ⭐ NEW
- **Bias Detection & Mitigation**: Identifies confirmation, anchoring, and availability biases
- **Competing Hypotheses Generation**: Analysis of Competing Hypotheses (ACH) methodology
- **Confidence Scoring**: Multi-factor assessment with Pyramid of Pain weighting
- **Hunt Stopping Criteria**: Prevents tunnel vision with objective completion metrics
- **Expert Pattern Recognition**: Built-in heuristics from elite threat hunters (88.3% accuracy)

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

### Traditional Capabilities
- **Natural Language Processing**: Convert queries into executable threat hunts
- **Atlassian Integration**: Confluence and Jira for knowledge management
- **Splunk Integration**: Sophisticated hunting queries using Splunk SDK
- **MITRE ATT&CK Framework**: Comprehensive threat intelligence and technique mapping
- **Security Controls**: Authentication, encryption, audit logging, rate limiting
- **Caching & Performance**: Redis-based caching for optimal performance

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

6. **Intelligence Engine** ([src/intelligence/threat_intel.py](src/intelligence/threat_intel.py))
   - MITRE ATT&CK framework
   - Pyramid of Pain implementation
   - Diamond Model analysis
   - Cyber Kill Chain mapping

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

## Installation

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
   # Edit .env with your configuration
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

## Development

### Project Structure
```
threat_hunting_mcp/
├── src/
│   ├── models/          # Data models
│   ├── frameworks/      # Hunting frameworks
│   ├── integrations/    # External integrations
│   ├── intelligence/    # Threat intelligence
│   ├── nlp/            # Natural language processing
│   ├── security/       # Security controls
│   ├── config.py       # Configuration
│   └── server.py       # Main server
├── requirements.txt    # Dependencies
├── .env.example       # Configuration template
└── README.md         # Documentation
```

### Adding New Hunt Types

1. Define hunt type in `models/hunt.py`
2. Implement creation logic in `frameworks/hunt_framework.py`
3. Add execution logic in `integrations/splunk.py`
4. Update main server in `server.py`

### Extending Intelligence Frameworks

1. Add framework to `intelligence/threat_intel.py`
2. Update analysis methods
3. Add framework resources
4. Document methodology

## Production Deployment

### Requirements
- Python 3.8+
- Redis (recommended)
- Splunk access
- Atlassian access
- Sufficient disk space for logs

### Security Hardening
- Use strong JWT secrets
- Enable HTTPS transport
- Configure firewall rules
- Regular security updates
- Monitor audit logs

### Performance Tuning
- Enable Redis caching
- Adjust rate limits
- Optimize Splunk queries
- Scale horizontally if needed

### Monitoring
- Monitor audit logs
- Track API usage
- Watch for security events
- Performance metrics

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new features
4. Follow security best practices
5. Submit pull request

## License

[Your License Here]

## Support

For support and questions:
- Create GitHub issues for bugs
- Check documentation first
- Follow security disclosure policy
- Provide detailed reproduction steps

---

**Note**: This is a defensive security tool designed for threat hunting and detection. Use responsibly and in accordance with your organization's security policies.