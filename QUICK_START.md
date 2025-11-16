# Quick Start Guide - Threat Hunting MCP Server

## ✅ Setup Complete!

Your threat hunting MCP server is now connected to Claude Code with full access to HEARTH community hunts.

## 🚀 How to Use

### Restart Claude Code

To activate the MCP server:
1. **Restart Claude Code** (important - MCP servers load on startup)
2. Look for the threat-hunting server in your available tools

### Example Natural Language Queries

Once restarted, you can ask Claude Code:

**HEARTH Community Hunts:**
```
Show me HEARTH community hunts for credential access
```

```
Recommend threat hunts for my Windows Active Directory environment
```

```
What's the tactic coverage in the HEARTH repository?
```

```
Suggest hunts for this incident: suspicious PowerShell execution detected on domain controller
```

```
Get details for hunt H001
```

```
Show me recent community hunts from the last 30 days
```

```
Find hunts related to MITRE technique T1110 (brute force)
```

```
Search for hunts tagged with lateral_movement and powershell
```

```
Analyze which MITRE ATT&CK tactics have the most community hunt coverage
```

## 🔧 What's Connected

### MCP Server Configuration
- **Location**: `~/.claude/.claude/.mcp.json`
- **Server Name**: `threat-hunting`
- **Python**: `./venv/bin/python` (or `python3` if using system Python)
- **Entry Point**: `./run_server.py`

### Available Tools (9 HEARTH Tools)
1. `search_community_hunts` - Search 50+ curated hypotheses
2. `get_hunt_by_id` - Get specific hunt details
3. `recommend_hunts` - AI-powered recommendations
4. `suggest_hunts_for_incident` - Incident-based suggestions
5. `analyze_tactic_coverage` - Gap analysis
6. `get_hearth_statistics` - Repository stats
7. `get_hunts_for_tactic` - Tactic-specific hunts
8. `get_hunts_for_technique` - Technique-specific hunts
9. `get_recent_community_hunts` - Recent additions

### HEARTH Repository
- **Local Path**: Auto-detected (defaults to `../HEARTH` relative to project) or configured via HEARTH_PATH env var
- **Contains**: 50+ community-curated threat hunting hypotheses
- **Types**: Flames (hypothesis), Embers (baseline), Alchemy (ML)

## 📝 Configuration Files

- `.env` - Environment configuration (HEARTH_PATH set)
- `.env.example` - Template for all available options
- `src/config.py` - Configuration loader
- `src/server.py` - MCP server with HEARTH tools registered

## 🐛 Troubleshooting

### Server Not Showing Up
1. Check Claude Code was restarted after config changes
2. Verify MCP config: `cat ~/.claude/.claude/.mcp.json | grep threat-hunting`
3. Check venv exists: `ls -la venv/`

### Dependencies Missing
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Test Configuration
```bash
venv/bin/python -c "from src.config import settings; print(f'HEARTH: {settings.hearth_path}')"
```

Should output: `HEARTH: /path/to/HEARTH` (your actual HEARTH repository path)

## 🎯 Next Steps

1. **Restart Claude Code** to load the MCP server
2. **Try a query**: "Show me HEARTH hunts for credential access"
3. **Explore**: Ask Claude about different tactics, techniques, or your environment

## 📚 Documentation

- Full README: `README.md`
- HEARTH Repository: https://github.com/THORCollective/HEARTH
- Live Database: https://thorcollective.github.io/HEARTH/

---

**Note**: The server is configured for HEARTH-only usage. Splunk and Atlassian integrations are present but dormant with mock credentials. They can be activated by updating `.env` with real credentials.
