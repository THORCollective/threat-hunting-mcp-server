# Behavioral Hunting Quick Reference Card

**Core Principle:** Hunt for adversary behaviors (TTPs) that are hard to change, not indicators that rotate hourly.

---

## Pyramid of Pain - Quick Reference

| Level | Change Time | Hunt Value | Action |
|-------|-------------|------------|--------|
| **Hash Values** | Seconds | ❌ Very Low | **AVOID** - Pivot to behavior |
| **IP Addresses** | Minutes | ❌ Low | **AVOID** - Pivot to behavior |
| **Domain Names** | Hours | ❌ Low-Medium | **AVOID** - Pivot to behavior |
| **Network Artifacts** | Days | ⚠️ Medium | Use but prioritize higher |
| **Host Artifacts** | Days | ⚠️ Medium | Use but prioritize higher |
| **Tools** | Weeks | ✅ High | **GOOD** - Hunt capabilities |
| **TTPs (Behaviors)** | Months-Years | ✅✅✅ Highest | **PRIMARY FOCUS** |

---

## The Behavioral Hunting Mindset

### Ask These Questions:

1. **What MUST the adversary do?**
   - To steal credentials → Must access LSASS/SAM/credential stores
   - To move laterally → Must authenticate + execute remotely
   - To persist → Must modify autoruns/services/tasks
   - To exfiltrate → Must establish outbound connections

2. **What behaviors are REQUIRED for this technique?**
   - Not specific tools or hashes
   - Focus on API calls, system resources, process relationships

3. **Will this detection survive tool/infrastructure rotation?**
   - If tool changes → Does detection still work? ✅
   - If C2 IP changes → Does detection still work? ✅
   - If payload recompiled → Does detection still work? ✅

---

## Common Behavioral Patterns by Tactic

### Credential Access (TA0006)

| Behavior | MITRE ID | Detection Focus |
|----------|----------|-----------------|
| LSASS memory access | T1003.001 | Any process opening handle to lsass.exe |
| SAM database access | T1003.002 | Registry access to SAM hive |
| DCSync | T1003.006 | Replication requests from non-DC systems |
| Kerberoasting | T1558.003 | TGS requests for SPNs with RC4 encryption |

**Key Insight:** Hunt for memory/registry access patterns, not specific dumping tools

---

### Lateral Movement (TA0008)

| Behavior | MITRE ID | Detection Focus |
|----------|----------|-----------------|
| RDP | T1021.001 | Remote auth (Type 10) + process creation |
| SMB/Admin Shares | T1021.002 | Service creation via SMB + execution |
| WMI | T1021.006 | WMI process creation on remote systems |
| PowerShell Remoting | T1021.006 | WSMan connections + remote execution |

**Key Insight:** Hunt for auth + execution patterns, not specific tools like PsExec

---

### Execution (TA0002)

| Behavior | MITRE ID | Detection Focus |
|----------|----------|-----------------|
| PowerShell | T1059.001 | Encoded commands, download cradles, AMSI bypass |
| Command Shell | T1059.003 | Suspicious parent-child relationships |
| WMI | T1047 | Wmiprvse.exe spawning unusual processes |
| Scheduled Tasks | T1053.005 | Task creation with unusual actions |

**Key Insight:** Hunt for execution patterns and parent-child anomalies

---

### Defense Evasion (TA0005)

| Behavior | MITRE ID | Detection Focus |
|----------|----------|-----------------|
| Process Injection | T1055 | CreateRemoteThread, QueueUserAPC APIs |
| Obfuscation | T1027 | High entropy files, encoding patterns |
| Disable AV | T1562.001 | Changes to security software settings |
| DLL Hijacking | T1574.001 | DLL loads from unusual paths |

**Key Insight:** Hunt for API usage patterns and system modifications

---

### Persistence (TA0003)

| Behavior | MITRE ID | Detection Focus |
|----------|----------|-----------------|
| Registry Run Keys | T1547.001 | Modifications to autorun registry locations |
| Scheduled Tasks | T1053.005 | New tasks with persistence actions |
| Services | T1543.003 | Service creation/modification |
| Startup Items | T1547.001 | Files added to startup folders |

**Key Insight:** Hunt for modifications to well-known persistence locations

---

### Command and Control (TA0011)

| Behavior | MITRE ID | Detection Focus |
|----------|----------|-----------------|
| Web Protocols | T1071.001 | Beaconing patterns (regular intervals/sizes) |
| DNS | T1071.004 | Tunneling patterns (long subdomains, high volume) |
| Non-Standard Ports | T1571 | Known apps on unusual ports |
| Protocol Tunneling | T1572 | Protocol mismatches |

**Key Insight:** Hunt for communication patterns, not specific C2 IPs/domains

---

## From IOC to Behavior: Quick Pivots

### Given a Malware Hash → Hunt for:
- ✅ Execution behavior (T1059.*) - Process chains, parent-child anomalies
- ✅ Persistence mechanisms (T1547.*) - Registry/startup modifications
- ✅ Defense evasion (T1027, T1055) - Injection, obfuscation patterns

### Given a C2 IP/Domain → Hunt for:
- ✅ Beaconing behavior (T1071.*) - Regular intervals, consistent sizes
- ✅ DNS tunneling (T1071.004) - Unusual subdomain patterns
- ✅ Protocol anomalies - Unexpected protocols/ports

### Given a Tool Name (e.g., "Mimikatz") → Hunt for:
- ✅ LSASS access behavior (T1003.001) - Any process accessing LSASS
- ✅ Credential dumping (T1003.*) - SAM, LSA Secrets access
- ✅ Tool capabilities - What the tool DOES, not what it IS

---

## Splunk Quick Query Templates

### Credential Dumping (Any Tool)
```splunk
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where GrantedAccess IN ("0x1010", "0x1410", "0x1438")
| stats count by SourceImage, Computer_Name, User
```

### Process Injection (Any Tool)
```splunk
index=sysmon EventCode=8
| where TargetImage IN ("*explorer.exe", "*svchost.exe", "*winlogon.exe")
| stats count by SourceImage, TargetImage, Computer_Name
```

### Lateral Movement (Any Method)
```splunk
index=windows EventCode=4624 Logon_Type IN (3,10)
| join Source_Network_Address, Account_Name
    [search index=sysmon EventCode=1]
| stats count by Account_Name, Computer_Name
```

### PowerShell Download Cradles (Any Payload)
```splunk
index=powershell OR index=sysmon EventCode=1 Image="*powershell.exe"
| regex CommandLine="(?i)(downloadstring|webclient|invoke-webrequest)"
| stats count by Computer_Name, User, CommandLine
```

### C2 Beaconing (Any Infrastructure)
```splunk
index=network
| bucket _time span=1m
| stats count sum(bytes) as total_bytes by src_ip, dest_ip, _time
| streamstats window=10 stdev(total_bytes) as byte_std by src_ip
| where byte_std < 100
```

---

## Red Flags: Signs of IOC-Focused Hunting (Avoid!)

❌ **Detection depends on specific hash values**
- "Alert if file hash = abc123..."
- **Problem:** Adversary recompiles → new hash → detection fails

❌ **Detection depends on specific IP addresses**
- "Block connections to 192.168.1.100"
- **Problem:** Adversary rotates IPs → detection fails

❌ **Detection depends on specific file paths**
- "Alert if C:\\Windows\\Temp\\evil.exe exists"
- **Problem:** Adversary changes path → detection fails

❌ **Detection depends on specific tool signatures**
- "Alert if Mimikatz strings found"
- **Problem:** Custom tools don't match → detection fails

---

## Green Flags: Signs of Behavioral Hunting (Good!)

✅ **Detection focuses on required actions**
- "Alert on any LSASS memory access"
- **Benefit:** Works across all credential dumping tools

✅ **Detection focuses on API usage patterns**
- "Alert on CreateRemoteThread into system processes"
- **Benefit:** Works across all injection frameworks

✅ **Detection focuses on process relationships**
- "Alert on cmd.exe spawned by Office applications"
- **Benefit:** Works across all macro-based malware

✅ **Detection focuses on communication patterns**
- "Alert on regular beaconing intervals"
- **Benefit:** Works across all C2 frameworks

---

## Testing Behavioral Detections

### Good Test: Multiple Tools, Same Behavior

**Example: Test credential dumping detection**
1. Run Mimikatz → Detection triggers ✅
2. Run ProcDump on LSASS → Detection triggers ✅
3. Run custom dumper → Detection triggers ✅
4. Run Task Manager on LSASS → Review if expected ⚠️

**Result:** Detection works across tools, with expected false positives handled

### Bad Test: Single Tool Only

**Example: Test for "Mimikatz"**
1. Run Mimikatz → Detection triggers ✅
2. Run custom dumper → Detection FAILS ❌

**Result:** Detection is tool-specific, not behavioral

---

## Measuring Hunt Program Maturity

### Level 1 - IOC Dependent (Avoid)
- Hunts based on hashes, IPs, domains from threat feeds
- Constant IOC updates required
- Adversaries bypass by rotating infrastructure

### Level 2 - Artifact Focused (Better)
- Hunts for registry keys, file paths, network artifacts
- Better than IOCs but still can be changed
- Some behavioral elements

### Level 3 - Tool Capabilities (Good)
- Hunts for what tools CAN DO, not signatures
- Focuses on tool behaviors and capabilities
- More durable detections

### Level 4 - Behavioral Focused (Best) ⭐
- Hunts for required adversary actions
- Independent of specific tools/infrastructure
- Durable detections that force operational changes
- Maps clearly to MITRE ATT&CK TTPs

---

## One-Page Summary

### The Core Question:
**"If the adversary changes their tool/infrastructure, does my detection still work?"**

- **NO** → You're hunting IOCs (bottom of pyramid) ❌
- **YES** → You're hunting behaviors (top of pyramid) ✅

### The Core Action:
**Always ask: "What behavior is this IOC exhibiting?"**

Then hunt for THAT behavior across all tools/variants.

### The Core Benefit:
**Behavioral hunting creates durable detections that:**
- Survive tool rotation
- Survive infrastructure rotation
- Survive payload modification
- Force adversaries to change operations, not just swap tools

### The Core Philosophy:
**"Hunt for HOW adversaries operate, not WHAT specific tools they use"**

---

## Quick Decision Tree

```
Found an IOC (hash/IP/domain)?
    ↓
What behavior does it represent?
    ↓
What actions are REQUIRED for this behavior?
    ↓
Can I detect those actions regardless of tool?
    ↓
YES → Build behavioral detection ✅
NO → Find the required action and try again
```

---

## Further Reading

- **[Full Behavioral Hunting Guide](BEHAVIORAL_HUNTING_GUIDE.md)** - Detailed examples and patterns
- **[Main README](README.md)** - MCP server features and setup
- **[MITRE ATT&CK](https://attack.mitre.org)** - Complete technique database
- **[Pyramid of Pain](http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)** - Original concept by David Bianco

---

**Remember: Focus on the TOP of the Pyramid of Pain. Make it TOUGH for adversaries!**
