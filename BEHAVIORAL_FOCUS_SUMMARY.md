# Behavioral Hunting Focus - Implementation Summary

This document summarizes the changes made to refocus the Threat Hunting MCP Server on **behavioral hunting** at the top of the Pyramid of Pain.

---

## Core Philosophy Change

### Before
General-purpose threat hunting tool with IOC enrichment capabilities

### After
**Behavioral-first** threat hunting platform that:
- Prioritizes TTPs (behaviors) over IOCs (indicators)
- Automatically suggests behavioral pivots when IOCs are encountered
- Warns users about low-value IOC-based hunting
- Emphasizes durable detections that survive adversary tool/infrastructure rotation

---

## Key Changes by Component

### 1. README.md Updates

**Added:**
- ✅ Pyramid of Pain visualization showing behavioral focus
- ✅ "Philosophy: Hunt Behaviors, Not Indicators" section
- ✅ Clear examples of what TO hunt vs what to AVOID
- ✅ Behavioral hunt examples (credential dumping, lateral movement, etc.)
- ✅ "Getting Started with Behavioral Hunting" quick start
- ✅ "Behavioral Hunting Manifesto" with core principles

**Key Message:**
> "Hunt for HOW adversaries behave, not WHAT specific tools they use"

---

### 2. threat_intel.py Refactoring

#### PyramidOfPain Class

**Enhanced with:**
- `adversary_change_time` - Shows how quickly adversaries rotate each indicator type
- `hunt_value` - Clear guidance on hunting value (Very Low → Highest)
- `recommended` - Boolean flag marking TTPs and tools as recommended hunt targets

**Example:**
```python
'ttps': {
    'pain': 7,
    'difficulty': 'Tough',
    'adversary_change_time': 'Months to Years',
    'hunt_value': 'HIGHEST - Primary focus for threat hunting',
    'recommended': True  # ← This is what we hunt!
}
```

#### prioritize_hunts() Enhancement

**Now includes:**
- Warning messages for low-value IOC hunts
- Hunt value ratings
- Recommendations for behavioral alternatives

**Example Warning:**
```
⚠️  LOW HUNT VALUE: IP indicators change in minutes.
Consider hunting for behaviors instead.
```

#### enrich_ioc() Behavioral Pivot

**Major Addition:** `behavioral_pivot_suggestions`

When users search for an IOC, they now receive:
- ❌ Warning about low hunt value (for hashes, IPs, domains)
- ✅ Behavioral hunting alternatives mapped to MITRE ATT&CK
- ✅ Specific suggestions for pivoting to TTPs

**Example:**
```python
# User searches for IP address
# System responds with:
{
    'warning': '⚠️  IP is at BOTTOM of Pyramid. Adversaries change in minutes.',
    'behavioral_pivot_suggestions': [
        'Hunt for C2 beaconing behaviors (T1071.001)',
        'Hunt for DNS tunneling patterns (T1071.004)',
        '⭐ BEST PRACTICE: Pivot from IOCs to behavioral patterns'
    ]
}
```

---

### 3. hunt_nlp.py Behavioral Focus

#### Class Enhancement

**Added:**
- `behavioral_focus_mode = True` - Flag indicating behavioral priority
- Documentation emphasizing behavioral hunting in all methods

#### _handle_ioc_analysis() Redesign

**New Behavior:**
- Analyzes IOC but ALWAYS provides behavioral alternatives
- Issues warnings for low-value IOCs
- Recommends behavioral hunting over IOC hunting

**Output Format:**
```python
{
    'ioc_analysis': {
        '192.168.1.1': {
            'pyramid_level': 'ip_addresses',
            'warning': '⚠️  IP is at BOTTOM of Pyramid...',
            'behavioral_alternatives': [
                {
                    'technique': 'T1071.001 - Web Protocols',
                    'hunt_description': 'Hunt for C2 beaconing patterns',
                    'pyramid_level': 'TTPs (Top)'
                }
            ]
        }
    },
    'recommendation': '💡 IOCs provide context but poor hunting value...'
}
```

#### _suggest_behavioral_hunt() New Function

**Purpose:** Core function that pivots from any IOC type to behavioral alternatives

**Logic:**
- IP/Domain → C2 beaconing, DNS tunneling behaviors
- Hash → Execution patterns, persistence mechanisms
- URL → Web shell behaviors, data exfiltration patterns

---

### 4. New Documentation: BEHAVIORAL_HUNTING_GUIDE.md

**Comprehensive guide including:**

#### Section 1: Pyramid of Pain Deep Dive
- Visual pyramid with change times
- Hunt value table (Very Low → Highest)
- Clear guidance on what to focus on

#### Section 2: Behavioral Hunting Principles
- **Principle 1:** Hunt for "how" not "what"
- **Principle 2:** Focus on required adversary actions
- **Principle 3:** Understand adversary constraints

#### Section 3: Behavioral Detection Patterns
Six detailed examples:
1. **Credential Access** - LSASS memory dumping (T1003.001)
2. **Process Injection** - Remote thread creation (T1055)
3. **Lateral Movement** - Remote service execution (T1021)
4. **Persistence** - Registry run key modifications (T1547)
5. **Command & Control** - Beaconing detection (T1071)
6. **Living-off-the-Land** - PowerShell cradles (T1059.001)

Each includes:
- Behavior pattern description
- Detection logic (Splunk SPL)
- Why it works
- What tools it catches
- Pyramid level

#### Section 4: Anti-Patterns to Avoid
- ❌ Hash-based detection only
- ❌ IP/Domain blocklists only
- ❌ File path/name only

#### Section 5: Building Durable Detections
Framework for converting IOCs to behavioral hunts:
1. Understand the attack technique
2. Identify required actions
3. Generalize the pattern
4. Build behavioral detection

#### Section 6: Quick Reference
Table mapping IOC types to behavioral alternatives

---

## Behavioral Hunting Examples

### Example 1: Credential Dumping

**IOC Approach (Old):**
```
Alert on hash: a3f5b8c9d1e2f3a4b5c6d7e8f9a0b1c2 (Mimikatz)
```

**Behavioral Approach (New):**
```splunk
# Hunt for ANY process accessing LSASS memory
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where NOT SourceImage IN legitimate_tools
```

**Why Better:**
- Works against Mimikatz, ProcDump, custom tools
- Survives recompilation, obfuscation
- Pyramid Level: TTPs (Tough to change)

---

### Example 2: Command & Control

**IOC Approach (Old):**
```
Block IPs: [192.168.1.100, 203.0.113.5, ...]
Block domains: [evil.com, bad-c2.net, ...]
```

**Behavioral Approach (New):**
```splunk
# Hunt for beaconing behavior patterns
index=network
| bucket _time span=1m
| stats count sum(bytes) as total_bytes by src_ip, dest_ip
| where byte_stdev < threshold AND connection_regularity > threshold
```

**Why Better:**
- Works regardless of C2 infrastructure
- Catches Cobalt Strike, Metasploit, custom C2
- Pyramid Level: TTPs (Tough to change)

---

### Example 3: Lateral Movement

**IOC Approach (Old):**
```
Alert on tool: psexec.exe
Alert on hash: [specific PsExec hash]
```

**Behavioral Approach (New):**
```splunk
# Hunt for remote execution patterns
index=windows EventCode=4624 Logon_Type IN (3,10)
| join Computer_Name
    [search index=sysmon EventCode=1]
| where time_delta < 5m
```

**Why Better:**
- Catches PsExec, WMI, PowerShell Remoting, custom tools
- Focuses on required behavior (auth + execution)
- Pyramid Level: TTPs (Tough to change)

---

## User Experience Changes

### When User Provides IOC

**Before:**
```
User: "Analyze IP 192.168.1.100"
System: "Here's threat intel on this IP..."
```

**After:**
```
User: "Analyze IP 192.168.1.100"
System:
  "⚠️  IP is at BOTTOM of Pyramid. Adversaries change in minutes.

  Behavioral Alternatives (Top of Pyramid):
  - Hunt for C2 beaconing patterns (T1071.001)
  - Hunt for DNS tunneling behaviors (T1071.004)

  💡 Recommendation: Pivot to behavioral hunting for durable detection"
```

### When User Provides Hash

**Before:**
```
User: "Hunt for hash abc123..."
System: "Searching for hash..."
```

**After:**
```
User: "Hunt for hash abc123..."
System:
  "⚠️  HASH is at BOTTOM of Pyramid. Adversaries change in seconds.

  Behavioral Alternatives (Top of Pyramid):
  - Hunt for execution behaviors (T1059.*) - process chains
  - Hunt for persistence mechanisms (T1547.*) - autoruns
  - Hunt for defense evasion (T1055) - process injection

  💡 Instead of hunting this specific hash, hunt for what it DOES"
```

---

## Metrics for Success

### Before (IOC-Focused)
- Detection lifespan: Hours to days
- Coverage: Specific to known indicators
- Maintenance: Constant IOC feed updates
- Adversary impact: Trivial to evade (recompile, rotate infrastructure)

### After (Behavior-Focused)
- Detection lifespan: Months to years ✅
- Coverage: Entire technique classes ✅
- Maintenance: Minimal updates needed ✅
- Adversary impact: Forces operational changes ✅

---

## Key Files Modified

1. **[README.md](README.md)**
   - Added Pyramid of Pain visualization
   - Added behavioral hunting philosophy
   - Added practical examples
   - Added manifesto

2. **[src/intelligence/threat_intel.py](src/intelligence/threat_intel.py)**
   - Enhanced PyramidOfPain class
   - Added behavioral pivot suggestions
   - Added warnings for low-value IOCs

3. **[src/nlp/hunt_nlp.py](src/nlp/hunt_nlp.py)**
   - Added behavioral focus mode
   - Enhanced IOC analysis with behavioral alternatives
   - Added automatic behavioral pivot suggestions

4. **[BEHAVIORAL_HUNTING_GUIDE.md](BEHAVIORAL_HUNTING_GUIDE.md)** (NEW)
   - Comprehensive guide to behavioral hunting
   - 6 detailed detection patterns with SPL
   - Anti-patterns to avoid
   - Framework for building durable detections

5. **[BEHAVIORAL_FOCUS_SUMMARY.md](BEHAVIORAL_FOCUS_SUMMARY.md)** (THIS FILE)
   - Summary of all changes
   - Before/after comparisons
   - Implementation details

---

## Testing Behavioral Focus

### Test Scenarios

1. **Test IOC Submission**
   ```python
   result = await enrich_ioc("192.168.1.100", "ip")
   assert 'behavioral_pivot_suggestions' in result
   assert 'warning' in result
   ```

2. **Test Hunt Prioritization**
   ```python
   hunts = [
       {'value': 'abc123', 'type': 'hash'},
       {'value': 'T1003.001', 'type': 'technique'}
   ]
   prioritized = pyramid.prioritize_hunts(hunts)
   assert prioritized[0]['type'] == 'technique'  # TTP first!
   ```

3. **Test Natural Language**
   ```
   User: "Hunt for credential dumping"
   Expected: Behavioral detection (LSASS access), not hash search
   ```

---

## Next Steps for Full Behavioral Integration

### Recommended Enhancements

1. **Behavioral Pattern Library**
   - Expand detection patterns in BEHAVIORAL_HUNTING_GUIDE.md
   - Add more MITRE ATT&CK technique mappings
   - Include sub-technique specific patterns

2. **Automated Behavioral Translation**
   - When user provides IOC, automatically generate behavioral hunt
   - "Smart pivot" from any IOC to most relevant TTP

3. **Hunt Quality Scoring**
   - Score hunts based on Pyramid of Pain level
   - Visualize hunt quality metrics
   - Encourage TTP-based hunts through gamification

4. **HEARTH Integration Enhancement**
   - Filter HEARTH hunts to show TTP-focused ones first
   - Tag community hunts by Pyramid level
   - Promote highest-value hunts

5. **Detection Engineering Pipeline**
   - Template system for converting behaviors to detections
   - Validation framework ensuring behavioral focus
   - Test harness for behavioral hunt efficacy

---

## Conclusion

This refactoring successfully transforms the Threat Hunting MCP Server from a general-purpose hunting tool into a **behavioral-first** platform that:

✅ Educates users about the Pyramid of Pain
✅ Guides users toward high-value behavioral hunting
✅ Warns against low-value IOC-based approaches
✅ Automatically suggests behavioral pivots
✅ Provides comprehensive documentation and examples
✅ Embeds behavioral focus throughout the codebase

**Core Achievement:** Users are now **actively guided** toward hunting behaviors at the top of the Pyramid of Pain, making their detection programs more durable and effective against sophisticated adversaries.

**Remember:** Make it **TOUGH** for adversaries by focusing on behaviors they can't easily change!
