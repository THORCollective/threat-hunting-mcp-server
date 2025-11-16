# Behavioral Hunting Refactor Summary

## Overview

This repository has been refactored to focus on **behavioral hunting (TTPs)** at the top of the Pyramid of Pain, rather than IOC-based hunting at the bottom.

## Changes Made

### 1. **Philosophy Shift** ✅

**Before:** Mixed focus on IOCs and behaviors
**After:** Clear emphasis on behavioral hunting with IOCs treated as pivot points

**Key Message:**
> "Hunt for HOW adversaries behave, not WHAT specific tools/infrastructure they use"

---

### 2. **README.md Updates** ✅

#### Added Philosophy Section
- Prominent Pyramid of Pain visualization
- Clear explanation of why behavioral hunting is superior
- Emphasis on adversary change times (seconds for hashes vs months/years for TTPs)

#### Added Behavioral Examples
- Concrete examples of good (behavioral) vs bad (IOC) hunting
- Real-world detection patterns for credential access, lateral movement, process injection
- Natural language query examples focused on behaviors

#### Added Behavioral Manifesto
- 5 core principles of behavioral hunting
- Mindset shift examples (old way vs new way)
- Quick decision framework

**Files Modified:**
- [README.md](README.md) - Main documentation with behavioral focus

---

### 3. **Pyramid of Pain Enhancement** ✅

#### Enhanced PyramidOfPain Class
`src/intelligence/threat_intel.py`

**New Features:**
- Each pyramid level includes:
  - `adversary_change_time` - How fast adversaries can rotate
  - `hunt_value` - Explicit hunting value assessment
  - `recommended` - Boolean flag (True for TTPs/Tools, False for IOCs)

**Example:**
```python
'ttps': {
    'pain': 7,
    'difficulty': 'Tough',
    'adversary_change_time': 'Months to Years',
    'hunt_value': 'HIGHEST - Primary focus for threat hunting',
    'recommended': True  # FOCUS HERE!
}

'hash_values': {
    'pain': 1,
    'difficulty': 'Trivial',
    'adversary_change_time': 'Seconds',
    'hunt_value': 'Very Low - Avoid IOC-only hunting',
    'recommended': False  # AVOID!
}
```

#### Enhanced IOC Enrichment

**New Method: `_suggest_behavioral_pivots()`**

When an IOC is provided, the system now:
1. Classifies its pyramid level
2. Adds warnings for low-value IOCs
3. **Automatically suggests behavioral hunting alternatives**

**Example Output:**
```json
{
  "ioc": "192.168.1.100",
  "type": "ip",
  "pyramid_level": "ip_addresses",
  "warning": "⚠️ This IP is at the BOTTOM of the Pyramid of Pain. Adversaries can change it in minutes.",
  "behavioral_pivot_suggestions": [
    "Hunt for C2 beaconing behaviors (T1071.001) - regular intervals, consistent packet sizes",
    "Hunt for DNS tunneling patterns (T1071.004) - unusual subdomain lengths",
    "⭐ BEST PRACTICE: Always pivot from IOCs to behavioral patterns"
  ]
}
```

**Files Modified:**
- [src/intelligence/threat_intel.py](src/intelligence/threat_intel.py) - Enhanced Pyramid of Pain implementation

---

### 4. **NLP Module Enhancement** ✅

#### Behavioral Focus Mode
`src/nlp/hunt_nlp.py`

**New Feature:** `behavioral_focus_mode = True`

When users provide IOCs, the NLP module now:
1. Processes the IOC request
2. **Automatically provides behavioral alternatives**
3. Warns about low-value IOC hunting

#### New Method: `_suggest_behavioral_hunt()`

Maps IOC types to behavioral hunting alternatives:

**Example:**
```python
# User searches for hash
behavioral_alternatives = [
    {
        'technique': 'T1059.* - Command and Scripting Interpreter',
        'hunt_description': 'Hunt for suspicious process chains',
        'pyramid_level': 'TTPs (Top)'
    },
    {
        'technique': 'T1055 - Process Injection',
        'hunt_description': 'Hunt for injection behaviors regardless of tool',
        'pyramid_level': 'TTPs (Top)'
    }
]
```

**Files Modified:**
- [src/nlp/hunt_nlp.py](src/nlp/hunt_nlp.py) - Behavioral pivoting logic

---

### 5. **Documentation Created** ✅

#### Behavioral Hunting Guide
**[BEHAVIORAL_HUNTING_GUIDE.md](BEHAVIORAL_HUNTING_GUIDE.md)**

**Contents:**
- Complete explanation of Pyramid of Pain
- Behavioral hunting principles
- 6 detailed detection patterns with Splunk queries:
  - Credential Access (LSASS memory dumping)
  - Process Injection (CreateRemoteThread)
  - Lateral Movement (Remote execution patterns)
  - Persistence (Registry run keys)
  - Command and Control (Beaconing detection)
  - Living-off-the-Land (PowerShell download cradles)
- Anti-patterns to avoid
- Framework for building durable detections
- IOC → Behavior pivot examples

**Key Sections:**
- Understanding the Pyramid of Pain
- Behavioral Hunting Principles
- Behavioral Detection Patterns (6 examples)
- Anti-Patterns to Avoid
- Building Durable Detections
- Quick Reference Tables

---

#### Quick Reference Card
**[BEHAVIORAL_HUNTING_QUICK_REF.md](BEHAVIORAL_HUNTING_QUICK_REF.md)**

**One-page cheat sheet including:**
- Pyramid of Pain quick reference table
- The behavioral hunting mindset (3 key questions)
- Common behavioral patterns by MITRE tactic
- IOC → Behavior quick pivots
- Splunk query templates
- Red flags (bad) vs Green flags (good) hunting
- Testing behavioral detections
- Hunt program maturity levels
- Quick decision tree

---

### 6. **Architecture Alignment** ✅

**All Components Now Emphasize Behavioral Hunting:**

| Component | Behavioral Enhancement |
|-----------|----------------------|
| **README** | Philosophy, examples, manifesto |
| **Pyramid of Pain** | Adversary change times, hunt values, recommendations |
| **IOC Enrichment** | Behavioral pivot suggestions, warnings |
| **NLP Module** | Automatic behavioral alternatives |
| **Documentation** | Complete guides and quick references |

---

## Key Improvements

### Before Refactor ❌

**User:** "Hunt for hash abc123"
**System:** ✅ "Here's a query for that hash"
**Problem:** Detection fails when adversary recompiles

---

### After Refactor ✅

**User:** "Hunt for hash abc123"
**System:**
```
⚠️ WARNING: Hash values are at the BOTTOM of the Pyramid of Pain.
Adversaries can change this in SECONDS.

Instead, hunt for these BEHAVIORS:
- T1059.* - Suspicious process execution patterns
- T1055 - Process injection behaviors
- T1547.* - Persistence mechanisms

These detections work regardless of which tool the adversary uses.
```

**Result:** User is guided toward durable behavioral detections

---

## Usage Examples

### Example 1: Credential Dumping

**Old Way (IOC-focused):**
```
Hunt for Mimikatz hash: a3f5b8c9d1e2f3a4...
```
Result: Fails when adversary uses custom tool

**New Way (Behavior-focused):**
```
Hunt for any process accessing LSASS memory (T1003.001)
```
Result: Catches Mimikatz, ProcDump, custom tools, future variants

---

### Example 2: C2 Detection

**Old Way (IOC-focused):**
```
Block C2 IP: 192.168.1.100
```
Result: Adversary rotates IPs → detection fails

**New Way (Behavior-focused):**
```
Hunt for C2 beaconing patterns (T1071.001)
- Regular connection intervals
- Consistent packet sizes
- Non-standard ports
```
Result: Works regardless of C2 infrastructure

---

## Behavioral Hunting Principles

### 1. Hunt for Required Actions
**Question:** What MUST the adversary do to achieve their objective?
**Example:** To steal credentials → Must access LSASS/SAM

### 2. Focus on What Persists
**Avoid:** Hashes, IPs, domains (change in seconds/minutes/hours)
**Focus:** Behaviors, API patterns, process relationships (change in months/years)

### 3. Think Like an Adversary
**Question:** What are the constraints on the adversary's operations?
**Example:** To inject code → Must use CreateRemoteThread or similar API

### 4. Build Durable Detections
**Test:** Does detection work when adversary:
- Changes tools? ✅
- Changes infrastructure? ✅
- Recompiles payload? ✅

### 5. Pivot from IOCs to Behaviors
**Process:**
1. Receive IOC (hash/IP/domain)
2. Understand what behavior it represents
3. Identify required adversary actions
4. Hunt for those actions across ALL tools

---

## File Hierarchy

```
threat_hunting_mcp/
├── README.md                           # Updated with behavioral focus
├── BEHAVIORAL_HUNTING_GUIDE.md         # NEW: Complete behavioral guide
├── BEHAVIORAL_HUNTING_QUICK_REF.md     # NEW: One-page cheat sheet
├── REFACTOR_SUMMARY.md                 # NEW: This file
├── src/
│   ├── intelligence/
│   │   └── threat_intel.py            # Enhanced Pyramid of Pain
│   └── nlp/
│       └── hunt_nlp.py                # Behavioral pivot suggestions
```

---

## Testing the Changes

### Test 1: IOC Query with Behavioral Pivot

**Input:** "Analyze IP address 192.168.1.100"

**Expected Output:**
```json
{
  "status": "success",
  "ioc_analysis": {
    "192.168.1.100": {
      "type": "ip",
      "pyramid_level": "ip_addresses",
      "warning": "⚠️ IP is at the BOTTOM of the Pyramid of Pain...",
      "behavioral_alternatives": [
        {
          "technique": "T1071.001 - Web Protocols",
          "hunt_description": "Hunt for C2 beaconing patterns",
          "pyramid_level": "TTPs (Top)"
        }
      ]
    }
  },
  "recommendation": "IOCs provide context but poor hunting value. Review behavioral alternatives."
}
```

---

### Test 2: Behavioral Query

**Input:** "Hunt for credential dumping behavior (T1003.001)"

**Expected Output:**
- Focus on LSASS memory access patterns
- Splunk queries for Sysmon Event 10
- Detection works across all credential dumping tools
- No dependency on specific hashes or tool signatures

---

## Metrics for Success

### Before (IOC-Focused)
- Detection lifespan: Hours to days
- Tools detected: Specific known tools only
- Adversary effort to bypass: Trivial (recompile/rotate)
- Maintenance burden: Constant IOC feed updates

### After (Behavior-Focused)
- Detection lifespan: Months to years ✅
- Tools detected: Any tool using the technique ✅
- Adversary effort to bypass: Must change operations ✅
- Maintenance burden: Minimal - behavioral patterns stable ✅

---

## Key Takeaways

### The Core Message:
**"Hunt for behaviors at the TOP of the Pyramid of Pain"**

### The Core Benefit:
**"Durable detections that force adversaries to change operations, not just swap tools"**

### The Core Action:
**"Always pivot from IOCs to the behaviors they represent"**

---

## References

- **Pyramid of Pain:** http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
- **MITRE ATT&CK:** https://attack.mitre.org
- **PEAK Framework:** Integrated in this MCP server
- **HEARTH Community:** 50+ behavioral hunt hypotheses

---

## Next Steps

1. **Review Documentation:**
   - [Quick Reference Card](BEHAVIORAL_HUNTING_QUICK_REF.md) - Start here!
   - [Behavioral Hunting Guide](BEHAVIORAL_HUNTING_GUIDE.md) - Deep dive
   - [Main README](README.md) - Updated philosophy

2. **Test Behavioral Hunting:**
   - Use natural language queries focused on techniques
   - Notice how IOC queries now provide behavioral alternatives
   - Build detections that work across multiple tools

3. **Contribute:**
   - Share behavioral detection patterns
   - Add new TTP-focused hunt examples
   - Report issues or improvements

---

**Remember: Focus on the TOP of the Pyramid of Pain. Make it TOUGH for adversaries!**
