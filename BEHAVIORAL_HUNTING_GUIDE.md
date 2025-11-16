# Behavioral Hunting Guide

**Philosophy: Hunt for behaviors that persist across tool/infrastructure changes**

This guide provides concrete examples of behavioral hunting at the top of the Pyramid of Pain.

## Table of Contents
1. [Understanding the Pyramid of Pain](#understanding-the-pyramid-of-pain)
2. [Behavioral Hunting Principles](#behavioral-hunting-principles)
3. [Behavioral Detection Patterns](#behavioral-detection-patterns)
4. [Anti-Patterns to Avoid](#anti-patterns-to-avoid)
5. [Building Durable Detections](#building-durable-detections)

---

## Understanding the Pyramid of Pain

```
                    TOUGH TO CHANGE
                   /                \
                  /   TTPs           \  ← FOCUS HERE
                 /    (Behaviors)     \
                /______________________\
               /   Tools               \
              /   (Capabilities)        \
             /__________________________ \
            /  Host/Network Artifacts    \
           /________________________________\
          /      Domain Names               \
         /         (Annoying)                \
        /____________________________________  \
       /        IP Addresses                   \
      /            (Easy)                       \
     /___________________________________________\
               Hash Values (Trivial)
```

### What This Means for Hunting

| Level | Adversary Change Time | Hunt Value | Focus |
|-------|----------------------|------------|-------|
| **Hash Values** | Seconds | ❌ Very Low | Avoid IOC-only |
| **IP Addresses** | Minutes | ❌ Low | Pivot to behavior |
| **Domain Names** | Hours | ❌ Low-Medium | Pivot to behavior |
| **Network Artifacts** | Days | ⚠️ Medium | Better than IOCs |
| **Host Artifacts** | Days | ⚠️ Medium | Better than IOCs |
| **Tools** | Weeks | ✅ High | Hunt capabilities |
| **TTPs (Behaviors)** | Months-Years | ✅✅✅ Highest | **PRIMARY FOCUS** |

---

## Behavioral Hunting Principles

### Principle 1: Hunt for "How" Not "What"

**❌ Bad: IOC-Based**
```
Hunt for hash: a3f5b8c9d1e2f3a4b5c6d7e8f9a0b1c2
Problem: Adversary recompiles → new hash → detection fails
```

**✅ Good: Behavior-Based**
```
Hunt for: Process injection into system processes (T1055)
Detection: Monitor CreateRemoteThread, QueueUserAPC, SetThreadContext APIs
Result: Works regardless of which tool performs injection
```

### Principle 2: Focus on Required Adversary Actions

**❌ Bad: Tool Signature**
```
Hunt for: Specific Mimikatz strings in memory
Problem: Custom credential dumpers don't match
```

**✅ Good: Required Behavior**
```
Hunt for: Any process accessing LSASS memory (T1003.001)
Detection: Sysmon Event 10 (ProcessAccess) targeting lsass.exe
Result: Catches Mimikatz, custom tools, living-off-the-land techniques
```

### Principle 3: Understand Adversary Constraints

Adversaries MUST perform certain actions to achieve objectives:
- To steal credentials → Must access credential stores (LSASS, SAM, LSA secrets)
- To move laterally → Must authenticate to remote systems
- To persist → Must modify autoruns, services, or scheduled tasks
- To execute code → Must create processes or threads

**Hunt for these required behaviors!**

---

## Behavioral Detection Patterns

### 1. Credential Access (T1003)

#### LSASS Memory Dumping (T1003.001)

**Behavior Pattern:**
```
Any process (regardless of name/hash) opening a handle to lsass.exe
with PROCESS_VM_READ permissions
```

**Detection Logic:**
```splunk
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| stats count dc(SourceImage) as unique_processes by Computer_Name, SourceUser
| where count > 1 OR NOT (SourceImage IN ("*\\taskmgr.exe", "*\\procexp.exe"))
```

**Why This Works:**
- Behavior is REQUIRED for credential dumping
- Works against: Mimikatz, ProcDump, custom tools, LOLBins
- Persists through: Tool changes, hash changes, obfuscation

**Pyramid Level:** TTPs (Top) - Tough to change

---

### 2. Process Injection (T1055)

#### Remote Thread Creation

**Behavior Pattern:**
```
Process A creating threads in Process B's memory space,
especially targeting system processes
```

**Detection Logic:**
```splunk
index=sysmon EventCode=8
| eval suspicious_target=if(
    match(TargetImage, "(?i)(explorer|svchost|winlogon|csrss|lsass)"), 1, 0
)
| where suspicious_target=1
| stats count by SourceImage, TargetImage, Computer_Name
```

**Why This Works:**
- Required for code injection/hiding
- Works against: Cobalt Strike, Metasploit, custom malware
- Persists through: Different injection frameworks

**Pyramid Level:** TTPs (Top) - Tough to change

---

### 3. Lateral Movement (T1021)

#### Remote Service Execution Patterns

**Behavior Pattern:**
```
Authentication to remote systems followed by process creation
within short time window
```

**Detection Logic:**
```splunk
# Step 1: Find remote authentications
index=windows EventCode=4624 Logon_Type IN (3,10)
| eval auth_key=Source_Network_Address."|".Target_User_Name

# Step 2: Correlate with process creation
| join auth_key type=inner max=0
    [search index=sysmon EventCode=1
    | eval auth_key=Computer_Name."|".User]

# Step 3: Identify patterns
| timechart span=5m count by auth_key
| where count > threshold
```

**Why This Works:**
- Lateral movement REQUIRES authentication + execution
- Works against: PsExec, WMI, PowerShell Remoting, SMB, RDP
- Persists through: Tool and credential rotation

**Pyramid Level:** TTPs (Top) - Tough to change

---

### 4. Persistence (T1547)

#### Registry Run Key Modifications

**Behavior Pattern:**
```
Modification of autorun registry locations by unusual processes
```

**Detection Logic:**
```splunk
index=sysmon EventCode=13
    (TargetObject="*\\Run\\*" OR
     TargetObject="*\\RunOnce\\*" OR
     TargetObject="*\\CurrentVersion\\Windows\\Run")
| where NOT Image IN ("*\\msiexec.exe", "*\\setup.exe", "*\\installer.exe")
| stats count values(Details) as values by Computer_Name, Image, TargetObject
```

**Why This Works:**
- Registry autoruns are limited, well-defined locations
- Behavior persists regardless of payload
- Catches: Custom malware, living-off-the-land, commercial tools

**Pyramid Level:** Host Artifacts → TTPs (Medium-High)

---

### 5. Command and Control (T1071)

#### Beaconing Behavior Detection

**Behavior Pattern:**
```
Network connections with regular intervals and consistent payload sizes
indicating automated C2 communication
```

**Detection Logic:**
```splunk
index=network
| bucket _time span=1m
| stats count sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_port, _time
| streamstats window=10 stdev(total_bytes) as byte_stdev by src_ip, dest_ip
| where byte_stdev < 100 AND count > 5
| stats count as connection_count by src_ip, dest_ip, dest_port
| where connection_count > 20
```

**Why This Works:**
- Automated beaconing is REQUIRED for persistent C2
- Pattern persists across different C2 frameworks
- Works against: Cobalt Strike, Metasploit, custom C2, APT frameworks

**Pyramid Level:** TTPs (Top) - Tough to change

---

### 6. Living-off-the-Land (Multiple Techniques)

#### PowerShell Download Cradle Patterns

**Behavior Pattern:**
```
PowerShell execution with network connection capabilities
(DownloadString, DownloadFile, WebClient, Invoke-WebRequest)
```

**Detection Logic:**
```splunk
index=powershell OR index=sysmon EventCode=1 Image="*powershell.exe"
| regex CommandLine="(?i)(downloadstring|downloadfile|webclient|invoke-webrequest|iwr|net\.webclient)"
| stats count by Computer_Name, User, CommandLine
```

**Why This Works:**
- Download + execute is common attack pattern
- Behavior persists across different payloads/C2
- Catches: Empire, Metasploit, custom scripts

**Pyramid Level:** TTPs (Top) - Tough to change

---

## Anti-Patterns to Avoid

### ❌ Anti-Pattern 1: Hash-Based Detection Only

**Bad Example:**
```
IF file_hash == "a3f5b8c9d1e2f3a4b5c6d7e8f9a0b1c2" THEN
    alert("Mimikatz detected!")
```

**Problem:** Adversary recompiles → New hash → Detection bypassed in seconds

**Better Approach:**
```
IF (process.target_image == "lsass.exe" AND
    process.access_rights CONTAINS "PROCESS_VM_READ" AND
    process.source_image NOT IN allowlist) THEN
    alert("LSASS memory access - potential credential dumping")
```

---

### ❌ Anti-Pattern 2: IP/Domain Blocklists Only

**Bad Example:**
```
IF connection.destination_ip IN [known_bad_ips] THEN
    block_connection()
```

**Problem:** Adversary rotates infrastructure hourly → Constant blocklist updates

**Better Approach:**
```
IF (connection.interval_regularity > threshold AND
    connection.byte_size_consistency > threshold AND
    connection.destination NOT IN known_good) THEN
    alert("Potential C2 beaconing behavior detected")
```

---

### ❌ Anti-Pattern 3: File Path/Name Only

**Bad Example:**
```
IF file.path == "C:\\Windows\\Temp\\evil.exe" THEN
    alert("Malware detected!")
```

**Problem:** Adversary changes path/name trivially

**Better Approach:**
```
IF (process.parent == "explorer.exe" AND
    process.child == "powershell.exe" AND
    process.command_line CONTAINS "-enc" AND
    network.connection_made) THEN
    alert("Suspicious PowerShell execution pattern")
```

---

## Building Durable Detections

### Framework: From IOC to Behavior

When you receive an IOC (hash, IP, domain), follow this process:

1. **Understand the Attack Technique**
   - What MITRE ATT&CK technique does this IOC relate to?
   - What behavior was the adversary performing?

2. **Identify Required Actions**
   - What MUST the adversary do to achieve this objective?
   - What OS APIs, system resources, or patterns are required?

3. **Generalize the Pattern**
   - Remove specific values (hashes, IPs, paths)
   - Focus on relationships and behaviors
   - Consider legitimate use cases (reduce false positives)

4. **Build Behavioral Detection**
   - Write detection logic for the behavior, not the indicator
   - Test against multiple tools that perform the same behavior
   - Validate detection persists across tool/infrastructure changes

### Example: From Malware Hash to Behavior

**Starting Point:** Malware hash `abc123...` performs credential dumping

**Step 1 - Understand Technique:**
- MITRE ATT&CK: T1003.001 - LSASS Memory
- Behavior: Access LSASS process memory to extract credentials

**Step 2 - Required Actions:**
- MUST call OpenProcess() on lsass.exe
- MUST request PROCESS_VM_READ permissions
- MUST call ReadProcessMemory() or MiniDumpWriteDump()

**Step 3 - Generalize Pattern:**
```
ANY process accessing lsass.exe memory
EXCLUDING legitimate tools (Task Manager, debugging tools in controlled context)
```

**Step 4 - Behavioral Detection:**
```splunk
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where GrantedAccess IN ("0x1010", "0x1410", "0x1438")
| where NOT SourceImage IN ("*\\taskmgr.exe", "*\\procexp64.exe")
| stats count by SourceImage, SourceUser, Computer_Name
```

**Result:** Detection works against:
- Mimikatz (any version/hash)
- ProcDump
- Custom credential dumpers
- Future tools using this technique

---

## Quick Reference: IOC → Behavior Pivots

| IOC Type | Behavioral Alternative | MITRE Technique |
|----------|----------------------|-----------------|
| **Malware Hash** | Hunt for execution behavior patterns | T1059.* (Execution) |
| **C2 IP Address** | Hunt for beaconing patterns | T1071.* (C2 Protocol) |
| **C2 Domain** | Hunt for DNS tunneling patterns | T1071.004 (DNS) |
| **Malicious URL** | Hunt for download cradle patterns | T1105 (Ingress Transfer) |
| **Registry Key** | Hunt for autorun modifications | T1547.* (Boot/Logon) |
| **File Path** | Hunt for persistence locations | T1053.*, T1543.* |
| **Tool Name** | Hunt for tool capabilities | T1003, T1021, T1055 |

---

## Measuring Hunt Effectiveness

### Good Behavioral Hunt Characteristics:

✅ **Survives tool rotation** - Works against multiple tools performing same behavior

✅ **Survives infrastructure rotation** - Doesn't depend on specific IPs/domains

✅ **Survives code modification** - Not based on hashes or specific strings

✅ **Low false positive rate** - Excludes legitimate business activities

✅ **Maps to MITRE ATT&CK** - Clearly ties to adversary technique

✅ **Testable** - Can validate detection with red team exercises

### Red Flags (Poor Hunt Quality):

❌ Detection breaks when adversary recompiles code

❌ Detection requires constant IOC feed updates

❌ Detection is specific to one tool/malware family

❌ Detection can be trivially bypassed with minor changes

❌ No clear mapping to adversary behavior/technique

---

## Conclusion

**Remember the Core Principle:**

> "Hunt for HOW adversaries behave, not WHAT specific tools/infrastructure they use"

Behavioral hunting at the top of the Pyramid of Pain creates:
- **Durable detections** that survive adversary tool/infrastructure rotation
- **Broader coverage** across multiple threat actors using similar techniques
- **Force multiplication** - one behavioral detection replaces hundreds of IOCs
- **Adversary frustration** - forces fundamental operational changes, not just tool swaps

**Focus your hunting program on TTPs, and you'll make it TOUGH for adversaries to operate undetected.**
