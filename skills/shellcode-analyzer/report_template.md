# Shellcode Analysis Report: <filename>

**Date:** <YYYY-MM-DD>
**File:** <filename>
**Size:** <N> bytes
**Bitness:** <64-bit (x64) | 32-bit (x86)>
**Classification:** <one-line summary, e.g. "Metasploit reverse_tcp stager (encoded)">

---

## 1. Encoding / Packing

**Type:** <encoding scheme name, e.g. "JMP/CALL/POP XOR decoder stub", or "None — plaintext shellcode">

<Describe the encoding/packing mechanism. Include:>
<- How the decoder stub locates the encoded payload>
<- The decryption/decompression algorithm (XOR key schedule, rolling key, etc.)>
<- Termination condition for the decode loop>
<- How control transfers to the decoded payload>

**Decoder addresses:**
| Address | Instruction | Purpose |
|---------|-------------|---------|
| `+0x__` | `...` | ... |

<If no encoding was found, state "No encoding or packing detected." and remove the table.>

---

## 2. Decoded Payload — Static Analysis

### 2.1 API Resolution

**Technique:** <e.g. "PEB walking with ROR13 hashing", "IAT lookup", "GetProcAddress", "Syscall stubs">

<Describe the API resolution mechanism:>
<- How it locates loaded modules (PEB, hardcoded addresses, etc.)>
<- Hashing algorithm and calling convention>
<- How resolved addresses are invoked>

### 2.2 Resolved API Hashes

| Hash | API | Purpose |
|------|-----|---------|
| `0x________` | `FunctionName` | Brief purpose |

<If the shellcode uses direct imports or syscalls instead of hashing, adapt this table accordingly.>

### 2.3 Configuration / Embedded Data

<Document any embedded configuration: C2 addresses, ports, URLs, encryption keys, sleep timers, pipe names, etc.>

| Field | Value |
|-------|-------|
| ... | ... |

### 2.4 Execution Flow

```
1. <Step-by-step execution summary>
2. <Use numbered steps with sub-steps (a, b, c) for loops/branches>
3. <Include retry logic, error handling paths, and final payload execution>
```

---

## 3. Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| C2 IP | `...` |
| C2 Port | `...` |
| Protocol | ... |
| User-Agent | ... |
| Named Pipe | ... |
| Mutex | ... |
| File Path | ... |
| Registry Key | ... |

<Include only rows that apply. Remove rows with no findings.>

---

## 4. Classification

<Provide a definitive classification:>
<- Malware family / framework (e.g. Metasploit, Cobalt Strike, custom)>
<- Payload type (stager, stageless, dropper, loader, etc.)>
<- Key distinguishing features>
<- What the shellcode does vs. what it would download/execute at runtime>

---

## 5. Annotations

<State what labels and comments were applied in the debugger session. Reference key labeled addresses if helpful.>
