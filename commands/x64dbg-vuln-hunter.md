---
description: Hunt for vulnerabilities in a running debuggee by analyzing imports/exports, triaging attack surface, and iteratively testing for bugs with PoC generation.
---

# x64dbg-vuln-hunter

Hunt for vulnerabilities in a running debuggee. Performs import/export reconnaissance, triages attack surface by I/O context, then iteratively tests for bugs (buffer overflows, integer wraps, logic flaws, etc.) and builds proof-of-concept exploits.

These steps use the tools exposed by the `x64dbg` MCP server. Call them directly by name.

**Remote setup (REMnux → Windows VM):** OpenCode runs on REMnux and drives x64dbg on a separate Windows VM. The target program must already be loaded in x64dbg on the Windows VM and paused. Connect to it with the `connect_remote` tool (host, REQ/REP `27066`, PUB/SUB `27067`). The PE that the offline scripts (`enum_imports.py`, `find_xrefs.py`) parse must be readable on the REMnux host — copy the sample over if needed.

## Prerequisites

- The target program must be loaded in x64dbg (on the Windows VM) and paused (at entrypoint or a function of interest)
- Be conservative with the context window — disassemble on demand, read memory on demand, do not dump large regions speculatively

## Instructions

### 1. Connect and verify state

Confirm the debugger is connected and the debuggee is paused:

1. Call `connect_remote` (if not already connected), then `get_debugger_status` — verify status is `paused`
2. If running, call `pause`
3. Call `get_register` for `rip` (64-bit) or `eip` (32-bit) to determine bitness and current location
4. Call `get_memory_map` to get an overview of loaded modules

Note the main module name and base address for subsequent steps.

IF the debuggee looks packed (e.g., entry point is in a non-standard section, imports look obfuscated, or YARA signatures match known packers), run `/x64dbg-find-oep` first to unpack and find the real entry point.

### 2. Reconnaissance — imports and exports

The goal is to identify all program entry points that handle external (attacker-controllable) input.

#### 2a. Enumerate imports and exports

Use the LIEF-based enumeration script (bundled, run via the virtualenv Python on REMnux) to parse the PE's imports, exports, and security features:

```
/opt/x64dbg-automate-mcp-deps/bin/python3 /opt/x64dbg-skills-opencode/skills/vuln-hunter/enum_imports.py <target_pe_path_on_remnux> --output imports.json
```

**Packed binaries**: LIEF parses the on-disk PE, so packed binaries will show only the packer's minimal IAT (e.g. `GetProcAddress`, `LoadLibraryA`). For packed targets:
1. Unpack first (e.g. via `/x64dbg-find-oep`)
2. Take a `/x64dbg-state-snapshot` to dump all memory to disk
3. Re-run the script with `--snapshot-dir <snapshot_dir> --base <module_base>` to parse the resolved IAT from the memory dump instead

Read the output and the generated JSON. Categorize each import by I/O context:

| Category | Example APIs |
|---|---|
| **Network** | `recv`, `recvfrom`, `WSARecv`, `InternetReadFile`, `HttpQueryInfo`, `WinHttpReadData`, `getaddrinfo` |
| **File** | `ReadFile`, `CreateFileA/W`, `fread`, `fgets`, `MapViewOfFile`, `NtReadFile`, `mmioOpen`, `mmioRead` |
| **Registry** | `RegQueryValueExA/W`, `RegGetValueA/W`, `RegEnumValueA/W` |
| **Environment** | `GetEnvironmentVariableA/W`, `getenv` |
| **Command line** | `GetCommandLineA/W`, `CommandLineToArgvW` |
| **Clipboard / UI** | `GetClipboardData`, `GetWindowTextA/W`, `GetDlgItemTextA/W` |
| **IPC / Pipes** | `ReadFile` on pipe handles, `PeekNamedPipe`, `TransactNamedPipe` |
| **Memory / String** | `memcpy`, `strcpy`, `strcat`, `sprintf`, `wcscat`, `lstrcpyA/W`, `MultiByteToWideChar` — these are sinks, not sources, but are critical for buffer overflow detection |
| **Allocation** | `malloc`, `HeapAlloc`, `VirtualAlloc`, `LocalAlloc`, `GlobalAlloc` — track buffer sizes |

Also note dangerous formatting/conversion functions: `sprintf`, `vsprintf`, `swprintf`, `sscanf`, `atoi`, `atol`, `strtol` — these may be involved in format string or integer conversion bugs.

Exports indicate externally callable interfaces (DLL entry points, COM interfaces, etc.) that may accept untrusted input.

#### 2c. Find cross-references to I/O functions

For each interesting import identified above, find where it is called in the main module.

**Preferred approach — IAT byte-pattern search via Python/LIEF**:

The most reliable way to find xrefs is to search the `.text` section for byte patterns that reference IAT entries. This works even when the debugger's `findcalls` command fails or returns incomplete results. The bundled `find_xrefs.py` automates this — run it via the virtualenv Python:

```
/opt/x64dbg-automate-mcp-deps/bin/python3 /opt/x64dbg-skills-opencode/skills/vuln-hunter/find_xrefs.py <snapshot_dir> --base <module_base> --functions recv,ReadFile,strcpy --output xrefs.json
```

Or write your own inline script (run with `/opt/x64dbg-automate-mcp-deps/bin/python3`) following this pattern:

```python
import lief, struct

binary = lief.parse("<target_pe_path>")
disk_base = binary.optional_header.imagebase   # e.g. 0x400000
runtime_base = <module_base>                    # e.g. 0x160000
rebase = runtime_base - disk_base

# Get .text section bytes
text = [s for s in binary.sections if s.name == '.text'][0]
text_data = bytes(text.content)
text_va = disk_base + text.virtual_address

# For each import, compute IAT VA using DISK base (not runtime base!)
for imp in binary.imports:
    for entry in imp.entries:
        disk_iat_va = disk_base + entry.iat_address

        # Search for FF 15 <iat_va_le> (call dword ptr [IAT]) — direct callers
        pattern_call = b'\xff\x15' + struct.pack('<I', disk_iat_va)
        # Search for FF 25 <iat_va_le> (jmp dword ptr [IAT]) — thunk stub
        pattern_jmp = b'\xff\x25' + struct.pack('<I', disk_iat_va)

        # Find all occurrences in .text
        for i in range(len(text_data) - 5):
            chunk = text_data[i:i+6]
            if chunk == pattern_call:
                caller_runtime = text_va + i + rebase
                # Record direct caller
            elif chunk == pattern_jmp:
                thunk_runtime = text_va + i + rebase
                # Record thunk address

        # For thunks: also find E8 <rel32> callers of the thunk
        if thunk_found:
            thunk_disk = thunk_runtime - rebase
            for i in range(len(text_data) - 4):
                if text_data[i] == 0xE8:
                    rel32 = struct.unpack('<i', text_data[i+1:i+5])[0]
                    target = text_va + i + 5 + rel32
                    if target == thunk_disk:
                        caller_runtime = text_va + i + rebase
                        # Record thunk caller
```

**Key detail**: IAT addresses in on-disk code use the PE's `ImageBase` (e.g. `0x400000`), NOT the runtime base address. The code is not patched for ASLR relocation — the loader fixes up IAT entries at runtime, but the `FF 15`/`FF 25` instruction operands remain as disk addresses. Always use `binary.optional_header.imagebase` for IAT VA computation.

**Fallback approach — debugger commands**:

If the Python approach is impractical, use `execute_command` with the `findcalls` command:

```
execute_command("findcalls <import_address>")
```

Record each call site address. These are the **xrefs** — the primary targets for triage.

**Important**: Be selective. Focus on the most security-relevant imports first (network inputs, file reads, string copies). Do not enumerate xrefs for every import — that would bloat the context.

### 3. Triage areas of interest

For each xref group (organized by I/O function), evaluate the surrounding context:

1. **Disassemble** 30–50 instructions around each call site using `disassemble`
2. **Identify the containing function** — look for the function prologue (push rbp/ebp; mov rsp/esp pattern or similar) and note the function's start address
3. **Consider the actor** — who provides the input?
   - Remote attacker (network) → highest risk
   - Local attacker (file, registry, environment) → medium risk
   - Authenticated user (UI, clipboard) → lower risk but still relevant
4. **Consider the sink** — where does the input end up?
   - Fixed-size stack buffer → stack overflow potential
   - Heap buffer with unchecked size → heap overflow potential
   - Format string argument → format string vulnerability
   - Integer used in allocation size → integer overflow/wraparound
   - Used in control flow decision → logic flaw potential
5. **Label** each triaged function with a descriptive name via `set_label` (e.g., `vuln_candidate_recv_handler`, `vuln_candidate_file_parser`)
6. **Comment** each call site with a brief risk note via `set_comment`

After triaging, present the ranked list to the user:

```
## Triaged Attack Surface

| Rank | Address | Function | I/O Source | Sink | Risk |
|------|---------|----------|------------|------|------|
| 1    | 0x...   | ...      | Network    | Stack buffer | High |
| 2    | 0x...   | ...      | File       | Heap alloc   | Medium |
| ...  | ...     | ...      | ...        | ...          | ... |
```

Ask the user: "Here is the triaged attack surface. Which targets should I investigate? (all / specific ranks / let me choose)"

### 4. Bug hunting (iterative)

For each selected target, perform the following loop. **Do one target at a time** to stay focused and conserve context.

#### 4a. Deep analysis of the target function

1. Disassemble the full function (from prologue to retn) using `disassemble`
2. If the function is complex (>100 instructions), use `/x64dbg-decompile` for a higher-level view
3. Identify:
   - **Buffer sizes** — look for `sub rsp, N` (stack frame), `push N` / `mov ecx, N` before `HeapAlloc`/`malloc`, static `.data`/`.bss` buffers
   - **Length checks** — are sizes validated before copy? Look for `cmp`, `ja`/`jb` guards
   - **Integer arithmetic** — addition/multiplication on sizes before allocation (wrapping potential). Look for `add`, `imul`, `shl` on values derived from input
   - **Loop bounds** — are they controlled by attacker input?
   - **Format strings** — is user input passed as format argument (first arg) to `sprintf`/`printf` family?
   - **Logic flaws** — off-by-one in comparisons, signed/unsigned confusion (`jl` vs `jb`), TOCTOU patterns
   - **Side effects** — does the function write to global state, file, or registry based on unchecked input?

#### 4b. Formulate a hypothesis

Based on the analysis, describe the suspected vulnerability:
- **Type**: buffer overflow, integer overflow, format string, use-after-free, logic flaw, etc.
- **Trigger**: what input triggers it (e.g., "a `recv` buffer > 256 bytes when the stack buffer is 256")
- **Impact**: what happens if triggered (crash, code execution, info leak, etc.)

Present the hypothesis to the user.

#### 4c. Prepare instrumentation

Set up the debugger to observe the target code path:

1. Set a breakpoint at the function entry via `set_breakpoint`
2. Set breakpoints at key points: the dangerous call (e.g., `strcpy`), the length check (if any), the return
3. If fine-grained observation is needed, run `/x64dbg-tracealyzer` to trace through the function

#### 4d. Generate a test input

Create an input that should trigger the suspected bug. Use `Bash` to write a Python script that generates the payload:

- For network targets: a Python socket script that sends crafted data
- For file targets: a Python script that writes a crafted file to disk
- For other I/O: an appropriate delivery mechanism

The test input should be **diagnostic first** — use recognizable patterns (e.g., `"A" * 300` for overflow, `"%x" * 20` for format string) to confirm the bug before refining to a PoC.

Write the script to `./exploits/test_<target_name>.py`.

#### 4e. Trigger and observe

1. Tell the user what input to provide, or if the test script can deliver it automatically, run it via `Bash`
2. Call `go` to resume execution
3. Wait for a breakpoint hit or exception via `wait_for_event` or `get_debugger_status`
4. When paused:
   - Read registers via `get_all_registers`
   - Read the stack and relevant buffers via `read_memory`
   - Disassemble at the current location via `disassemble`
   - Check if the hypothesis is confirmed (e.g., buffer overwritten past boundary, EIP/RIP control, crash at expected location)
5. Document findings with comments and labels

#### 4f. Assess result

- **Bug confirmed**: proceed to PoC development (step 5)
- **Bug not triggered**: refine the hypothesis or input, revisit the analysis. Consider:
  - Was the code path actually reached? Check if breakpoints were hit
  - Are there additional checks that prevent the bug?
  - Is the input being transformed before reaching the sink?
- **Program crashed unexpectedly**: analyze the crash context. If the target needs restarting:
  - Use `execute_command("InitDebug")` to restart, or
  - Ask the user to restart the target if needed
  - Re-apply breakpoints and instrumentation

Repeat steps 4a–4f for each target until bugs are found or all targets are exhausted.

### 5. Proof-of-concept development (iterative)

For each confirmed bug, develop a PoC that demonstrates impact.

#### 5a. Design the PoC

Plan a PoC that demonstrates a meaningful impact:
- **Crash PoC** (minimum): input that reliably crashes the target
- **Info leak PoC**: input that causes the target to reveal memory contents
- **Code execution PoC**: input that achieves a small demonstration — e.g., spawning `calc.exe`, writing a marker file, or connecting back to a listener

Consider the target's mitigations:
- ASLR, DEP/NX, stack cookies, CFG — check with `get_memory_map` (look at page protections) and examine the binary's PE headers
- Adjust PoC strategy based on mitigations present

#### 5b. Write the PoC script

Write a Python PoC script to `./exploits/poc_<vuln_name>.py`. The script should:
- Be self-contained and well-commented
- Include a description of the vulnerability at the top
- Generate the exploit payload
- Deliver it to the target (network send, file write, etc.)
- Print status messages so the user can follow along

#### 5c. Test the PoC

1. Ensure the target is running and instrumented (breakpoints at key locations)
2. Run the PoC script via `Bash` (or ask the user to trigger it if manual interaction is required)
3. Observe the result in the debugger
4. If the PoC fails:
   - Analyze why (wrong offset, mitigation blocked it, timing issue, etc.)
   - Refine the payload and retry
   - If the target crashed, restart it (see step 4f)
5. If the PoC succeeds:
   - Document the full exploitation chain
   - Capture relevant register/memory state as evidence

Repeat steps 5a–5c until the PoC is reliable or the user decides to move on.

### 6. Report generation

Ask the user: "Would you like a markdown vulnerability report?"

If yes, read the report template at `/opt/x64dbg-skills-opencode/skills/vuln-hunter/report_template.md` and fill in every section based on findings. Write the completed report to `./reports/vuln_report_<timestamp>.md` via `Write`. Omit table rows or sections that have no findings, but preserve the overall structure.
