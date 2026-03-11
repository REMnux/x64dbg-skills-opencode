---
name: find-oep
description: Smart trace-based OEP finder for packed/protected PE executables. Traces through packer stubs using intelligent stepping, anti-debug evasion, and heuristic OEP detection, then captures a state snapshot at the original entry point.
allowed-tools: mcp__x64dbg__list_sessions, mcp__x64dbg__start_session, mcp__x64dbg__connect_to_session, mcp__x64dbg__get_debugger_status, mcp__x64dbg__disconnect, mcp__x64dbg__allocate_memory, mcp__x64dbg__write_memory, mcp__x64dbg__read_memory, mcp__x64dbg__set_register, mcp__x64dbg__get_register, mcp__x64dbg__get_all_registers, mcp__x64dbg__disassemble, mcp__x64dbg__assemble, mcp__x64dbg__set_breakpoint, mcp__x64dbg__clear_breakpoint, mcp__x64dbg__list_breakpoints, mcp__x64dbg__step_over, mcp__x64dbg__step_into, mcp__x64dbg__go, mcp__x64dbg__pause, mcp__x64dbg__run_to_return, mcp__x64dbg__set_comment, mcp__x64dbg__set_label, mcp__x64dbg__get_symbol, mcp__x64dbg__eval_expression, mcp__x64dbg__execute_command, mcp__x64dbg__refresh_gui, mcp__x64dbg__get_memory_map, mcp__x64dbg__trace_over, mcp__x64dbg__trace_into, mcp__x64dbg__wait_for_event, AskUserQuestion, Bash, Read, Write, Skill
---

# find-oep

Smart trace-based OEP finder for packed/protected PE executables. Walks through unpacking stages using intelligent stepping, anti-debug evasion, and heuristic OEP detection. Once the OEP is found, captures a state snapshot for downstream use (PE reconstruction, analysis, etc.).

## Instructions

### 1. Gather input and assess target

Ask the user (via `AskUserQuestion`) for any information not already provided:

- **Target path** — absolute path to the packed PE on disk
- **x64dbg path** — absolute path to x64dbg/x32dbg (if not already known)
- **Bitness** — 64-bit or 32-bit (default: 64)

Determine the CIP register name: `rip` for 64-bit, `eip` for 32-bit.
Determine the stack pointer register: `rsp` for 64-bit, `esp` for 32-bit.
Determine the debugger variant: `x64dbg.exe` for 64-bit, `x32dbg.exe` for 32-bit.

### 2. Launch the debugger and load the target

Use `mcp__x64dbg__start_session` with:
- `executable_path`: the packed PE path
- `x64dbg_path`: the appropriate debugger binary

Always start a new session for a clean environment. Wait for the debugger to settle — call `mcp__x64dbg__get_debugger_status` and confirm the debuggee is paused at the entry point. If running, call `mcp__x64dbg__pause`.

Record the **session PID** and **x64dbg path** for later reconnection.

### 3. Initial reconnaissance

Gather information about the packed binary to inform the unpacking strategy:

1. **Capture entry state**: Call `mcp__x64dbg__get_all_registers` to record the initial register state (especially the stack pointer — packers often restore it before jumping to OEP).
2. **Memory map**: Call `mcp__x64dbg__get_memory_map` to identify the module's sections, their protections, and any suspicious characteristics (e.g., sections with write+execute, sections with zero raw size but large virtual size, non-standard section names).
3. **Entry point disassembly**: Disassemble 50–100 instructions from the entry point using `mcp__x64dbg__disassemble` to identify the packer stub pattern.
4. **YARA scan**: Invoke `/yara-sigs` via `Skill("yara-sigs")` to identify the packer and obvious crypto/anti-debug signatures.
   - You may rerun this YARA scan if the packer contains self-decrypting code that hides signatures until unpacked.

Summarize findings to the user:
- Identified packer (if recognized)
- Section layout and anomalies
- Entry stub characteristics
- Recommended unpacking strategy

### 4. Heuristic OEP discovery (core loop)

This is the main unpacking loop. The goal is to trace through the packer stub and identify when execution transfers to the original, unpacked code.

#### OEP Heuristics

The OEP is likely reached when several of these conditions align:

| Heuristic | Description |
|-----------|-------------|
| **Section transition** | CIP moves from a packer section (e.g., `.rsrc`, `.aspack`, last section) into the original code section (usually `.text` or the first section) |
| **Stack restoration** | ESP/RSP returns to (or near) its initial value from step 3 |
| **Common OEP patterns** | Disassembly shows typical compiler entry sequences: `push ebp; mov ebp, esp`, `sub rsp, N`, `call __security_init_cookie`, MSVC/GCC/Delphi/Borland CRT init patterns |
| **Large code region** | After writes settle, a large contiguous region of valid-looking code exists in the original code section |
| **IAT populated** | The import table region contains valid pointers to API functions |

#### Stepping strategy

1. **Start at the packed entry point**. Disassemble the current location.
2. **Identify the current phase**:
   - *Decode loop*: Repetitive instruction patterns (xor, mov byte, loop/dec+jnz). Set a breakpoint after the loop (on the first instruction following the loop exit) and `go`. If you cannot determine the loop exit, use `mcp__x64dbg__trace_over` with a `break_condition` that detects leaving the loop (e.g., a CIP range check).
   - *API resolution*: Calls to `GetProcAddress`, `LoadLibrary*`, hash-based API resolution. Step over these — they are building the IAT.
   - *Anti-debug check*: See step 6 for detection and evasion.
   - *Inter-module call*: Calls into system DLLs. Step over unless they appear suspicious.
   - *Tail jump / OEP transfer*: A `jmp` or `push+ret` that lands in a different section — potential OEP. Verify with the heuristics above.
   - *Multi-stage transition*: Decoded stub that itself decodes another layer. Repeat the process.

3. **When in a repetitive region** (same addresses appearing repeatedly):
   - Use `mcp__x64dbg__trace_over` with a `break_condition` like `cip < <loop_start> || cip > <loop_end>` to escape the loop efficiently.
   - Alternatively, identify the loop counter and set a conditional breakpoint: `mcp__x64dbg__set_breakpoint` with an appropriate condition.

4. **At each significant transition**, disassemble 20–30 instructions at the new location, check the memory section it belongs to, and evaluate the OEP heuristics.

5. **Label and comment** key addresses as you go: decode loop entries, API resolution routines, anti-debug checks, stage transitions, and the final OEP. Use `mcp__x64dbg__set_comment` and `mcp__x64dbg__set_label`.

### 5. Anti-debug detection and evasion

Packers frequently employ anti-debug techniques. When you encounter them, work around them to simulate non-debugged execution:

| Technique | Detection | Evasion |
|-----------|-----------|---------|
| **IsDebuggerPresent** | Call to `kernel32.IsDebuggerPresent` or direct PEB.BeingDebugged read | Step to the call, then set `eax`/`rax` to `0` after it returns (`mcp__x64dbg__set_register`) |
| **NtQueryInformationProcess** (DebugPort) | Call with class `0x7` | Step over the call, then zero the output buffer (`mcp__x64dbg__write_memory`) |
| **PEB.BeingDebugged** | Direct memory read of `fs:[30]+2` (x86) or `gs:[60]+2` (x64) | Write `0x00` to the BeingDebugged byte in the PEB (`mcp__x64dbg__write_memory`). Find PEB address via `mcp__x64dbg__eval_expression` with `peb()`. |
| **PEB.NtGlobalFlag** | Read of PEB+0x68 (x86) or PEB+0xBC (x64) | Write `0x00000000` to clear debug flags |
| **Heap flags** | PEB.ProcessHeap flags check | Patch the heap flags to remove debug indicators |
| **Timing checks** | `rdtsc`, `GetTickCount`, `QueryPerformanceCounter` | Step over the first call, note the result, step over the second, then patch the result to show minimal elapsed time |
| **Hardware breakpoint detection** | `GetThreadContext` / direct DR register reads | Clear debug registers before the check or patch the return values |
| **INT 2D / INT 3 tricks** | Exception-based anti-debug | Set the appropriate exception handler breakpoint and ensure execution continues as if no debugger is present |
| **Self-checksum** | CRC/hash of code regions (detects software breakpoints) | Use hardware breakpoints instead of software breakpoints in checksummed regions |

This list is not exhaustive. Always analyze the disassembly to understand the anti-debug technique being used and apply the appropriate evasion.

When you detect anti-debug behavior:
1. Inform the user what technique was found
2. Apply the evasion
3. Verify execution continues normally
4. Add a comment at the anti-debug location

**Proactive anti-debug setup**: At the start of unpacking, consider preemptively patching common PEB fields:
- Write `0x00` to PEB.BeingDebugged
- Write `0x00000000` to PEB.NtGlobalFlag
This can be done via `mcp__x64dbg__eval_expression` to find `peb()`, then `mcp__x64dbg__write_memory`.

### 6. Confirm OEP

When you believe you've reached the OEP:

1. **Disassemble** 50+ instructions and verify the code looks like a real program entry (not packer stub code).
2. **Check section**: Confirm CIP is in the expected code section (`.text` or first section).
3. **Check stack**: Compare ESP/RSP to the initial value from step 3.
4. **Check IAT**: Read a few pointers from the import section — they should point to valid API functions in loaded DLLs. Use `mcp__x64dbg__get_symbol` to verify.
5. **Inform the user** with:
   - The OEP address
   - The section it's in
   - A disassembly listing of the first ~30 instructions
   - Confidence level and reasoning

Ask the user via `AskUserQuestion`: "OEP found at `<address>`. Take a state snapshot?"

If the user says no or wants to adjust, continue stepping as directed.

### 7. Capture state snapshot

Invoke `/state-snapshot` via `Skill("state-snapshot")` to dump the full debuggee memory state at the OEP. Note the snapshot output directory.

Report the final results to the user:
- OEP address and section
- Packer identified
- Anti-debug techniques encountered and evaded
- Snapshot output directory
- The debugger session remains open — the user can continue analysis or chain with other skills

### 8. Refresh GUI

Always call `mcp__x64dbg__refresh_gui` as the final step.
