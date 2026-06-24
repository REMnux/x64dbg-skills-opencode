---
description: Smart trace-based OEP finder for packed/protected PE executables. Traces through packer stubs using intelligent stepping, anti-debug evasion, and heuristic OEP detection, then captures a state snapshot at the original entry point.
---

# x64dbg-find-oep

Smart trace-based OEP finder for packed/protected PE executables. Walks through unpacking stages using intelligent stepping, anti-debug evasion, and heuristic OEP detection. Once the OEP is found, captures a state snapshot for downstream use (PE reconstruction, analysis, etc.).

These steps use the tools exposed by the `x64dbg` MCP server. Call them directly by name.

**Remote setup (REMnux → Windows VM):** OpenCode runs on REMnux and drives x64dbg on a separate Windows VM. You cannot launch the debugger from here. The user must have x64dbg running on the Windows VM with the packed PE already loaded and paused at the entry point. You connect to it with the `connect_remote` tool (host, REQ/REP `27066`, PUB/SUB `27067`).

## Instructions

### 1. Gather input and assess target

Ask the user for any information not already provided:

- **Windows VM host/IP** and ports (default `27066`/`27067`)
- **Target path** — path to the packed PE as loaded on the Windows VM
- **Bitness** — 64-bit or 32-bit (default: 64)

Determine the CIP register name: `rip` for 64-bit, `eip` for 32-bit.
Determine the stack pointer register: `rsp` for 64-bit, `esp` for 32-bit.

### 2. Connect to the remote debugger and confirm state

Call `connect_remote` with the host and ports from step 1 (if not already connected). Then call `get_debugger_status` and confirm the debuggee is loaded and paused at the entry point. If running, call `pause`. If no debuggee is loaded, ask the user to open the packed PE in x64dbg on the Windows VM, then retry.

Record the **host** and **ports** for later reconnection (the snapshot step needs them).

### 3. Initial reconnaissance

Gather information about the packed binary to inform the unpacking strategy:

1. **Capture entry state**: Call `get_all_registers` to record the initial register state (especially the stack pointer — packers often restore it before jumping to OEP).
2. **Memory map**: Call `get_memory_map` to identify the module's sections, their protections, and any suspicious characteristics (e.g., sections with write+execute, sections with zero raw size but large virtual size, non-standard section names).
3. **Entry point disassembly**: Disassemble 50–100 instructions from the entry point using `disassemble` to identify the packer stub pattern.
4. **YARA scan**: Run `/x64dbg-yara-sigs` to identify the packer and obvious crypto/anti-debug signatures.
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
   - *Decode loop*: Repetitive instruction patterns (xor, mov byte, loop/dec+jnz). Set a breakpoint after the loop (on the first instruction following the loop exit) and `go`. If you cannot determine the loop exit, use `trace_over` with a `break_condition` that detects leaving the loop (e.g., a CIP range check).
   - *API resolution*: Calls to `GetProcAddress`, `LoadLibrary*`, hash-based API resolution. Step over these — they are building the IAT.
   - *Anti-debug check*: See step 5 for detection and evasion.
   - *Inter-module call*: Calls into system DLLs. Step over unless they appear suspicious.
   - *Tail jump / OEP transfer*: A `jmp` or `push+ret` that lands in a different section — potential OEP. Verify with the heuristics above.
   - *Multi-stage transition*: Decoded stub that itself decodes another layer. Repeat the process.

3. **When in a repetitive region** (same addresses appearing repeatedly):
   - Use `trace_over` with a `break_condition` like `cip < <loop_start> || cip > <loop_end>` to escape the loop efficiently.
   - Alternatively, identify the loop counter and set a conditional breakpoint: `set_breakpoint` with an appropriate condition.

4. **At each significant transition**, disassemble 20–30 instructions at the new location, check the memory section it belongs to, and evaluate the OEP heuristics.

5. **Label and comment** key addresses as you go: decode loop entries, API resolution routines, anti-debug checks, stage transitions, and the final OEP. Use `set_comment` and `set_label`.

### 5. Anti-debug detection and evasion

Packers frequently employ anti-debug techniques. When you encounter them, work around them to simulate non-debugged execution:

| Technique | Detection | Evasion |
|-----------|-----------|---------|
| **IsDebuggerPresent** | Call to `kernel32.IsDebuggerPresent` or direct PEB.BeingDebugged read | Step to the call, then set `eax`/`rax` to `0` after it returns (`set_register`) |
| **NtQueryInformationProcess** (DebugPort) | Call with class `0x7` | Step over the call, then zero the output buffer (`write_memory`) |
| **PEB.BeingDebugged** | Direct memory read of `fs:[30]+2` (x86) or `gs:[60]+2` (x64) | Write `0x00` to the BeingDebugged byte in the PEB (`write_memory`). Find PEB address via `eval_expression` with `peb()`. |
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
This can be done via `eval_expression` to find `peb()`, then `write_memory`.

### 6. Confirm OEP

When you believe you've reached the OEP:

1. **Disassemble** 50+ instructions and verify the code looks like a real program entry (not packer stub code).
2. **Check section**: Confirm CIP is in the expected code section (`.text` or first section).
3. **Check stack**: Compare ESP/RSP to the initial value from step 3.
4. **Check IAT**: Read a few pointers from the import section — they should point to valid API functions in loaded DLLs. Use `get_symbol` to verify.
5. **Inform the user** with:
   - The OEP address
   - The section it's in
   - A disassembly listing of the first ~30 instructions
   - Confidence level and reasoning

Ask the user: "OEP found at `<address>`. Take a state snapshot?"

If the user says no or wants to adjust, continue stepping as directed.

### 7. Capture state snapshot

Capture the full debuggee state at the OEP onto REMnux with the bundled snapshot script. The script reads every committed memory region over the network and writes the dump to REMnux, so nothing has to be copied off the Windows VM afterward. Because only one client can be connected to the remote x64dbg at a time, disconnect the MCP client first and reconnect after:

1. **Disconnect the MCP client**: call `disconnect` to free the ZMQ connection for the snapshot script.
2. **Run the snapshot script** via the bundled virtualenv Python, using the host and ports recorded in step 2:

   ```
   /opt/x64dbg-automate-mcp-deps/bin/python3 /opt/x64dbg-skills-opencode/skills/state-snapshot/state_snapshot.py --remote-host <windows_vm_ip> --req-port 27066 --pub-port 27067
   ```

   The dump lands in `./snapshots/<timestamp>/` on REMnux (pass `--output-dir <path>` to override).
3. **Reconnect the MCP client**: call `connect_remote` with the host and ports from step 2 to restore the session to the same debuggee.

Note the snapshot output directory on REMnux.

Report the final results to the user:
- OEP address and section
- Packer identified
- Anti-debug techniques encountered and evaded
- Snapshot output directory
- The debugger session remains open — the user can continue analysis or chain with other commands

### 8. Refresh GUI

Always call `refresh_gui` as the final step.
