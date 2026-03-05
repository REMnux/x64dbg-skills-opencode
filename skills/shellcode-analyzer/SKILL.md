---
name: shellcode-analyzer
description: Load, unpack, and analyze shellcode in x64dbg. Use this skill when the user wants to analyze shellcode, load a shellcode blob into a debugger, unpack encoded/encrypted shellcode, or perform static/dynamic analysis of shellcode payloads.
allowed-tools: mcp__x64dbg__list_sessions, mcp__x64dbg__start_session, mcp__x64dbg__connect_to_session, mcp__x64dbg__get_debugger_status, mcp__x64dbg__allocate_memory, mcp__x64dbg__write_memory, mcp__x64dbg__read_memory, mcp__x64dbg__set_register, mcp__x64dbg__get_register, mcp__x64dbg__get_all_registers, mcp__x64dbg__disassemble, mcp__x64dbg__set_breakpoint, mcp__x64dbg__clear_breakpoint, mcp__x64dbg__list_breakpoints, mcp__x64dbg__step_over, mcp__x64dbg__step_into, mcp__x64dbg__go, mcp__x64dbg__pause, mcp__x64dbg__run_to_return, mcp__x64dbg__set_comment, mcp__x64dbg__set_label, mcp__x64dbg__get_symbol, mcp__x64dbg__eval_expression, mcp__x64dbg__execute_command, mcp__x64dbg__refresh_gui, mcp__x64dbg__get_memory_map, mcp__x64dbg__trace_over, mcp__x64dbg__trace_into, AskUserQuestion, Bash, Read, Write, Skill
---

# shellcode-analyzer

Load a raw shellcode blob into x64dbg using a sacrificial process, then optionally unpack, statically analyze, and dynamically analyze it.

## Instructions

### 1. Gather input

Ask the user (via `AskUserQuestion`) for:

- **Shellcode path** — absolute path to the raw shellcode file on disk
- **x64dbg path** — absolute path to the x64dbg/x32dbg binary (if not in memory)
- **Bitness** — 64-bit or 32-bit (default: 64, but one is not recommended over the other; it depends on the shellcode being analyzed)

Determine the CIP register name: `rip` for 64-bit, `eip` for 32-bit.
Determine the debugger variant: `x64dbg.exe` for 64-bit, `x32dbg.exe` for 32-bit.

### 2. Read the shellcode

Read the raw shellcode file as hex via Bash:

```
python -c "import sys; data=open(sys.argv[1],'rb').read(); print(data.hex())" "<shellcode_path>"
```

Capture the hex string and note the byte length (`len(hex_string) // 2`).

### 3. Launch the debugger

Use `mcp__x64dbg__start_session` with:
- `executable_path`: path to `timeout.exe` (typically `C:\Windows\System32\timeout.exe`)
- `x64dbg_path`: path to the appropriate x64dbg/x32dbg binary

Always start a new session, do not look for existing sessions. This ensures a clean environment and avoids conflicts with any active debugging sessions.

Note the **session PID** and **x64dbg path** from the result. Wait for the debugger to settle — call `mcp__x64dbg__get_debugger_status` and confirm the debuggee is paused. If running, call `mcp__x64dbg__pause`.

### 4. Allocate memory

Allocate a region at least one full page (0x1000 bytes) larger than the shellcode size. Attempt to use static allocation at 0x0000020000000000 for x64 or 0x20000000 for x32, but if that fails, allow the OS to choose the base. This makes it easier for the analyst to refer to addresses in the shellcode without needing to work with relative offsets.

Call `mcp__x64dbg__allocate_memory` with this size. Record the returned base address.

### 5. NOP sled (optional)

Some shellcodes require a NOP sled to function properly. The user should answer yes if they don't know.
Ask the user via `AskUserQuestion`: "Would you like a 32-byte NOP sled before the shellcode?"

If yes:
- Write 32 NOP bytes at the base address: call `mcp__x64dbg__write_memory` with `hex_data` = `"90"` repeated 32 times (`"9090909090909090909090909090909090909090909090909090909090909090"`)
- Set `shellcode_offset` = base address + 0x20 (32 bytes)
- Set `entry_point` = base address (start of NOP sled)

If no:
- Set `shellcode_offset` = base address
- Set `entry_point` = base address

### 6. Write shellcode to memory

Call `mcp__x64dbg__write_memory` with:
- `address`: the `shellcode_offset`
- `hex_data`: the hex string from step 2

### 7. Set CIP

Call `mcp__x64dbg__set_register` with:
- `register`: `rip` or `eip` (per bitness)
- `value`: the `entry_point` address

### 8. Unpacking assistance

Some shellcodes are obscured by a packer/crypter. Ask the user via `AskUserQuestion`: "Shellcode loaded. Do you need help unpacking it?"

If yes:

1. Disassemble from `entry_point` using `mcp__x64dbg__disassemble`
2. Analyze the disassembly for decryption/decompression patterns:
   - XOR loops, rolling keys, byte-by-byte transforms
   - Decompression routines (e.g., RtlDecompressBuffer calls)
   - Self-modifying code that writes to its own region
   - Multi-stage stubs that decode a payload then jump to it
      (It is possible no unpacking is required; if so, inform the user and skip to static analysis)
3. Summarize findings to the user
4. To execute the unpacking stub:
   - Identify where the decoder loop ends and the decoded payload begins (look for a jump or call after the loop)
   - Set a breakpoint at that transition point via `mcp__x64dbg__set_breakpoint`
   - Call `mcp__x64dbg__go` to run until the breakpoint hits
   - Confirm the debugger paused at the expected location
   - Disassemble the now-decoded shellcode for subsequent analysis steps

### 9. Static analysis

Ask the user via `AskUserQuestion`: "Would you like help statically analyzing the shellcode?"

If yes:

1. Disassemble the shellcode from `entry_point` (or decoded payload start if unpacked) using `mcp__x64dbg__disassemble`
2. Invoke `/yara-sigs` via `Skill("yara-sigs")` to scan for crypto, packers, and anti-debug signatures
   - When doing yara analysis, ONLY consider the shellcode region (not the entire memory space) to avoid noise
3. Analyze the combined results for:
   - **Import resolution** — PEB walking, LDR traversal, API hashing (e.g., ROR13, CRC32, DJB2)
   - **Anti-debug** — IsDebuggerPresent checks, NtQueryInformationProcess, timing checks, PEB.BeingDebugged
   - **Networking** — socket setup, connect/send/recv patterns, HTTP/DNS indicators
   - **Stagers** — VirtualAlloc + download + execute patterns
   - **Evasion** — syscall stubs, heaven's gate, indirect calls
   - **Novel behavior** — anything unusual or sophisticated
4. Add comments at key addresses via `mcp__x64dbg__set_comment` (import resolution, API calls, anti-debug, networking, control flow transitions)
5. Add labels at major blocks via `mcp__x64dbg__set_label` (e.g., `api_resolver`, `decode_loop`, `payload_entry`)
6. Summarize findings to the user

### 10. Dynamic analysis

Ask the user via `AskUserQuestion`: "Would you like help dynamically analyzing the shellcode?"

If yes:

Use the static analysis as a roadmap. Step/run through key sections of the shellcode to:

- **Resolve runtime values** — step through import resolution to discover which APIs are resolved (read resolved pointers from registers/stack after hash-lookup routines)
- **Confirm control flow** — verify branch decisions, loop counts, and conditional paths
- **Inspect payloads** — read decoded strings, URLs, C2 addresses, or embedded configs from memory via `mcp__x64dbg__read_memory`
- **Trace execution** — use `mcp__x64dbg__trace_over` or `mcp__x64dbg__trace_into` for targeted sections, or use `/tracealyzer` via `Skill("tracealyzer")` for deeper analysis

Use breakpoints strategically — set them at critical points (API calls, post-decode, network setup), run to them, inspect state, then continue. Avoid running the shellcode to completion; stop before any destructive or network-active payloads execute.

Summarize dynamic findings to the user, noting any insights that differ from or extend the static analysis. 

Refine static comments/labels based on dynamic insights.

### 11. Report Generation

Ask via `AskUserQuestion`: "Would you like a markdown report of the static analysis?" — if yes, read the template at `${CLAUDE_PLUGIN_ROOT}/skills/shellcode-analyzer/report_template.md` and fill in every section based on analysis findings. Write the completed report to `./reports/shellcode_analysis_<timestamp>.md` via `Write`. Omit table rows or sections that have no findings, but preserve the overall structure.

### 12. Refresh GUI

Always call `mcp__x64dbg__refresh_gui` as the final step.
