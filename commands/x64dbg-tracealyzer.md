---
description: Trace execution (into or over calls) for N steps or until a condition, then analyze the recorded instruction log
---

# x64dbg-tracealyzer

Trace debuggee execution — stepping into or over calls — for a specified number of instructions or until a condition is met. The full instruction log is captured to a file and then analyzed.

These steps use the tools exposed by the `x64dbg` MCP server (e.g. `get_debugger_status`, `trace_into`, `disassemble`). Call them directly by name. The debugger runs on a remote Windows VM; if the server is not connected yet, connect first with the `connect_remote` tool (host, REQ/REP port `27066`, PUB/SUB port `27067`).

## Instructions

Follow these steps exactly:

### 1. Verify debugger connection

Call `get_debugger_status` to confirm the debugger is connected and a debuggee is loaded and **paused**. If it is running, call `pause`. If no debuggee is loaded, tell the user and stop.

### 2. Gather trace parameters

Ask the user for the following if not already provided:

- **Trace mode**: trace *into* calls or trace *over* calls (default: over)
- **Stop condition** — one of:
  - A maximum number of instructions (e.g. `1000`)
  - An x64dbg expression that stops when true (e.g. `cip == 0x7FF6A0001000`, `rax != 0`)
  - Both (whichever triggers first)

If the user provides a symbol or address for the stop condition, resolve it with `eval_expression` and build the `break_condition` expression (e.g. `cip == <resolved_addr>`).

When the user only specifies a step count N and no explicit break condition, use break_condition `0` (never true — the trace runs until max_steps is hit).

### 3. Capture starting context

Call `get_all_registers` and `disassemble` at the current instruction pointer to record the starting state. Note the starting address.

### 4. Run the trace

Prepare the output log path: `./traces/trace_<timestamp>.log` (create the `traces` directory if it doesn't exist via `Bash`).

Call the appropriate trace tool (`trace_into` or `trace_over`) with:

| Parameter | Value |
|-----------|-------|
| `break_condition` | The user's condition, or `0` if only a step count was given |
| `max_steps` | The user's step count, or `50000` if only a condition was given |
| `log_text` | `{p:cip} {i:cip} | Label={label@cip} Comment={comment@cip}` |
| `log_file` | The output log path from above |
| `wait_timeout` | Scale with max_steps — use `max(60, max_steps // 500)` seconds |

### 5. Read and analyze the trace log

Read the trace log file. The log contains one line per executed instruction in the format:

```
<address> <disassembly> | Label=<label> Comment=<comment>
```

*Ignore when Labels or Comments say `[Formatting Error]`, it just means there is no label or comment at that instruction.*

Analyze the trace and present a summary to the user:

- **Trace overview**: total instructions executed, start address → end address, trace mode used
- **Execution flow**: describe the high-level behavior — what the code did, which functions were called, loops observed, and notable control-flow patterns
- **Hot spots**: addresses or regions that appear most frequently (loops, repeated calls)
- **Key observations**: interesting register manipulations, memory accesses, syscalls, API calls, string operations, or anything else that stands out

Use `get_symbol` to resolve notable addresses to symbol names where possible.

If the trace log is very large (>2000 lines), read it in chunks and summarize progressively.

### 6. Follow-up actions

After presenting the summary, ask the user if they would like any follow-up actions such as:

- **Annotate**: add comments/labels in x64dbg at key addresses using `set_comment` / `set_label`
- **Deeper analysis**: re-trace a specific sub-region, or focus on a particular function
- **Deobfuscation**: identify and explain obfuscated patterns found in the trace
- **Export**: the trace log is already saved to disk at the path from step 4
