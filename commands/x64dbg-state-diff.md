---
description: Compare two state snapshots to identify register and memory changes between two points in time
---

# x64dbg-state-diff

Compare two debuggee state snapshots and produce a detailed change analysis — which registers changed, which memory regions were modified, and what the changes mean. This runs entirely offline on REMnux against snapshot directories produced by `/x64dbg-state-snapshot`.

## Instructions

Follow these steps exactly:

### 1. Identify snapshots

List the available snapshots:

```
ls -la ./snapshots
```

If there are fewer than two snapshots, tell the user they need at least two snapshots (captured via `/x64dbg-state-snapshot`) and stop.

If the user specified two snapshot paths, use those directly. Otherwise, present the available snapshots and ask the user to pick the **before** (earlier) and **after** (later) snapshots.

### 2. Run the diff script

Execute the diff engine via the bundled virtualenv Python:

```
/opt/x64dbg-automate-mcp-deps/bin/python3 /opt/x64dbg-skills-opencode/skills/state-diff/state_diff.py --before <before_snapshot_dir> --after <after_snapshot_dir>
```

The script writes `diff_report.json` into the after-snapshot directory by default. If the user specified a custom output path, pass `--output <path>`.

### 3. Read the report

Use `Read` to load the generated `diff_report.json`.

### 4. Analyze and reason

Interpret the diff report for the user:

- **Register changes**: Explain what each changed register suggests. For example:
  - RIP/EIP advanced → instructions were executed
  - RSP/ESP changed → stack grew or shrank (function calls, local variables)
  - RAX/EAX changed → likely a return value or computation result
  - Flag changes → comparison or arithmetic results

- **Memory changes**: Explain what modified regions likely represent:
  - Stack region modifications → local variables written, function arguments pushed
  - Heap regions → dynamic allocations or object mutations
  - Image/module regions → self-modifying code or relocations
  - Look at the actual byte patterns for clues (string data, pointers, counters)

- **Synthesize a narrative**: Combine register and memory observations into a coherent explanation of what the program did between the two snapshots. For example: "The program called function X, which allocated Y bytes on the stack and wrote a string to a heap buffer."

Present the analysis in a clear, structured format with the raw evidence (hex values, addresses) supporting each conclusion.
