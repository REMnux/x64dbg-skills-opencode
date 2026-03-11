# x64dbg-skills

Claude Code plugin providing skills for x64dbg debugger automation.

## Skills

### `/state-snapshot`

Captures a full debuggee state snapshot to disk for offline analysis:
- All committed memory regions as raw binary files
- Complete processor state (registers) as JSON

### `/state-diff`

Compares two state snapshots to identify what changed between two points in time:
- Register changes (instruction pointer advancement, stack movement, flags, etc.)
- Memory region modifications (stack writes, heap mutations, code changes)
- Synthesized narrative explaining what the program did between snapshots

### `/decompile`

Decompiles a function to C-like pseudocode using [angr](https://angr.io/):
- Decompiles the function at the current instruction pointer if no address is specified
- Accepts a specific address or symbol as an argument
- Tries multiple decompiler strategies for best results
- Suggests nearby functions if the specified address isn't a function entry

### `/yara-sigs`

Scans snapshot memory dumps with [YARA](https://virustotal.github.io/yara/) signatures from the [x64dbg yarasigs](https://github.com/x64dbg/yarasigs) database:
- Automatically clones the yarasigs repo (including Yara-Rules and citizenlab submodules) on first use
- Scan categories: **packers & compilers**, **crypto constants**, **anti-debug / anti-VM**, or **all signatures**
- Builds on `/state-snapshot` — uses an existing snapshot or takes a fresh one
- Reports matches grouped by rule with memory region addresses and metadata

### `/tracealyzer`

Traces execution (into or over calls) for N steps or until a condition is met, then analyzes the recorded instruction log:
- Configurable trace mode: step **into** calls or step **over** calls
- Stop on a max instruction count, an x64dbg expression (e.g. `cip == 0x401000`), or both
- Captures a full instruction log to `traces/` with addresses, disassembly, labels, and comments
- Summarizes execution flow, hot spots, API calls, loops, and notable patterns
- Follow-up actions: annotate key addresses in x64dbg, deeper sub-region analysis, deobfuscation

### `/shellcode-analyzer`

Loads, unpacks, and analyzes raw shellcode blobs in x64dbg:
- Launches x64dbg with `timeout.exe` as a sacrificial process (supports 32-bit and 64-bit)
- Allocates memory, writes shellcode, and redirects execution with optional NOP sled
- **Unpacking** — identifies and executes decoder stubs (XOR loops, decompression routines, self-modifying code)
- **Static analysis** — disassembly, YARA scanning (`/yara-sigs`), annotates key addresses with comments and labels
- **Dynamic analysis** — steps through import resolvers, inspects decoded payloads/strings/C2 configs
- Produces annotated shellcode in x64dbg and optional markdown reports

### `/find-oep`

Smart trace-based OEP finder for packed/protected PE executables:
- Traces through packer stubs using intelligent stepping, anti-debug evasion, and heuristic detection (section transitions, stack restoration, compiler entry patterns, IAT population)
- Handles common packers (UPX, ASPack, MPRESS, PECompact, Themida, VMProtect, Enigma) and unknown/custom packers
- Detects and evades anti-debug techniques: PEB flags, timing checks, hardware BP detection, exception tricks, self-checksums
- Leverages `/yara-sigs` for packer identification and `/state-snapshot` for memory capture at OEP
- Leaves the debugger paused at the OEP with a state snapshot for downstream analysis or PE reconstruction

### `/vuln-hunter`

Hunts for vulnerabilities in a running debuggee through systematic analysis:
- **Reconnaissance** — enumerates imports/exports, categorizes I/O functions by attack context (network, file, registry, etc.), and finds cross-references to dangerous sinks
- **Triage** — ranks code paths by attacker reachability and sink severity, presents a prioritized attack surface map
- **Bug hunting** — iteratively analyzes target functions for buffer overflows, integer wraps, format strings, logic flaws; generates test inputs and observes behavior under the debugger
- **PoC development** — builds proof-of-concept Python scripts that demonstrate impact (crash, info leak, code execution)
- Leverages `/decompile` for complex functions and `/tracealyzer` for execution tracing
- Produces annotated targets in x64dbg and optional markdown vulnerability reports

## Prerequisites

- [x64dbg](https://x64dbg.com/) and [x64dbg Automate](https://dariushoule.github.io/x64dbg-automate-pyclient/installation/) installed
- [x64dbg MCP server](https://dariushoule.github.io/x64dbg-automate-pyclient/mcp-server/) configured in Claude Code
- Python 3 with the `x64dbg_automate` pip package installed:
  ```
  pip install x64dbg_automate[mcp] --upgrade
  ```
- For the `/decompile` skill: [angr](https://pypi.org/project/angr/) (Python >= 3.10):
  ```
  pip install angr
  ```
- For the `/yara-sigs` skill: [yara-python](https://pypi.org/project/yara-python/) and [Git](https://git-scm.com/):
  ```
  pip install yara-python
  ```
- For the `/vuln-hunter` skill: [LIEF](https://lief-project.github.io/) for static PE analysis:
  ```
  pip install lief
  ```

## Installation

Add the marketplace and install the plugin:

```
/plugin marketplace add dariushoule/x64dbg-skills
/plugin install x64dbg-skills
```

## Updating

To update to the latest version:

```
/plugin install x64dbg-skills
```

## Usage

A decent guide that gives good ideas on how to use these skills: [Cooking with x64dbg and MCP](https://x64.ooo/posts/2026-02-12-cooking-with-x64dbg-and-mcp)

## License

MIT
