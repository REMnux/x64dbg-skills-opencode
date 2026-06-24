---
description: Scan a state snapshot's memory dumps with YARA signatures to detect packers, crypto constants, malware, and more
---

# x64dbg-yara-sigs

Scan debuggee memory (via a state snapshot) against a large YARA signature database to identify packers, crypto constants, anti-debug tricks, malware families, and more. This runs offline on REMnux against a snapshot directory produced by `/x64dbg-state-snapshot`.

These steps use the tools exposed by the `x64dbg` MCP server. Call them directly by name.

## Instructions

Follow these steps exactly:

### 1. Check prerequisites

Confirm yara-python is available in the bundled virtualenv via `Bash`:

```
/opt/x64dbg-automate-mcp-deps/bin/python3 -c "import yara; print(yara.__version__)"
```

If that fails, tell the user the `/opt/x64dbg-automate-mcp-deps` virtualenv is missing yara-python and stop.

### 2. Ensure the YARA signature database is available

The signature database ships with the REMnux package at `/opt/x64dbg-skills-opencode/yarasigs`. Confirm it exists:

```
ls /opt/x64dbg-skills-opencode/yarasigs
```

If the directory is missing or empty (no `Yara-Rules` or `citizenlab` subdirectories), the package did not clone it correctly — tell the user to reinstall the `x64dbg-automate-mcp` package and stop. (Do not try to clone into `/opt` yourself; it is root-owned.)

### 3. Determine what to scan for

The YARA database contains many rule categories. If the user specified what they want to scan for in their invocation, use that. Otherwise, ask the user what they want to scan for, offering these options:

- **Packers & compilers** — Detect packers (UPX, Themida, etc.) and compiler signatures
- **Crypto constants** — Find cryptographic algorithm constants (AES S-boxes, RSA, MD5, etc.)
- **Anti-debug / anti-VM** — Detect anti-debugging and anti-virtualization techniques
- **All signatures** — Scan with every available rule (slower, more noise)

Map the selection to the script's `--categories` value: `packers`, `crypto`, `antidebug`, or `all`.

### 4. Obtain a snapshot to scan

Check if a recent snapshot exists in `./snapshots` (use `ls`).

- If snapshots exist, ask the user whether to use an existing snapshot or take a fresh one.
- If no snapshots exist, tell the user you need to take a snapshot first.

To take a fresh snapshot, run the `/x64dbg-state-snapshot` command. After it completes, note the snapshot directory path.

### 5. Run the YARA scan

Execute the scan script via the bundled virtualenv Python:

```
/opt/x64dbg-automate-mcp-deps/bin/python3 /opt/x64dbg-skills-opencode/skills/yara-sigs/yara_scan.py --snapshot-dir <snapshot_path> --yarasigs-dir /opt/x64dbg-skills-opencode/yarasigs --categories <category> [--module-filter <module_name>]
```

Where `<category>` is one of: `packers`, `crypto`, `antidebug`, or `all`.

**Module filtering:** If the user asks to focus on a specific module (e.g. the main executable), pass `--module-filter <name>` where `<name>` is a substring of the module name as shown in the memory map (e.g. `secret_encryptor`). This merges all of the module's sections into a single buffer before scanning, which is critical for YARA rules whose patterns span multiple PE sections (e.g. MD5 init constants in `.text` + T-table in `.rdata`). **Always prefer using `--module-filter` when scanning a specific module** rather than relying on per-region scanning.

The script writes results to `<snapshot_path>/yara_results.json` and prints a summary to stdout.

### 6. Report results

Read `<snapshot_path>/yara_results.json` if it exists and the stdout summary is not sufficient.

Present findings organized by:
- **Match summary** — How many rules matched across how many memory regions
- **Matches by rule** — Each matched rule name, its description/metadata, and which memory regions it hit (with base addresses and region info from `memory_map.json`)
- **Notable findings** — Call out anything especially interesting (known packers, specific crypto algorithms, anti-debug patterns)

If no matches were found, tell the user and suggest trying a broader category (e.g., "all").
