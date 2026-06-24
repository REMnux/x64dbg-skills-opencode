---
description: Decompile a function to C-like pseudocode using angr
---

# x64dbg-decompile

Decompile a function from the debugged binary into C-like pseudocode using angr (offline, on REMnux). The binary on disk is parsed by angr; the live remote debugger is used only to resolve the target address and module.

Optional argument: an address or symbol name to decompile — `$ARGUMENTS`. If empty, decompile the function containing the current instruction pointer.

These steps use the tools exposed by the `x64dbg` MCP server. Call them directly by name.

## Instructions

Follow these steps exactly:

### 1. Check prerequisites

Confirm angr is available in the bundled virtualenv via `Bash`:

```
/opt/x64dbg-automate-mcp-deps/bin/python3 -c "import angr; print(angr.__version__)"
```

If that fails, tell the user the `/opt/x64dbg-automate-mcp-deps` virtualenv is missing angr (it should be installed by the REMnux package; reinstall with `sudo /opt/x64dbg-automate-mcp-deps/bin/pip install angr`). Then stop.

### 2. Verify debugger connection

Call `get_debugger_status` to confirm the debugger is connected and paused. If not debugging, tell the user and stop.

### 3. Determine target function address

**If `$ARGUMENTS` is non-empty (an address or symbol):**
- If it looks like a hex address, use it directly
- If it looks like a symbol name, resolve it via `eval_expression`

**If `$ARGUMENTS` is empty:**
- Get the current instruction pointer via `get_register` (register `rip` for 64-bit, `eip` for 32-bit)
- Use the current RIP/EIP value as the target address

Call this resolved value `target_addr`.

### 4. Resolve module path and compute RVA

Use `eval_expression` to evaluate:
- `mod.path(target_addr)` — to get the on-disk path of the module containing the address
- `mod.base(target_addr)` — to get the module's base address

Compute the RVA: `target_addr - module_base`

If `mod.path` fails, the address may not belong to a loaded module. Tell the user and stop.

**Note (remote setup):** `mod.path` returns the module path *as seen on the Windows VM*. angr needs that binary readable on REMnux. If the sample is not already on the REMnux host, copy it over (or work against the local copy of the sample) and pass that path as `--binary` in the next step.

### 5. Run the decompile script

Execute via the bundled virtualenv Python:

```
/opt/x64dbg-automate-mcp-deps/bin/python3 /opt/x64dbg-skills-opencode/skills/decompile/decompile.py --binary "<module_path_on_remnux>" --address <rva_hex>
```

Where:
- `<module_path_on_remnux>` is the on-disk path to the binary readable on REMnux
- `<rva_hex>` is the RVA in hex (e.g. `0x1060`)

The script may take 10-30 seconds for large binaries (CFG generation is the bottleneck). Use a timeout of at least 120 seconds.

### 6. Present results

The script outputs decompiled C pseudocode to stdout and status messages to stderr.

Present the decompiled code to the user in a ```c code block. If the script failed, relay the error message from stderr (e.g., function not found, decompilation failed) and suggest nearby functions if listed.
