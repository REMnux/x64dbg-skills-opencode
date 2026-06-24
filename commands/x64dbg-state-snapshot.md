---
description: Capture a full debuggee state snapshot (all committed memory regions + processor state) from the remote x64dbg to disk on REMnux for offline analysis
---

# x64dbg-state-snapshot

Capture a full debuggee state snapshot — all committed memory regions as raw binary files plus the complete processor state as JSON. The debugger runs on a remote Windows VM; the snapshot script connects to it over the network and writes the dump to the REMnux working directory, where the offline analyzers (`/x64dbg-yara-sigs`, `/x64dbg-decompile`, `/x64dbg-state-diff`) then operate on it.

These steps use the tools exposed by the `x64dbg` MCP server. Call them directly by name.

## Instructions

Follow these steps exactly:

### 1. Verify debugger connection

Call `get_debugger_status` to confirm the debugger is connected and a debuggee is loaded. Note the **remote host** and the **REQ/REP and PUB/SUB ports** of the current connection (default `27066`/`27067`) — you will need them to reconnect later. If you do not know the host, ask the user for the Windows VM IP.

If no debuggee is loaded, tell the user and stop.

### 2. Pause the debuggee if running

If the debugger status shows the debuggee is running (not paused), call `pause` to pause it. Remember that you auto-paused so you can resume later.

### 3. Disconnect the MCP client

Call `disconnect` to release the ZMQ connection. This is **required** because only one client can be connected to an x64dbg session at a time, and the Python snapshot script needs its own connection.

### 4. Run the snapshot script

Execute the snapshot script via the bundled virtualenv Python (it connects to the remote x64dbg itself):

```
/opt/x64dbg-automate-mcp-deps/bin/python3 /opt/x64dbg-skills-opencode/skills/state-snapshot/state_snapshot.py --remote-host <windows_vm_ip> --req-port 27066 --pub-port 27067
```

Where `<windows_vm_ip>` is the remote host noted in step 1 (adjust the ports if non-default).

The script defaults output to `./snapshots/<timestamp>/` in the current working directory. If the user specified a custom output directory, pass `--output-dir <path>`.

### 5. Reconnect the MCP client

Call `connect_remote` with the **host** and **ports** saved from step 1 to restore the MCP connection to the same debuggee.

### 6. Report results

Summarize what was captured:
- Output directory path (on REMnux)
- Number of memory region files saved and total size
- Whether registers were captured successfully
- Any regions that failed to read
