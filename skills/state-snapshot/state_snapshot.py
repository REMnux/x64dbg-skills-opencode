"""
Capture a full debuggee state snapshot (processor state + all committed memory regions).

Connects to a REMOTE x64dbg session via x64dbg_automate (ZMQ) and dumps:
  - registers.json: Full register dump (RegDump64/RegDump32 serialized via Pydantic)
  - memory_map.json: Manifest of all committed memory regions with metadata
  - <base>_<size>.bin: Raw memory contents for each committed region

REMnux/OpenCode port (REMnux x64dbg-skills-opencode): the upstream script attached to a
local x64dbg by PID, which only works when the debugger and this script run on the same
machine. This variant connects to x64dbg running on a separate Windows VM whose
x64dbg-automate plugin is in Remote mode, so the debuggee's memory is pulled over the
network onto the REMnux host for offline analysis. Connection setup is the only change;
the capture logic is unchanged. detach_session() simply closes the ZMQ sockets and leaves
the remote debugger running.
"""

import argparse
import json
import time
from pathlib import Path
from typing import Any

from x64dbg_automate import X64DbgClient


def _convert_bytes_to_hex(obj: Any) -> Any:
    """Recursively convert bytes values to hex strings for JSON serialization."""
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {k: _convert_bytes_to_hex(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_convert_bytes_to_hex(v) for v in obj]
    return obj


def create_output_dir(output_dir: str | None) -> Path:
    if output_dir:
        path = Path(output_dir)
    else:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        path = Path("snapshots") / timestamp
    path.mkdir(parents=True, exist_ok=True)
    return path


def snapshot_registers(client: X64DbgClient, output_dir: Path) -> dict:
    regs = client.get_regs()
    bitness = 64 if hasattr(regs.context, "rax") else 32
    data = {
        "bitness": bitness,
        "registers": _convert_bytes_to_hex(regs.model_dump()),
    }
    reg_path = output_dir / "registers.json"
    reg_path.write_text(json.dumps(data, indent=2))
    print(f"[+] Saved registers ({bitness}-bit) -> {reg_path}")
    return data


def snapshot_memory(client: X64DbgClient, output_dir: Path) -> list[dict]:
    MEM_COMMIT = 0x1000

    pages = client.memmap()
    committed = [p for p in pages if p.state == MEM_COMMIT]
    print(f"[*] Memory map: {len(pages)} total regions, {len(committed)} committed")

    manifest = []
    saved_count = 0
    total_bytes = 0

    for page in committed:
        entry = {
            "base": hex(page.base_address),
            "size": hex(page.region_size),
            "protect": hex(page.protect),
            "type": hex(page.type),
            "info": page.info,
            "file": None,
            "read_ok": False,
        }

        filename = f"{page.base_address:016X}_{page.region_size:X}.bin"
        try:
            data = client.read_memory(page.base_address, page.region_size)
            (output_dir / filename).write_bytes(data)
            entry["file"] = filename
            entry["read_ok"] = True
            saved_count += 1
            total_bytes += len(data)
        except Exception as e:
            entry["error"] = str(e)

        manifest.append(entry)

    manifest_path = output_dir / "memory_map.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"[+] Saved {saved_count}/{len(committed)} memory regions ({total_bytes:,} bytes) -> {output_dir}")
    print(f"[+] Memory map manifest -> {manifest_path}")
    return manifest


def main():
    parser = argparse.ArgumentParser(
        description="Capture an x64dbg debuggee state snapshot from a remote x64dbg session"
    )
    parser.add_argument("--remote-host", required=True,
                        help="Host/IP of the Windows VM running x64dbg with the automate plugin in Remote mode")
    parser.add_argument("--req-port", type=int, default=27066,
                        help="ZMQ REQ/REP port the plugin listens on (default: 27066)")
    parser.add_argument("--pub-port", type=int, default=27067,
                        help="ZMQ PUB/SUB port the plugin listens on (default: 27067)")
    parser.add_argument("--output-dir", default=None,
                        help="Output directory (default: ./snapshots/<timestamp>)")
    args = parser.parse_args()

    output_dir = create_output_dir(args.output_dir)
    print(f"[*] Snapshot output directory: {output_dir.resolve()}")

    print(f"[*] Connecting to remote x64dbg at {args.remote_host} "
          f"(REQ/REP {args.req_port}, PUB/SUB {args.pub_port})...")
    client = X64DbgClient.connect_remote(args.remote_host, args.req_port, args.pub_port)
    print("[+] Connected")

    try:
        snapshot_registers(client, output_dir)
        snapshot_memory(client, output_dir)
    finally:
        client.detach_session()
        print("[+] Disconnected from x64dbg session")

    print("[+] Snapshot complete")


if __name__ == "__main__":
    main()
