"""
Capture a full debuggee state snapshot (processor state + all committed memory regions).

Connects directly to a running x64dbg session via x64dbg_automate (ZMQ) and dumps:
  - registers.json: Full register dump (RegDump64/RegDump32 serialized via Pydantic)
  - memory_map.json: Manifest of all committed memory regions with metadata
  - <base>_<size>.bin: Raw memory contents for each committed region
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
    parser = argparse.ArgumentParser(description="Capture x64dbg debuggee state snapshot")
    parser.add_argument("--x64dbg-path", required=True, help="Path to x64dbg executable")
    parser.add_argument("--pid", required=True, type=int, help="PID of the x64dbg debugger process")
    parser.add_argument("--output-dir", default=None, help="Output directory (default: ./snapshots/<timestamp>)")
    args = parser.parse_args()

    output_dir = create_output_dir(args.output_dir)
    print(f"[*] Snapshot output directory: {output_dir.resolve()}")

    print(f"[*] Connecting to x64dbg session (PID {args.pid})...")
    client = X64DbgClient(args.x64dbg_path)
    client.attach_session(args.pid)
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
