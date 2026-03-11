"""Enumerate PE imports, exports, and security features using LIEF.

Supports two modes:
  1. On-disk PE:       python enum_imports.py <pe_path>
  2. Memory snapshot:  python enum_imports.py <pe_path> --snapshot-dir <dir> --base 0x400000

Mode 2 manually parses the PE import directory from snapshot dump files,
which is necessary for packed binaries whose on-disk IAT is just a packer stub.
"""
import argparse, json, struct, sys
from pathlib import Path

try:
    import lief
except ImportError:
    print("ERROR: lief is required. Install with: pip install lief", file=sys.stderr)
    sys.exit(1)


class SnapshotMemory:
    """Provides random-access reads over a state-snapshot's memory dump files."""

    def __init__(self, snapshot_dir):
        snapshot_dir = Path(snapshot_dir)
        map_path = snapshot_dir / "memory_map.json"
        if not map_path.exists():
            raise FileNotFoundError(f"No memory_map.json in {snapshot_dir}")

        raw = json.loads(map_path.read_text())
        regions = raw if isinstance(raw, list) else raw.get("regions", [])

        self.segments = []
        for r in regions:
            base = int(r["base"], 16)
            size = int(r["size"], 16)
            fpath = snapshot_dir / r["file"] if r.get("file") else None
            if fpath and fpath.exists():
                self.segments.append((base, size, fpath))
        self.segments.sort(key=lambda s: s[0])

    def read(self, addr, size):
        """Read `size` bytes from virtual address `addr`."""
        result = bytearray()
        remaining = size
        cur = addr
        for seg_base, seg_size, seg_path in self.segments:
            if cur >= seg_base + seg_size or cur + remaining <= seg_base:
                continue
            offset_in_seg = cur - seg_base
            if offset_in_seg < 0:
                # cur is before this segment, skip gap
                gap = seg_base - cur
                result.extend(b'\x00' * min(gap, remaining))
                remaining -= gap
                cur += gap
                offset_in_seg = 0
            avail = min(seg_size - offset_in_seg, remaining)
            data = seg_path.read_bytes()
            result.extend(data[offset_in_seg:offset_in_seg + avail])
            remaining -= avail
            cur += avail
            if remaining <= 0:
                break
        # Pad any remaining
        if remaining > 0:
            result.extend(b'\x00' * remaining)
        return bytes(result[:size])

    def read_u32(self, addr):
        d = self.read(addr, 4)
        return struct.unpack('<I', d)[0]

    def read_cstring(self, addr, max_len=256):
        d = self.read(addr, max_len)
        end = d.find(b'\x00')
        return d[:end].decode('ascii', errors='replace') if end >= 0 else d.decode('ascii', errors='replace')


def parse_imports_from_snapshot(mem, base):
    """Parse PE import directory from in-memory snapshot."""
    e_lfanew = mem.read_u32(base + 0x3C)
    pe_sig = base + e_lfanew
    opt_hdr = pe_sig + 24
    import_dir_rva = mem.read_u32(opt_hdr + 104)

    if import_dir_rva == 0:
        return {}

    import_dir_va = base + import_dir_rva
    imports = {}
    desc_off = 0

    while True:
        desc = import_dir_va + desc_off
        oft_rva = mem.read_u32(desc)
        name_rva = mem.read_u32(desc + 12)
        ft_rva = mem.read_u32(desc + 16)

        if oft_rva == 0 and name_rva == 0 and ft_rva == 0:
            break

        dll_name = mem.read_cstring(base + name_rva) if name_rva else "unknown"

        funcs = []
        hint_base = base + (oft_rva if oft_rva else ft_rva)
        idx = 0
        while True:
            hint_entry = mem.read_u32(hint_base + idx * 4)
            if hint_entry == 0:
                break
            if hint_entry & 0x80000000:
                funcs.append(f"ord_{hint_entry & 0xFFFF}")
            else:
                func_name = mem.read_cstring(base + hint_entry + 2)
                funcs.append(func_name if func_name else f"unknown_{idx}")
            idx += 1

        imports[dll_name] = funcs
        desc_off += 20

    return imports


def parse_pe_disk(pe_path):
    """Parse imports, exports, security from on-disk PE via LIEF."""
    binary = lief.parse(pe_path)
    if binary is None:
        print(f"ERROR: Failed to parse {pe_path}", file=sys.stderr)
        sys.exit(1)

    imports = {}
    if binary.has_imports:
        for imp in binary.imports:
            funcs = []
            for entry in imp.entries:
                name = entry.name if entry.name else f"ord_{entry.data & 0xFFFF}"
                funcs.append(name)
            imports[imp.name] = funcs

    exports = []
    if binary.has_exports:
        for entry in binary.get_export().entries:
            exports.append({
                "name": entry.name if entry.name else f"ord_{entry.ordinal}",
                "ordinal": entry.ordinal,
                "rva": f"0x{entry.address:X}",
            })

    dll_chars = binary.optional_header.dll_characteristics
    security = {
        "aslr": bool(dll_chars & 0x0040),
        "dep_nx": bool(dll_chars & 0x0100),
        "cfg": bool(dll_chars & 0x4000),
        "high_entropy_aslr": bool(dll_chars & 0x0020),
        "no_seh": bool(dll_chars & 0x0400),
    }

    return imports, exports, security


def main():
    parser = argparse.ArgumentParser(description="Enumerate PE imports/exports")
    parser.add_argument("pe_path", help="Path to the PE file on disk")
    parser.add_argument("--snapshot-dir", default=None,
                        help="State-snapshot directory (for packed/in-memory IAT)")
    parser.add_argument("--base", default="0x400000",
                        help="Module base address (hex, used with --snapshot-dir)")
    parser.add_argument("--output", default="imports.json", help="JSON output path")
    args = parser.parse_args()

    # Always get security info and exports from on-disk PE
    _, exports, security = parse_pe_disk(args.pe_path)

    if args.snapshot_dir:
        base = int(args.base, 16)
        mem = SnapshotMemory(args.snapshot_dir)
        imports = parse_imports_from_snapshot(mem, base)
        source = f"snapshot:{args.snapshot_dir} (base {args.base})"
    else:
        imports, _, _ = parse_pe_disk(args.pe_path)
        source = f"disk:{args.pe_path}"

    result = {
        "file": args.pe_path,
        "source": source,
        "security": security,
        "imports": imports,
        "exports": exports,
    }

    with open(args.output, "w") as fp:
        json.dump(result, fp, indent=2)

    total_imports = sum(len(v) for v in imports.values())
    print(f"Parsed: {source}")
    print(f"DLLs: {len(imports)}  |  Total imports: {total_imports}  |  Exports: {len(exports)}")
    print(f"\nSecurity: {json.dumps(security)}")

    for dll, funcs in imports.items():
        print(f"\n=== {dll} ({len(funcs)}) ===")
        for f in funcs:
            print(f"  {f}")

    if exports:
        print(f"\n=== Exports ({len(exports)}) ===")
        for e in exports:
            print(f"  {e['rva']:>10s}  {e['name']}")

    print(f"\nJSON written to: {args.output}")


if __name__ == "__main__":
    main()
