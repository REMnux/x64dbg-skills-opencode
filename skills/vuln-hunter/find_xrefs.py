"""Find IAT xrefs by searching for resolved API addresses in the IAT, then finding
code references to those IAT slots.

Usage: python find_xrefs.py <snapshot_dir> --base 0x400000 --functions lstrcpyA,CreateFileA
"""
import argparse, json, struct
from pathlib import Path


def load_region(snap, regions, addr):
    """Load the dump file containing `addr` and return (data, region_base)."""
    for r in regions:
        rb = int(r["base"], 16)
        rs = int(r["size"], 16)
        if rb <= addr < rb + rs and r.get("file"):
            return (snap / r["file"]).read_bytes(), rb
    return None, None


def main():
    parser = argparse.ArgumentParser(description="Find IAT xrefs from snapshot")
    parser.add_argument("snapshot_dir", help="State-snapshot directory")
    parser.add_argument("--base", default="0x400000", help="Module base (hex)")
    parser.add_argument("--functions", required=True, help="Comma-separated function names")
    parser.add_argument("--output", default="xrefs.json", help="JSON output")
    args = parser.parse_args()

    base = int(args.base, 16)
    snap = Path(args.snapshot_dir)
    target_funcs = [f.strip() for f in args.functions.split(",")]

    mmap = json.loads((snap / "memory_map.json").read_text())
    regions = mmap if isinstance(mmap, list) else mmap.get("regions", [])

    # Step 1: Find hint/name entries in .idata to get function_name -> hint_name_va
    idata_data, idata_base = load_region(snap, regions, base + 0x15B000)
    if not idata_data:
        print("ERROR: .idata region not found"); return

    idata_va = idata_base
    # Scan for ASCII strings (function names)
    name_to_va = {}  # function_name -> hint/name entry VA (the string start)
    i = 0
    while i < len(idata_data) - 2:
        end = idata_data.find(b'\x00', i)
        if end < 0: break
        s = idata_data[i:end]
        if len(s) >= 3 and all(32 <= b < 127 for b in s):
            name = s.decode('ascii')
            if '.dll' not in name.lower():
                va = idata_va + i
                # Multiple functions may have same name (from different DLLs)
                name_to_va.setdefault(name, []).append(va)
            i = end + 1
            # Align to 2-byte boundary (hint/name entries are word-aligned)
            if i % 2: i += 1
        else:
            i += 1

    # Step 2: For each hint/name entry, the VA of the 2-byte hint is (string_va - 2).
    # Search the .idata section for pointers to these hint/name entries.
    # These pointers form the OriginalFirstThunk (INT) or are embedded in the IAT region.
    # When we find a pointer to hint_entry_va (string_va - 2) in the INT area,
    # the corresponding IAT slot is at the same relative offset in the IAT.

    # Actually simpler: the IAT area contains RESOLVED addresses (pointers into DLLs).
    # We need to find those resolved addresses. We can get them from the loaded DLL exports.
    # But we don't have that in the snapshot easily.

    # Simplest approach: search for RVA pointers to hint/name entries in the .idata section.
    # A pointer to a hint/name entry is: (hint_name_va - base) as a 4-byte LE value,
    # because INT entries store RVAs.
    # But ASPack might store VAs instead of RVAs.

    # Let's try both: search for RVAs and VAs pointing to hint/name entries.
    # When we find such a pointer at offset X in a group, the IAT slot is at offset X
    # in the parallel IAT group (FirstThunk).

    # Actually, the most reliable approach for packed binaries:
    # Search the .idata IAT area for groups of 4-byte values separated by null dwords.
    # Each group corresponds to one DLL. The IAT slots are the addresses of these entries.
    # Map slot -> resolved_address, then resolve the address via DLL export tables.

    # For OUR purposes, we can use a hybrid: the INT (OriginalFirstThunk) entries
    # point to hint/name RVAs. Find INT entries, derive IAT slots from the parallel
    # FirstThunk, and match function names.

    # Search .idata for pointers that are RVAs to hint/name entries
    func_iat_slots = {}  # function_name -> list of IAT slot VAs
    idata_raw = idata_data

    for fname in target_funcs:
        if fname not in name_to_va:
            continue
        for str_va in name_to_va[fname]:
            hint_va = str_va - 2  # 2-byte hint precedes name
            hint_rva = hint_va - base
            # Search for this RVA (as 4-byte LE) in .idata
            rva_bytes = struct.pack('<I', hint_rva)
            pos = 0
            while True:
                idx = idata_raw.find(rva_bytes, pos)
                if idx < 0: break
                int_entry_va = idata_va + idx
                # This is an INT entry. Now we need to find the corresponding IAT slot.
                # The INT and IAT arrays are parallel. We need to find the import descriptor
                # that owns this INT entry to get the IAT base.
                # For now, just record the INT entry location
                func_iat_slots.setdefault(fname, []).append({
                    "int_entry_va": int_entry_va,
                })
                pos = idx + 1

    # Parse import descriptors to map INT entries to IAT slots
    # PE header
    pe_data, pe_base = load_region(snap, regions, base)
    if not pe_data:
        print("ERROR: PE header region not found"); return

    e_lfanew = struct.unpack_from('<I', pe_data, base - pe_base + 0x3C)[0]

    def read_u32_snap(addr):
        d, db = load_region(snap, regions, addr)
        if not d: return 0
        off = addr - db
        return struct.unpack_from('<I', d, off)[0] if off + 4 <= len(d) else 0

    opt_hdr = base + e_lfanew + 24
    import_dir_rva = read_u32_snap(opt_hdr + 104)
    import_dir_va = base + import_dir_rva

    # Build descriptor list: (oft_va, ft_va)
    descriptors = []
    desc_off = 0
    while True:
        desc = import_dir_va + desc_off
        oft_rva = read_u32_snap(desc)
        ft_rva = read_u32_snap(desc + 16)
        if oft_rva == 0 and ft_rva == 0:
            break
        # Check if these are RVAs or VAs (ASPack sometimes uses VAs)
        oft_va = oft_rva if oft_rva > base else base + oft_rva
        ft_va = ft_rva if ft_rva > base else base + ft_rva
        descriptors.append((oft_va, ft_va))
        desc_off += 20

    # For each INT entry found, find its descriptor and compute IAT slot
    resolved_slots = {}  # fname -> [iat_slot_va, ...]
    for fname, entries in func_iat_slots.items():
        for entry in entries:
            int_va = entry["int_entry_va"]
            for oft_va, ft_va in descriptors:
                # Check if int_va falls in this INT array
                offset = int_va - oft_va
                if 0 <= offset < 0x10000 and offset % 4 == 0:
                    iat_slot = ft_va + offset
                    resolved_slots.setdefault(fname, []).append(iat_slot)
                    break

    # Deduplicate
    for fname in resolved_slots:
        resolved_slots[fname] = sorted(set(resolved_slots[fname]))

    print("IAT slots:")
    for fname, slots in sorted(resolved_slots.items()):
        for s in slots:
            print(f"  {fname}: 0x{s:08X}")

    # Step 3: Search CODE section for references to IAT slots
    code_data, code_base = load_region(snap, regions, base + 0x1000)
    if not code_data:
        print("ERROR: CODE region not found"); return

    xrefs = {}
    for fname, slots in resolved_slots.items():
        for slot_va in slots:
            slot_bytes = struct.pack('<I', slot_va)
            pos = 0
            while True:
                idx = code_data.find(slot_bytes, pos)
                if idx < 0: break
                ref_va = code_base + idx
                # Determine instruction type
                itype = "ref"
                if idx >= 2:
                    pre = code_data[idx-2:idx]
                    if pre == b'\xFF\x15': itype = "call [IAT]"
                    elif pre == b'\xFF\x25': itype = "jmp [IAT]"
                    elif pre[0:1] == b'\xA1': itype = "mov eax, [IAT]"
                xrefs.setdefault(fname, []).append({
                    "address": f"0x{ref_va - (2 if itype.startswith(('call','jmp')) else 0):08X}",
                    "type": itype,
                    "iat_slot": f"0x{slot_va:08X}",
                })
                pos = idx + 1

    print(f"\nCross-references:")
    total = 0
    for fname, refs in sorted(xrefs.items()):
        print(f"\n  {fname} ({len(refs)} xrefs):")
        for r in refs:
            print(f"    {r['address']}  {r['type']}")
        total += len(refs)
    print(f"\nTotal: {total} xrefs")

    with open(args.output, "w") as fp:
        json.dump({"iat_slots": {k: [f"0x{s:08X}" for s in v] for k, v in resolved_slots.items()},
                    "xrefs": xrefs}, fp, indent=2)
    print(f"JSON written to: {args.output}")


if __name__ == "__main__":
    main()
