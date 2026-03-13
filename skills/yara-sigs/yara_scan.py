"""
Scan state-snapshot memory dumps with YARA rules from the yarasigs database.

Loads YARA rules by category, scans all .bin memory region files in a snapshot
directory, and outputs match results as JSON + human-readable summary.
"""

import argparse
import json
import sys
from pathlib import Path

import yara


# Rule category -> list of (glob pattern, base_dir) to search for .yar/.yara files
CATEGORY_MAP = {
    "packers": [
        ("packer.yara", "."),
        ("packer_compiler_signatures.yara", "."),
        ("Yara-Rules/packers/*.yar", "."),
        ("Yara-Rules/packers/*.yara", "."),
    ],
    "crypto": [
        ("crypto_signatures.yara", "."),
        ("Yara-Rules/crypto/*.yar", "."),
        ("Yara-Rules/crypto/*.yara", "."),
    ],
    "antidebug": [
        ("Yara-Rules/antidebug_antivm/*.yar", "."),
        ("Yara-Rules/antidebug_antivm/*.yara", "."),
    ],
    "all": [
        ("*.yar", "."),
        ("*.yara", "."),
        ("**/*.yar", "."),
        ("**/*.yara", "."),
    ],
}


def collect_rule_files(yarasigs_dir: Path, category: str) -> list[Path]:
    """Collect YARA rule file paths for the given category."""
    patterns = CATEGORY_MAP.get(category)
    if not patterns:
        print(f"[-] Unknown category: {category}", file=sys.stderr)
        print(f"    Valid categories: {', '.join(CATEGORY_MAP.keys())}", file=sys.stderr)
        sys.exit(1)

    seen = set()
    files = []
    for pattern, base in patterns:
        search_dir = yarasigs_dir / base if base != "." else yarasigs_dir
        for match in search_dir.glob(pattern):
            if match.is_file() and match.resolve() not in seen:
                seen.add(match.resolve())
                files.append(match)

    return sorted(files)


def compile_rules(rule_files: list[Path]) -> tuple[list[yara.Rules], list[str]]:
    """Compile YARA rules, skipping files that fail to compile."""
    compiled = []
    errors = []

    for rule_file in rule_files:
        try:
            rules = yara.compile(filepath=str(rule_file))
            compiled.append((rule_file.name, rules))
        except yara.SyntaxError as e:
            errors.append(f"{rule_file.name}: {e}")
        except yara.Error as e:
            errors.append(f"{rule_file.name}: {e}")

    return compiled, errors


def parse_bin_filename(filename: str) -> tuple[str, str] | None:
    """Parse a memory region filename like '00007FF6A0001000_1000.bin' -> (base, size)."""
    stem = Path(filename).stem
    parts = stem.split("_")
    if len(parts) == 2:
        return (f"0x{parts[0]}", f"0x{parts[1]}")
    return None


def _get_module_regions(memory_map: list[dict], module_filter: str) -> list[dict]:
    """Find all memory map entries belonging to a module (PE header + sections)."""
    # Find the base address of the target module
    module_bases = set()
    for entry in memory_map:
        info = entry.get("info", "")
        if module_filter.lower() in info.lower():
            module_bases.add(int(entry["base"], 16))
    if not module_bases:
        return []
    module_base = min(module_bases)
    # Include all contiguous regions from this module (PE header + sections)
    regions = []
    for entry in memory_map:
        entry_base = int(entry["base"], 16)
        info = entry.get("info", "")
        if entry_base >= module_base and (module_filter.lower() in info.lower() or info.startswith(' ".')):
            if entry_base < module_base + 0x10000000:  # reasonable max module size
                regions.append(entry)
    return regions


def _offset_to_region(offset: int, region_layout: list[tuple[int, int, dict]]) -> dict | None:
    """Map a byte offset within a merged buffer back to its source region."""
    for start, end, entry in region_layout:
        if start <= offset < end:
            return entry
    return None


def scan_snapshot(compiled_rules: list, snapshot_dir: Path, memory_map: list[dict], module_filter: str | None = None) -> list[dict]:
    """Scan memory regions against compiled YARA rules.

    When module_filter is set, all regions for that module are merged into a
    single contiguous buffer before scanning. This ensures cross-section YARA
    rules (e.g. MD5 init constants in .text + T-table in .rdata) can match.
    Without module_filter, each region .bin file is scanned independently.
    """
    # Build lookup from filename to memory map entry
    region_lookup = {}
    for entry in memory_map:
        if entry.get("file"):
            region_lookup[entry["file"]] = entry

    bin_files = sorted(snapshot_dir.glob("*.bin"))

    # --- Module-filtered mode: merge regions and scan as one buffer ---
    if module_filter:
        module_regions = _get_module_regions(memory_map, module_filter)
        module_files = {e.get("file") for e in module_regions}
        bin_files = [f for f in bin_files if f.name in module_files]

        if not bin_files:
            print(f"[-] No regions found for module '{module_filter}'", file=sys.stderr)
            return []

        module_base = min(int(e["base"], 16) for e in module_regions)
        print(f"[*] Module filter '{module_filter}': merging {len(bin_files)} regions (base 0x{module_base:X})")

        # Build merged buffer and a layout map for translating offsets back to regions
        merged = bytearray()
        region_layout = []  # list of (buf_start, buf_end, memory_map_entry)
        for bf in bin_files:
            data = bf.read_bytes()
            buf_start = len(merged)
            merged.extend(data)
            buf_end = len(merged)
            region_layout.append((buf_start, buf_end, region_lookup.get(bf.name, {})))

        merged_bytes = bytes(merged)
        total_size = len(merged_bytes)
        print(f"[*] Scanning merged buffer ({total_size:,} bytes)...")

        all_matches = []
        for rule_source, rules in compiled_rules:
            try:
                matches = rules.match(data=merged_bytes)
            except Exception:
                continue

            for match in matches:
                match_entry = {
                    "rule": match.rule,
                    "rule_source": rule_source,
                    "tags": list(match.tags),
                    "meta": {k: v for k, v in match.meta.items()} if match.meta else {},
                    "region_file": f"<merged:{module_filter}>",
                    "region_base": hex(module_base),
                    "region_size": hex(total_size),
                    "region_info": module_filter,
                    "region_protect": "",
                    "strings": [],
                }

                for string_match in match.strings:
                    for instance in string_match.instances:
                        src_region = _offset_to_region(instance.offset, region_layout)
                        src_info = src_region.get("info", "") if src_region else ""
                        match_entry["strings"].append({
                            "offset": hex(instance.offset),
                            "identifier": string_match.identifier,
                            "data_hex": instance.matched_data.hex(),
                            "data_ascii": instance.matched_data.decode("ascii", errors="replace")[:64],
                            "region": src_info,
                        })

                all_matches.append(match_entry)

        return all_matches

    # --- Standard mode: scan each region independently ---
    if not bin_files:
        print("[-] No .bin memory region files found in snapshot directory", file=sys.stderr)
        return []

    print(f"[*] Scanning {len(bin_files)} memory regions...")
    all_matches = []

    for bin_file in bin_files:
        data = bin_file.read_bytes()
        region_info = region_lookup.get(bin_file.name, {})
        parsed = parse_bin_filename(bin_file.name)

        for rule_source, rules in compiled_rules:
            try:
                matches = rules.match(data=data)
            except Exception:
                continue

            for match in matches:
                match_entry = {
                    "rule": match.rule,
                    "rule_source": rule_source,
                    "tags": list(match.tags),
                    "meta": {k: v for k, v in match.meta.items()} if match.meta else {},
                    "region_file": bin_file.name,
                    "region_base": parsed[0] if parsed else None,
                    "region_size": parsed[1] if parsed else None,
                    "region_info": region_info.get("info", ""),
                    "region_protect": region_info.get("protect", ""),
                    "strings": [],
                }

                for string_match in match.strings:
                    for instance in string_match.instances:
                        match_entry["strings"].append({
                            "offset": hex(instance.offset),
                            "identifier": string_match.identifier,
                            "data_hex": instance.matched_data.hex(),
                            "data_ascii": instance.matched_data.decode("ascii", errors="replace")[:64],
                        })

                all_matches.append(match_entry)

    return all_matches


def print_summary(matches: list[dict], compile_errors: list[str], rule_count: int, category: str):
    """Print a human-readable summary of scan results."""
    print(f"\n{'='*60}")
    print(f"YARA Scan Results — Category: {category}")
    print(f"{'='*60}")
    print(f"Rules loaded: {rule_count}")
    if compile_errors:
        print(f"Rules skipped (compile errors): {len(compile_errors)}")

    if not matches:
        print("\nNo matches found.")
        return

    # Group by rule
    by_rule = {}
    for m in matches:
        key = m["rule"]
        if key not in by_rule:
            by_rule[key] = {
                "rule_source": m["rule_source"],
                "tags": m["tags"],
                "meta": m["meta"],
                "regions": [],
            }
        by_rule[key]["regions"].append({
            "base": m["region_base"],
            "size": m["region_size"],
            "info": m["region_info"],
        })

    print(f"\nMatches: {len(matches)} hits across {len(by_rule)} rules\n")

    for rule_name, info in sorted(by_rule.items()):
        desc = info["meta"].get("description", info["meta"].get("info", ""))
        source = info["rule_source"]
        print(f"  [{rule_name}] ({source})")
        if desc:
            print(f"    Description: {desc}")
        if info["tags"]:
            print(f"    Tags: {', '.join(info['tags'])}")
        for region in info["regions"]:
            label = region["info"] or "unknown"
            print(f"    -> {region['base']} (size {region['size']}, {label})")
        print()


def main():
    # Ensure UTF-8 output on all platforms (Windows consoles default to locale codepage)
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')

    parser = argparse.ArgumentParser(description="Scan state snapshot memory with YARA rules")
    parser.add_argument("--snapshot-dir", required=True, help="Path to snapshot directory")
    parser.add_argument("--yarasigs-dir", required=True, help="Path to yarasigs repository")
    parser.add_argument("--categories", required=True, help="Rule category: packers, crypto, antidebug, all")
    parser.add_argument("--module-filter", default=None, help="Only scan regions belonging to this module (substring match on info field, e.g. 'secret_encryptor')")
    args = parser.parse_args()

    snapshot_dir = Path(args.snapshot_dir)
    yarasigs_dir = Path(args.yarasigs_dir)

    if not snapshot_dir.is_dir():
        print(f"[-] Snapshot directory not found: {snapshot_dir}", file=sys.stderr)
        sys.exit(1)
    if not yarasigs_dir.is_dir():
        print(f"[-] YARA signatures directory not found: {yarasigs_dir}", file=sys.stderr)
        sys.exit(1)

    # Load memory map for region metadata
    memory_map_path = snapshot_dir / "memory_map.json"
    memory_map = []
    if memory_map_path.exists():
        memory_map = json.loads(memory_map_path.read_text())

    # Collect and compile rules
    category = args.categories
    print(f"[*] Collecting YARA rules for category: {category}")
    rule_files = collect_rule_files(yarasigs_dir, category)
    print(f"[*] Found {len(rule_files)} rule files")

    if not rule_files:
        print("[-] No rule files found for this category", file=sys.stderr)
        sys.exit(1)

    print("[*] Compiling rules...")
    compiled, compile_errors = compile_rules(rule_files)
    print(f"[+] Compiled {len(compiled)} rule files successfully")
    if compile_errors:
        print(f"[!] {len(compile_errors)} files had compile errors (skipped):", file=sys.stderr)
        for err in compile_errors[:10]:
            print(f"    {err}", file=sys.stderr)
        if len(compile_errors) > 10:
            print(f"    ... and {len(compile_errors) - 10} more", file=sys.stderr)

    # Scan
    matches = scan_snapshot(compiled, snapshot_dir, memory_map, module_filter=args.module_filter)

    # Write JSON results
    results_path = snapshot_dir / "yara_results.json"
    results_data = {
        "category": category,
        "rules_loaded": len(compiled),
        "compile_errors": len(compile_errors),
        "total_matches": len(matches),
        "matches": matches,
    }
    results_path.write_text(json.dumps(results_data, indent=2))
    print(f"[+] Results written to {results_path}")

    # Print summary
    print_summary(matches, compile_errors, len(compiled), category)


if __name__ == "__main__":
    main()
