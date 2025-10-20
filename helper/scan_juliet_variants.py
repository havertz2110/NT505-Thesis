#!/usr/bin/env python3
"""
Scan Juliet testcases to summarize sNN subsets and their dominant variant patterns.

Usage:
  python helper/scan_juliet_variants.py [root]

Defaults to dataset/juliet-dynamic-master/testcases as root.
"""

import os
import re
import sys
from collections import Counter, defaultdict


def find_cwe_dirs(root):
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        if not os.path.isdir(path):
            continue
        if not name.startswith("CWE"):
            continue
        # sNN subdirectories
        sdirs = [d for d in os.listdir(path) if re.fullmatch(r"s\d{2}", d)]
        if sdirs:
            yield name, path, sorted(sdirs)


def extract_variant_from_filename(fname):
    # Expect names like: CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01.c
    # or CWE121_...__CWE193_char_alloca_loop_53d.c, CWE121_...__connect_socket_51a.c
    # Return the variant stem (e.g., 'char_type_overrun_memcpy', 'CWE193_char_alloca_loop', 'connect_socket')
    base = os.path.splitext(fname)[0]
    if "__" not in base:
        return None
    trailing = base.split("__", 1)[1]

    parts = trailing.split("_")
    if not parts:
        return None

    # Remove trailing suffix tokens: numeric (01, 10), numeric+letter (51a),
    # and status markers (bad/good/goodG2B/goodB2G/good1/good2)
    status = {"bad", "good", "good1", "good2", "goodG2B", "goodB2G", "goodG2B1", "goodB2G1"}
    while parts:
        last = parts[-1]
        if last in status:
            parts.pop()
            continue
        if re.fullmatch(r"\d{1,3}[a-z]?", last):
            parts.pop()
            continue
        # Sometimes there is an extra 'out' token like '*.out' in Makefiles, but filenames won't include it.
        break

    if not parts:
        return None

    # Collapse obvious noise prefixes/suffixes
    # Keep at most first 4 tokens for readability (e.g. 'char_type_overrun_memcpy')
    stem = "_".join(parts[:4])
    return stem


def summarize_variants(root):
    summary = {}
    for cwe_name, cwe_path, sdirs in find_cwe_dirs(root):
        cwe_entry = {}
        for sd in sdirs:
            sd_path = os.path.join(cwe_path, sd)
            variants = Counter()
            files = [f for f in os.listdir(sd_path) if f.startswith("CWE") and (f.endswith('.c') or f.endswith('.cpp'))]
            for f in files:
                v = extract_variant_from_filename(f)
                if v:
                    variants[v] += 1
            # Keep top 5 variants for this subset
            top = variants.most_common(5)
            cwe_entry[sd] = {"total": sum(variants.values()), "top": top}
        summary[cwe_name] = cwe_entry
    return summary


def format_summary(summary):
    lines = []
    for cwe_name in sorted(summary.keys()):
        lines.append(f"- {cwe_name}")
        sdirs = summary[cwe_name]
        for sd in sorted(sdirs.keys()):
            info = sdirs[sd]
            top = info["top"]
            if not top:
                lines.append(f"  - {sd}: (no CWE* source files found)")
                continue
            # Render top 3 variants with counts
            render = ", ".join([f"{v} ({n})" for v, n in top[:3]])
            lines.append(f"  - {sd}: {render}")
    return "\n".join(lines)


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.join('dataset', 'juliet-dynamic-master', 'testcases')
    if not os.path.isdir(root):
        print(f"Error: testcases root not found: {root}")
        sys.exit(1)
    summary = summarize_variants(root)
    print(format_summary(summary))


if __name__ == "__main__":
    main()

