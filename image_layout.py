#!/usr/bin/env python3
"""Flash layout of an ESP-IDF app image: where each flash-mapped segment sits relative to the 64 KB MMU page.

esptool places each flash-mapped segment (DROM rodata, IROM text) at the first file offset congruent to its
vaddr mod 64 KB after the previous one, and fills the gap with RAM segments. When the segment before it grows past
the page edge, the next segment moves a whole page: every later flash sector changes, which defeats a
differential OTA. Shrinking below the lower edge moves it down a page, same effect.

  image_layout.py build/            # or the .bin; partition table read from build/partition_table/
  image_layout.py build/ --expect-irom 0x60018 --min-slack 4096 --min-free 32768 [--json]

Exit 0 ok, 1 a check failed, 2 unreadable input or no flash-mapped segment pair.
"""
import argparse
import json
import os
import struct
import sys

PAGE = 0x10000
SEG_HDR = 8
# vaddr ranges mapped from flash: (lo, hi, kind)
FLASH_RANGES = [
    (0x3C000000, 0x3E000000, "DROM"),  # S2/S3/C2/C3 data bus
    (0x3F400000, 0x3F800000, "DROM"),  # ESP32
    (0x42000000, 0x44000000, "IROM"),  # S3/C-series/H2 (C6/H2/C5 also map rodata here)
    (0x400C2000, 0x40C00000, "IROM"),  # ESP32
]


def flash_kind(addr):
    for lo, hi, k in FLASH_RANGES:
        if lo <= addr < hi:
            return k
    return None


def segments(b):
    if len(b) < 24 or b[0] != 0xE9:
        raise ValueError("not an ESP app image (magic)")
    off, out = 24, []
    for _ in range(b[1]):
        if off + SEG_HDR > len(b):
            raise ValueError("truncated segment header")
        addr, ln = struct.unpack_from("<II", b, off)
        if off + SEG_HDR + ln > len(b):
            raise ValueError("truncated segment")
        out.append(dict(hdr=off, data=off + SEG_HDR, addr=addr, len=ln, end=off + SEG_HDR + ln,
                        kind=flash_kind(addr) if (off + SEG_HDR) % PAGE == addr % PAGE else None))
        off += SEG_HDR + ln
    return out


def smallest_app_part(pt):
    sizes = []
    for i in range(0, len(pt) - 31, 32):
        magic, typ = struct.unpack_from("<HB", pt, i)
        if magic != 0x50AA:
            break
        if typ == 0:
            sizes.append(struct.unpack_from("<I", pt, i + 8)[0])
    return min(sizes) if sizes else None


def margins(end, hdr):
    """Bytes the previous segment (ending at file offset `end`, 4-aligned) may grow and shrink while the next
    header stays at `hdr`. esptool (get_alignment_data_needed) puts the header in the page after the one `end`
    is in, except when end % PAGE == hdr % PAGE, where it follows directly at `end`."""
    if end == hdr:
        return 0, 0
    page = hdr - hdr % PAGE
    up = page - 4 - end
    down = end - (hdr - PAGE) - 4 if end > hdr - PAGE else end - (page - PAGE)
    return up, down


def analyse(binpath, part_size=None):
    b = open(binpath, "rb").read()
    segs = segments(b)
    flash = [s for s in segs if s["kind"]]
    if len(flash) < 2:
        raise ValueError("fewer than two flash-mapped segments")
    edges = []
    for prev, s in zip(flash, flash[1:]):
        up, down = margins(prev["end"], s["hdr"])
        edges.append(dict(kind=s["kind"], hdr=s["hdr"], page=s["data"] // PAGE, prev_kind=prev["kind"],
                          prev_len=prev["len"], up=up, down=down))
    r: dict = dict(bin=binpath, size=len(b), segments=segs, edges=edges, part_size=part_size,
             free=part_size - len(b) if part_size else None)
    return r


def main():
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    ap.add_argument("path", help="build dir or app .bin")
    ap.add_argument("--part-size", type=lambda s: int(s, 0), help="app partition size (default: smallest app "
                                                                  "partition of the build's partition table)")
    ap.add_argument("--expect-irom", type=lambda s: int(s, 0), help="required file offset of the IROM header")
    ap.add_argument("--min-slack", type=lambda s: int(s, 0), default=0, help="min bytes to either page edge")
    ap.add_argument("--min-free", type=lambda s: int(s, 0), help="min free bytes in the app partition")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    try:
        binpath, part = a.path, a.part_size
        if os.path.isdir(a.path):
            desc = json.load(open(os.path.join(a.path, "project_description.json")))
            binpath = os.path.join(a.path, desc["app_bin"])
            if part is None:
                pt = os.path.join(a.path, "partition_table", "partition-table.bin")
                part = smallest_app_part(open(pt, "rb").read())
        r = analyse(binpath, part)
    except Exception as e:  # anything unreadable is exit 2, never a pass or a plain check failure
        print(f"image_layout: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    if a.min_free is not None and r["free"] is None:
        print("image_layout: --min-free needs a partition size", file=sys.stderr)
        return 2

    fails = []
    for e in r["edges"]:
        if min(e["up"], e["down"]) < a.min_slack:
            fails.append(f"{e['prev_kind']} is {min(e['up'], e['down'])} B from the edge that moves {e['kind']} "
                         f"(min {a.min_slack})")
    irom = next((e for e in r["edges"] if e["kind"] == "IROM"), None)
    if a.expect_irom is not None and (irom is None or irom["hdr"] != a.expect_irom):
        fails.append(f"IROM header at {irom['hdr']:#x}, expected {a.expect_irom:#x}" if irom else "no IROM segment")
    if a.min_free is not None and r["free"] < a.min_free:
        fails.append(f"{r['free']} B free in the app partition (min {a.min_free})")
    r["fail"] = fails

    if a.json:
        print(json.dumps(r))
    else:
        print(f"{r['bin']}: {r['size']} B ({r['size']:#x})" +
              (f", {r['free']} B free of {r['part_size']:#x}" if r["free"] is not None else ""))
        for e in r["edges"]:
            print(f"  {e['kind']} at {e['hdr']:#x} (page {e['page']}): {e['prev_kind']} len {e['prev_len']:#x} "
                  f"may grow {e['up']} B / shrink {e['down']} B before {e['kind']} moves a page")
        for f in fails:
            print(f"  FAIL: {f}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
