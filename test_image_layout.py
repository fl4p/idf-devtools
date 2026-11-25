import struct
import subprocess
import sys
from pathlib import Path

import pytest

import image_layout as il

TOOL = Path(__file__).with_name("image_layout.py")


def image(drom_len, irom_hdr=0x60018, ram=0x100):
    """DROM at 0x20, RAM filler, IROM header at irom_hdr (as esptool lays out an S3 image)."""
    segs = [(0x3C100020, b"\0" * drom_len), (0x3FC90000, b"\0" * ram)]
    pos = 24 + 8 * 2 + drom_len + ram
    if irom_hdr - pos >= 8:
        segs.append((0x40374000, b"\0" * (irom_hdr - pos - 8)))
    segs.append((0x42000020, b"\0" * 0x100))
    out = bytes([0xE9, len(segs)]) + b"\0" * 22
    for a, d in segs:
        out += struct.pack("<II", a, len(d)) + d
    return out


def run(tmp_path, data, *args):
    p = tmp_path / "app.bin"
    p.write_bytes(data)
    return subprocess.run([sys.executable, str(TOOL), str(p), *args], capture_output=True, text=True)


def test_slack_matches_documented_case():
    # DROM 0x5f7e4 left 2,060 B below the page edge (doc/2026-09-08-image-layout-stability-for-ota.md)
    segs = il.segments(image(0x5F7E4))
    drom, irom = segs[0], segs[-1]
    assert drom["kind"] == "DROM" and irom["kind"] == "IROM"
    assert irom["hdr"] - drom["end"] - 8 == 2060


@pytest.mark.parametrize("drom,rc", [(0x51C7C, 0), (0x5F000, 1), (0x5FE00, 1), (0x50100, 1)])
def test_slack_guard_fails_near_either_edge(tmp_path, drom, rc):
    assert run(tmp_path, image(drom), "--min-slack", "4096").returncode == rc


def test_moved_page_fails_even_with_large_slack(tmp_path):
    r = run(tmp_path, image(0x4C9C8, irom_hdr=0x50018), "--expect-irom", "0x60018", "--min-slack", "4096")
    assert r.returncode == 1 and "expected 0x60018" in r.stdout


@pytest.mark.parametrize("data", [b"", b"\x00" * 64, image(0x1000)[:100]])
def test_unreadable_is_not_ok(tmp_path, data):
    assert run(tmp_path, data).returncode == 2


def test_min_free_without_partition_is_not_ok(tmp_path):
    assert run(tmp_path, image(0x51C7C), "--min-free", "1").returncode == 2
    assert run(tmp_path, image(0x51C7C), "--min-free", "1", "--part-size", "0x1").returncode == 1
