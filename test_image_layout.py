import struct
import os
import subprocess
import sys
import tempfile
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
    # DROM 0x5f7e4 (doc/2026-09-08-image-layout-stability-for-ota.md); esptool moves IROM at E > 0x5fffc
    r = il.margins(0x20 + 0x5F7E4, 0x60018)
    assert r == (2040, 0x20 + 0x5F7E4 - 0x50018 - 4)


def test_valid_layout_at_page_start_is_not_a_failure(tmp_path):
    # DROM ending in the first 0x18 B of the page before IROM's is a legal layout (negative margin before the fix)
    r = run(tmp_path, image(0x4FFE4), "--expect-irom", "0x60018")
    assert r.returncode == 0, r.stdout


def esptool_irom_hdr(drom_len):
    """IROM header offset as esptool itself lays out an S3 image with this DROM length."""
    bi = pytest.importorskip("esptool.bin_image")
    img = bi.ESP32S3FirmwareImage()
    img.segments = [bi.ELFSection(b".flash.rodata", 0x3C100020, b"\0" * drom_len, 0),
                    bi.ELFSection(b".dram0.data", 0x3FC90000, b"\0" * 0x6000, 0),
                    bi.ELFSection(b".iram0.text", 0x40374000, b"\0" * 0x20000, 0),
                    bi.ELFSection(b".flash.text", 0x42000020, b"\0" * 0x100, 0)]
    img.entrypoint = 0x40374000
    fd, p = tempfile.mkstemp()
    os.close(fd)
    try:
        img.save(p)
        segs = il.segments(open(p, "rb").read())
    finally:
        os.unlink(p)
    return next(x["hdr"] for x in segs if x["kind"] == "IROM"), segs[0]["end"]


@pytest.mark.parametrize("drom", [0x51C7C, 0x5F7E4, 0x5FFDC, 0x50000, 0x4FFE4, 0x4FFF8, 0x5FFF8, 0x6000C])
def test_margins_match_esptool(drom):
    hdr, end = esptool_irom_hdr(drom)
    up, down = il.margins(end, hdr)
    assert esptool_irom_hdr(drom + up)[0] == hdr
    assert esptool_irom_hdr(drom + up + 4)[0] != hdr
    for d in range(4, down + 1, 4) if down < 64 else (4, down // 2 & ~3, down - 4, down):
        assert esptool_irom_hdr(drom - d)[0] == hdr, d
    if drom - down - 4 > 0:
        assert esptool_irom_hdr(drom - down - 4)[0] != hdr


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
