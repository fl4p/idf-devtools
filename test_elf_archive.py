"""Unit tests for elf_archive: artifact derivation, app_desc parsing, dedup,
retention pruning, coredump sha auto-match, and extract round-trip.

No hardware/IDF needed; the only external dep is the `zstd` CLI (tests that
need it skip if it's absent).

    python3 -m unittest test_elf_archive
"""
import json
import os
import shutil
import struct
import tempfile
import unittest

import elf_archive as ea

HAVE_ZSTD = shutil.which("zstd") is not None


def make_bin(sha_hex, version="v1.2.3", project="proj"):
    """A minimal blob carrying an esp_app_desc_t: magic@0, version@0x10,
    project@0x30, app_elf_sha256@0x90."""
    buf = bytearray(0x100)
    struct.pack_into("<I", buf, 0, ea.APP_DESC_MAGIC)
    buf[0x10:0x10 + len(version)] = version.encode()
    buf[0x30:0x30 + len(project)] = project.encode()
    buf[0x90:0x90 + 32] = bytes.fromhex(sha_hex)
    return bytes(buf)


class ElfArchiveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        # redirect the archive at the module globals (resolved from cwd/env at import)
        ea.ARCHIVE_DIR = os.path.join(self.tmp, "arch")
        ea.BLOBS_DIR = os.path.join(ea.ARCHIVE_DIR, "blobs")
        ea.INDEX = os.path.join(ea.ARCHIVE_DIR, "index.jsonl")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, data=b"ELFDATA-0123456789"):
        p = os.path.join(self.tmp, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    # --- app_desc / artifact resolution ----------------------------------
    def test_read_app_desc(self):
        sha = "ab" * 32
        p = self._write("fw.bin", make_bin(sha, version="numble-288-gdeadbee"))
        d = ea.read_app_desc(p)
        self.assertEqual(d["version"], "numble-288-gdeadbee")
        self.assertEqual(d["sha"], sha)
        self.assertEqual(d["project"], "proj")

    def test_default_artifacts_from_project_description(self):
        bd = os.path.join(self.tmp, "build")
        os.makedirs(bd)
        json.dump({"app_elf": "x.elf", "app_bin": "x.bin"},
                  open(os.path.join(bd, "project_description.json"), "w"))
        elf, bin = ea.default_artifacts(bd)
        self.assertEqual(os.path.basename(elf), "x.elf")
        self.assertEqual(os.path.basename(bin), "x.bin")

    def test_default_artifacts_glob_fallback(self):
        bd = os.path.join(self.tmp, "b2")
        os.makedirs(bd)
        open(os.path.join(bd, "only.elf"), "wb").close()
        elf, _ = ea.default_artifacts(bd)
        self.assertEqual(os.path.basename(elf), "only.elf")

    # --- archive: dedup + index + round-trip ------------------------------
    @unittest.skipUnless(HAVE_ZSTD, "zstd CLI not installed")
    def test_archive_dedup_and_index(self):
        sha = "11" * 32
        elf = self._write("fw.elf")
        bin = self._write("fw.bin", make_bin(sha))
        ea.archive("devA", "serial", elf=elf, bin=bin, when="2026-01-01T00:00:00", background=False)
        ea.archive("devB", "ota", elf=elf, bin=bin, when="2026-01-02T00:00:00", background=False)
        blobs = [n for n in os.listdir(ea.BLOBS_DIR) if n.endswith(".elf.zst")]
        self.assertEqual(len(blobs), 1, "same build must dedup to one blob")
        self.assertEqual(len(ea._read_index()), 2, "but each flash is its own index line")

    @unittest.skipUnless(HAVE_ZSTD, "zstd CLI not installed")
    def test_extract_roundtrip(self):
        sha = "22" * 32
        payload = b"\x7fELF" + os.urandom(4096)
        elf = self._write("fw.elf", payload)
        bin = self._write("fw.bin", make_bin(sha))
        ea.archive("dev", "serial", elf=elf, bin=bin, background=False)
        out = ea.extract(sha, os.path.join(self.tmp, "out.elf"))
        self.assertEqual(open(out, "rb").read(), payload)

    # --- retention pruning ------------------------------------------------
    def test_prune_keeps_newest(self):
        os.makedirs(ea.BLOBS_DIR)
        with open(ea.INDEX, "w") as idx:
            for i in range(5):
                sha = f"{i:02d}" + "a" * 62
                open(os.path.join(ea.BLOBS_DIR, f"{sha[:8]}.elf.zst"), "wb").close()
                json.dump({"sha": sha}, open(os.path.join(ea.BLOBS_DIR, f"{sha[:8]}.json"), "w"))
                idx.write(json.dumps(dict(ts=f"2026-01-0{i+1}T00:00:00", device="d",
                                          method="ota", version=f"v{i}", sha=sha)) + "\n")
        ea.prune(keep=3)
        kept = sorted(n.split(".")[0] for n in os.listdir(ea.BLOBS_DIR) if n.endswith(".elf.zst"))
        self.assertEqual(kept, ["02aaaaaa", "03aaaaaa", "04aaaaaa"])
        self.assertEqual(len(ea._read_index()), 5, "index history is kept intact")

    # --- coredump auto-match ---------------------------------------------
    def test_sha_from_core(self):
        os.makedirs(ea.BLOBS_DIR)
        sha = "fe" * 32
        json.dump({"sha": sha}, open(os.path.join(ea.BLOBS_DIR, f"{sha[:8]}.json"), "w"))
        core = os.path.join(self.tmp, "core.bin")
        open(core, "wb").write(b"\x00" * 100 + bytes.fromhex(sha) + b"\xff" * 50)
        self.assertEqual(ea.sha_from_core(core), sha)
        # a core with no known sha matches nothing
        open(core, "wb").write(b"\x5a" * 200)
        self.assertIsNone(ea.sha_from_core(core))

    def test_lookup_latest_for_device(self):
        os.makedirs(ea.BLOBS_DIR)
        with open(ea.INDEX, "w") as idx:
            for ts, dev, sha in [("2026-01-01T00:00:00", "flat", "aa" * 32),
                                 ("2026-01-03T00:00:00", "flat", "bb" * 32),
                                 ("2026-01-02T00:00:00", "fry", "cc" * 32)]:
                idx.write(json.dumps(dict(ts=ts, device=dev, method="ota",
                                          version="v", sha=sha)) + "\n")
        # blob must exist for sha lookup to resolve
        open(os.path.join(ea.BLOBS_DIR, "bbbbbbbb.elf.zst"), "wb").close()
        self.assertEqual(ea.lookup(device="flat"), "bb" * 32)
        self.assertEqual(ea.lookup(device="flat", at="2026-01-02T00:00:00"), "aa" * 32)


if __name__ == "__main__":
    unittest.main()
