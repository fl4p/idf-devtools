"""Tests for nvs_dump on hand-built NVS pages (no IDF needed).

    python3 -m unittest test_nvs_dump
"""
import os
import subprocess
import sys
import tempfile
import unittest
import zlib

import nvs_dump as nd

HERE = os.path.dirname(os.path.abspath(__file__))

ACTIVE, FULL, FREEING, CORRUPT, UNINIT = 0xFFFFFFFE, 0xFFFFFFFC, 0xFFFFFFF8, 0xFFFFFFF0, 0xFFFFFFFF
U8, U16, I32, STR, BLOB_DATA, BLOB_IDX = 0x01, 0x02, 0x14, 0x21, 0x42, 0x48


def crc(*parts):
    c = 0xFFFFFFFF
    for p in parts:
        c = zlib.crc32(p, c)
    return c


def header(ns, typ, key, data8, span=1, chunk=0xFF, bad_crc=False):
    e = bytearray([ns, typ, span, chunk]) + bytes(4) + key.encode().ljust(16, b'\0') + bytes(data8)
    c = crc(e[0:4], e[8:32]) ^ (1 if bad_crc else 0)
    e[4:8] = c.to_bytes(4, 'little')
    return [bytes(e)]


def prim(ns, typ, key, value):
    n = typ & 0xF
    return header(ns, typ, key, value.to_bytes(n, 'little', signed=bool(typ & 0x10)).ljust(8, b'\xff'))


def var(ns, typ, key, payload, chunk=0xFF, bad_data_crc=False):
    span = 1 + (len(payload) + 31) // 32
    c = crc(payload) ^ (1 if bad_data_crc else 0)
    data8 = len(payload).to_bytes(2, 'little') + b'\xff\xff' + c.to_bytes(4, 'little')
    body = payload.ljust((span - 1) * 32, b'\xff')
    return header(ns, typ, key, data8, span, chunk) + [body[i:i + 32] for i in range(0, len(body), 32)]


def blob_idx(ns, key, size, count, start=0):
    return header(ns, BLOB_IDX, key, size.to_bytes(4, 'little') + bytes([count, start]) + b'\xff\xff')


def namespace(name, idx):
    return prim(0, U8, name, idx)


def page(seq, items, state=ACTIVE, erased=()):
    """items: list of entry lists (from the helpers above); erased: item positions to mark erased."""
    p = bytearray(b'\xff' * nd.PAGE_SIZE)
    p[0:4] = state.to_bytes(4, 'little')
    p[4:8] = seq.to_bytes(4, 'little')
    p[8] = 0xFE
    p[28:32] = crc(p[4:28]).to_bytes(4, 'little')
    slot = 0
    for n, entries in enumerate(items):
        es = 0x0 if n in erased else 0x2
        for e in entries:
            p[64 + slot * 32:64 + slot * 32 + 32] = e
            byte = 32 + slot // 4
            shift = 2 * (slot % 4)
            p[byte] = (p[byte] & ~(0x3 << shift)) | (es << shift)
            slot += 1
    return bytes(p)


def parse(image):
    warnings = []
    return nd.parse_nvs(image, warnings.append), warnings


class ForwardNamespaceTest(unittest.TestCase):
    def image(self):
        # Flash order: page with seq 7 holds data for ns 4 and 5; ns definitions sit
        # on a later-sequence page stored *before* it, and ns 5 later in its own page.
        data_page = page(3, [prim(4, U8, 'boot', 9), prim(5, U16, 'port', 1883), namespace('mqtt', 5)])
        ns_page = page(7, [namespace('wifi', 4)])
        empty = b'\xff' * nd.PAGE_SIZE
        return ns_page + data_page + empty

    def test_cli_does_not_crash(self):
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(self.image())
        try:
            r = subprocess.run([sys.executable, os.path.join(HERE, 'nvs_dump.py'), f.name],
                               capture_output=True, text=True)
        finally:
            os.unlink(f.name)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('Namespace wifi', r.stdout)
        self.assertRegex(r.stdout, r'boot\s*: U8\s+9')
        self.assertRegex(r.stdout, r'port\s*: U16\s+1883')

    def test_resolved(self):
        t, w = parse(self.image())
        self.assertEqual(t['wifi'], {'boot': (U8, 9)})
        self.assertEqual(t['mqtt'], {'port': (U16, 1883)})
        self.assertEqual(w, [])

    def test_unknown_namespace(self):
        t, _ = parse(page(0, [prim(7, I32, 'x', -5)]))
        self.assertEqual(t['ns#7'], {'x': (I32, -5)})


class PageOrderTest(unittest.TestCase):
    def test_higher_sequence_wins(self):
        newer = page(10, [prim(1, U8, 'k', 2)])
        older = page(2, [namespace('a', 1), prim(1, U8, 'k', 1)], state=FULL)
        t, _ = parse(newer + older)
        self.assertEqual(t['a']['k'], (U8, 2))

    def test_page_states(self):
        good = page(0, [namespace('a', 1), prim(1, U8, 'live', 1)], state=FULL)
        freeing = page(1, [prim(1, U8, 'moving', 2)], state=FREEING)
        corrupt = page(2, [prim(1, U8, 'corrupt', 3)], state=CORRUPT)
        uninit = page(3, [prim(1, U8, 'uninit', 4)], state=UNINIT)
        t, _ = parse(good + freeing + corrupt + uninit)
        self.assertEqual(t['a'], {'live': (U8, 1), 'moving': (U8, 2)})

    def test_size_not_page_multiple(self):
        with self.assertRaises(nd.ValidationError):
            nd.parse_nvs(b'\xff' * 100)


class EntryTest(unittest.TestCase):
    def test_erased_and_corrupt_entries(self):
        p = page(0, [namespace('a', 1),
                     prim(1, U8, 'gone', 1),                       # erased in the bitmap
                     header(1, U8, 'badhdr', b'\x05' + b'\xff' * 7, bad_crc=True),
                     var(1, STR, 'baddata', b'hello\0', bad_data_crc=True),
                     prim(1, U8, 'ok', 3)],
                 erased={1})
        t, w = parse(p)
        self.assertEqual(t['a'], {'ok': (U8, 3)})
        self.assertEqual(len(w), 2)

    def test_multi_span_string(self):
        s = ('x' * 100 + 'end').encode() + b'\0'
        t, w = parse(page(0, [namespace('a', 1), var(1, STR, 's', s), prim(1, U8, 'after', 1)]))
        self.assertEqual(t['a'], {'s': (STR, 'x' * 100 + 'end'), 'after': (U8, 1)})
        self.assertEqual(w, [])

    def test_partially_written_span(self):
        entries = var(1, STR, 's', b'y' * 70 + b'\0')
        p = bytearray(page(0, [namespace('a', 1), entries]))
        p[32] = (p[32] & 0x3F) | 0xC0      # last span entry (slot 3) back to EMPTY
        t, w = parse(bytes(p))
        self.assertEqual(t['a'], {})
        self.assertEqual(len(w), 1)


class BlobTest(unittest.TestCase):
    def test_index_before_chunks_across_pages(self):
        a, b = bytes(range(200)), bytes(range(50, 150))
        p0 = page(0, [namespace('cal', 2), blob_idx(2, 'tbl', 300, 2, 0),
                      var(2, BLOB_DATA, 'tbl', b'stale', chunk=128)], state=FULL)
        p1 = page(1, [var(2, BLOB_DATA, 'tbl', b, chunk=1), var(2, BLOB_DATA, 'tbl', a, chunk=0)])
        t, w = parse(p1 + p0)
        self.assertEqual(t['cal']['tbl'], (0x41, a + b))
        self.assertEqual(w, [])

    def test_missing_chunk_warns(self):
        p = page(0, [namespace('cal', 2), blob_idx(2, 'tbl', 10, 2), var(2, BLOB_DATA, 'tbl', b'01234', chunk=0)])
        t, w = parse(p)
        self.assertEqual(t['cal']['tbl'], (0x41, b'01234'))
        self.assertTrue(any('missing chunk' in m for m in w))


def _idf_generator():
    try:
        import esp_idf_nvs_partition_gen  # noqa: F401
        return True
    except ImportError:
        return False


@unittest.skipUnless(_idf_generator(), 'esp_idf_nvs_partition_gen not installed (source the IDF env)')
class IdfGeneratedTest(unittest.TestCase):
    """An image from nvs_partition_gen with its pages swapped in flash."""

    def test_swapped_pages(self):
        big = bytes(i * 7 & 0xFF for i in range(5000))
        rows = ['key,type,encoding,value', 'first,namespace,,']
        rows += ['k%02d,data,u32,%d' % (i, i * 1000) for i in range(150)]
        rows += ['second,namespace,,', 'name,data,string,' + 'z' * 300, 'n,data,i32,-42']
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'big.bin'), 'wb') as f:
                f.write(big)
            rows.append('big,file,binary,' + os.path.join(d, 'big.bin'))
            rows += ['third,namespace,,', 'last,data,u8,7']
            with open(os.path.join(d, 'in.csv'), 'w') as f:
                f.write('\n'.join(rows) + '\n')
            out = os.path.join(d, 'nvs.bin')
            subprocess.run([sys.executable, '-m', 'esp_idf_nvs_partition_gen', 'generate',
                            os.path.join(d, 'in.csv'), out, hex(8 * nd.PAGE_SIZE)],
                           check=True, capture_output=True)
            with open(out, 'rb') as f:
                img = f.read()
        pages = [img[i:i + nd.PAGE_SIZE] for i in range(0, len(img), nd.PAGE_SIZE)]
        used = [p for p in pages if p[0:4] != b'\xff\xff\xff\xff']
        self.assertGreaterEqual(len(used), 3)
        self.check(b''.join(reversed(pages)), big)
        # also reverse the sequence numbers: namespace definitions now follow their entries
        reseq = []
        for p, seq in zip(used, reversed([nd._u(p[4:8]) for p in used])):
            p = bytearray(p)
            p[4:8] = seq.to_bytes(4, 'little')
            p[28:32] = crc(p[4:28]).to_bytes(4, 'little')
            reseq.append(bytes(p))
        self.check(b''.join(reseq), big)

    def check(self, image, big):
        t, w = parse(image)
        self.assertEqual(w, [])
        self.assertEqual(t['first'], {'k%02d' % i: (0x04, i * 1000) for i in range(150)})
        self.assertEqual(t['second']['name'], (STR, 'z' * 300))
        self.assertEqual(t['second']['n'], (I32, -42))
        self.assertEqual(t['second']['big'], (0x41, big))
        self.assertEqual(t['third'], {'last': (U8, 7)})


if __name__ == '__main__':
    unittest.main()
