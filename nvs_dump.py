"""Dump the contents of an ESP-IDF NVS partition image.

Pages are read in sequence-number order (not flash order). All entries are
collected first; namespace names and multi-chunk blobs are resolved
afterwards, so a namespace definition or blob index may sit anywhere in the
partition. Unknown namespace indices print as ``ns#<idx>``. Entries marked
erased, entries with a bad header or data CRC and incomplete spans are
skipped (reported on stderr).
"""
import argparse
import sys
import zlib
from collections import namedtuple
from enum import Enum

# Layout and constants from nvs_flash (nvs_constants.h, nvs_page.hpp, nvs_types.hpp)
PAGE_SIZE = 4096
ENTRY_COUNT = 126
ENTRY_LENGTH = 32
ESB_OFFSET = 32
ENTRY_0_OFFSET = 64

PAGE_STATE_ACTIVE = 0xFFFFFFFE
PAGE_STATE_FULL = 0xFFFFFFFC
PAGE_STATE_FREEING = 0xFFFFFFF8
# Pages whose entries are live. FREEING is authoritative: IDF discards the
# half-filled copy target and restarts the move on boot.
LIVE_PAGE_STATES = (PAGE_STATE_ACTIVE, PAGE_STATE_FULL, PAGE_STATE_FREEING)

# 2-bit entry states
ES_EMPTY = 0x3
ES_WRITTEN = 0x2
ES_ERASED = 0x0

KEY_LENGTH = 16
NS_INDEX = 0
NS_ANY = 0xFF


class EntryType(Enum):
    U8 = 0x01
    I8 = 0x11
    U16 = 0x02
    I16 = 0x12
    U32 = 0x04
    I32 = 0x14
    U64 = 0x08
    I64 = 0x18
    STR = 0x21
    BLOB = 0x41         # single-entry blob (page version 1), also the type of reassembled blobs
    BLOB_DATA = 0x42
    BLOB_IDX = 0x48


VAR_TYPES = (EntryType.STR.value, EntryType.BLOB.value, EntryType.BLOB_DATA.value)

# Keys used for Wi-Fi SSIDs / passwords (blobs that can be printed as strings)
SSID_KEY_VALUES = ["sta.ssid", "ap.ssid"]
PASSWORD_KEY_VALUES = ["sta.pswd", "ap.passwd"]

Item = namedtuple('Item', 'ns type span chunk key data payload page entry')


class InputError(RuntimeError):
    pass


class ValidationError(InputError):
    def __init__(self, message):
        super().__init__("NVS partition invalid: %s" % message)


def _u(b):
    return int.from_bytes(b, 'little')


def _crc(*parts):
    c = 0xFFFFFFFF
    for p in parts:
        c = zlib.crc32(p, c)
    return c


def header_crc_ok(e):
    return _u(e[4:8]) == _crc(e[0:4], e[8:32])


def live_pages(image):
    """(page_index, seq, page_bytes) of all live pages, sorted by sequence number."""
    if len(image) % PAGE_SIZE:
        raise ValidationError("partition size (%d bytes) is not a multiple of page size (%d bytes)"
                              % (len(image), PAGE_SIZE))
    pages = []
    for idx in range(len(image) // PAGE_SIZE):
        page = image[idx * PAGE_SIZE:(idx + 1) * PAGE_SIZE]
        if _u(page[0:4]) in LIVE_PAGE_STATES:
            pages.append((idx, _u(page[4:8]), page))
    pages.sort(key=lambda p: (p[1], p[0]))
    return pages


def entry_states(page):
    return [(page[ESB_OFFSET + i // 4] >> (2 * (i % 4))) & 0x3 for i in range(ENTRY_COUNT)]


def page_items(page, page_index, warn):
    """Valid WRITTEN items of one page, in entry order."""
    states = entry_states(page)
    i = 0
    while i < ENTRY_COUNT:
        if states[i] != ES_WRITTEN:
            i += 1
            continue
        base = ENTRY_0_OFFSET + i * ENTRY_LENGTH
        e = page[base:base + ENTRY_LENGTH]
        where = "page %d entry %d" % (page_index, i)
        if not header_crc_ok(e):
            warn("%s: header CRC mismatch, skipped" % where)
            i += 1
            continue
        ns, typ, span, chunk = e[0], e[1], e[2], e[3]
        key = bytes(e[8:8 + KEY_LENGTH]).split(b'\0', 1)[0].decode('ascii', 'replace')
        data = bytes(e[24:32])
        payload = None
        if typ in VAR_TYPES:
            size = _u(data[0:2])
            if span < 1 or i + span > ENTRY_COUNT or size > (span - 1) * ENTRY_LENGTH:
                warn("%s: bad span %d / size %d for key %r, skipped" % (where, span, size, key))
                i += 1
                continue
            if any(s != ES_WRITTEN for s in states[i + 1:i + span]):
                warn("%s: span of key %r not fully written, skipped" % (where, key))
                i += span
                continue
            payload = bytes(page[base + ENTRY_LENGTH:base + ENTRY_LENGTH + size])
            if _crc(payload) != _u(data[4:8]):
                warn("%s: data CRC mismatch for key %r, skipped" % (where, key))
                i += span
                continue
        else:
            span = 1
        yield Item(ns, typ, span, chunk, key, data, payload, page_index, i)
        i += span


def _decode_str(payload):
    return payload.split(b'\0', 1)[0].decode('utf-8', 'replace')


def parse_nvs(image, warn=None):
    """Parse an NVS image into {namespace_name: {key: (type_value, value)}}.

    Later pages (higher sequence number) override earlier copies of a key.
    """
    if warn is None:
        def warn(msg):
            print("warning: " + msg, file=sys.stderr)

    items = [it for idx, _seq, page in live_pages(image) for it in page_items(page, idx, warn)]

    ns_names = {}
    for it in items:
        if it.ns == NS_INDEX and it.type == EntryType.U8.value:
            ns_names[it.data[0]] = it.key

    def ns_name(idx):
        return ns_names.get(idx, "ns#%d" % idx)

    table = {ns_names[i]: {} for i in sorted(ns_names)}
    blob_idx = {}   # (ns, key) -> (size, chunk_count, chunk_start)
    chunks = {}     # (ns, key) -> {chunk_index: bytes}

    for it in items:
        if it.ns == NS_INDEX or it.ns == NS_ANY:
            continue
        ns = table.setdefault(ns_name(it.ns), {})
        t = it.type
        if t < 0x20 and t & 0xF in (1, 2, 4, 8):
            n = t & 0xF
            ns[it.key] = (t, int.from_bytes(it.data[:n], 'little', signed=bool(t & 0x10)))
        elif t == EntryType.STR.value:
            ns[it.key] = (t, _decode_str(it.payload))
        elif t == EntryType.BLOB.value:
            ns[it.key] = (t, it.payload)
        elif t == EntryType.BLOB_DATA.value:
            chunks.setdefault((it.ns, it.key), {})[it.chunk] = it.payload
        elif t == EntryType.BLOB_IDX.value:
            blob_idx[(it.ns, it.key)] = (_u(it.data[0:4]), it.data[4], it.data[5])
            ns[it.key] = (EntryType.BLOB.value, None)
        else:
            warn("page %d entry %d: unknown type 0x%02X for key %r" % (it.page, it.entry, t, it.key))

    for (nsi, key), (size, count, start) in blob_idx.items():
        have = chunks.get((nsi, key), {})
        missing = [c for c in range(start, start + count) if c not in have]
        if missing:
            warn("blob %s/%s: missing chunk(s) %s" % (ns_name(nsi), key, missing))
        blob = b''.join(have.get(c, b'') for c in range(start, start + count))
        if len(blob) != size:
            warn("blob %s/%s: %d bytes reassembled, index says %d" % (ns_name(nsi), key, len(blob), size))
        table[ns_name(nsi)][key] = (EntryType.BLOB.value, blob)

    for (nsi, key) in chunks.keys() - blob_idx.keys():
        warn("blob %s/%s: data chunk(s) without index" % (ns_name(nsi), key))

    return table


def entry_data_to_string(entry_key, entry_type, entry_data, blob_limit=0, special_handling=False):
    if entry_type < 0x20:
        return str(entry_data)
    if entry_type == EntryType.STR.value:
        return entry_data
    if special_handling and entry_key in SSID_KEY_VALUES:
        n = _u(entry_data[0:4])
        return entry_data[4:4 + n].decode('utf-8', 'replace') if n <= 32 else ''
    if special_handling and entry_key in PASSWORD_KEY_VALUES:
        if not entry_data or entry_data[0] == 0xFF:
            return ''
        return _decode_str(entry_data)
    shown = entry_data if blob_limit <= 0 else entry_data[:blob_limit]
    s = ''.join('%02X ' % b for b in shown)
    return s + '...' if len(shown) < len(entry_data) else s


def dump_nvs_data(table, blob_limit=0, special_handling=False):
    for ns_name, ns in table.items():
        print("Namespace %s" % ns_name)
        for key, (typ, value) in ns.items():
            print("  %-16s: %-4s  %s" % (key, EntryType(typ).name,
                                         entry_data_to_string(key, typ, value, blob_limit, special_handling)))


def main():
    parser = argparse.ArgumentParser(description='ESP32 NVS partition analyzer')
    parser.add_argument('input', help='Path to binary dump of NVS partition.', type=argparse.FileType('rb'))
    parser.add_argument('--blob_limit', '-b', help='Set maximum number of bytes to dump per BLOB (0 = no limit)',
                        type=int, default=0)
    parser.add_argument('--special_handling', '-s', help='Display SSID and password BLOBs as strings',
                        action='store_true')
    args = parser.parse_args()
    dump_nvs_data(parse_nvs(args.input.read()), args.blob_limit, args.special_handling)


if __name__ == '__main__':
    try:
        main()
    except InputError as e:
        print(e, file=sys.stderr)
        sys.exit(2)
