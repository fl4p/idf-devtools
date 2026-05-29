#!/usr/bin/env python3
"""Archive firmware ELFs at flash time so a later coredump can be symbolicated
against the exact build it crashed on.

``esp-coredump`` is SHA-gated: it only decodes a core against the ELF whose
``app_elf_sha256`` matches the flashed image. That sha lives in the ``.bin``'s
``esp_app_desc`` (the ``.elf`` has it zeroed) and is also embedded in every
coredump. So we:

  - dedup archived ELFs by that sha (one zstd-compressed copy per unique build),
  - log every flash as a (time, device, method, version, sha) index line, and
  - match a core back to its ELF by finding the sha's 32 raw bytes in the dump
    (format-agnostic), falling back to "latest build flashed to <device>".

Artifacts (``<build>/<project>.elf`` / ``.bin``) are read from
``<build>/project_description.json`` so this works in any ESP-IDF project; pass
``--elf``/``--bin`` to override. The archive lives at ``$ELF_ARCHIVE_DIR`` (else
``./elf-archive``), so it sits next to the project, not this script.

Layout (under the archive dir):
  blobs/<sha8>.elf.zst   one zstd -19 ELF per unique build
  blobs/<sha8>.json      build meta {version, date, time, idf, sha}
  index.jsonl            one line per flash event

CLI:
  elf_archive.py archive <device> [--method ota|serial] [--build-dir DIR]
                                   [--elf P] [--bin P] [--at ISO] [--foreground]
  elf_archive.py list   [--device D]
  elf_archive.py find    --device D [--at ISO] | --sha SHA   # extract ELF to a tmp path
  elf_archive.py decode [--device D] [--at ISO] <core.bin>   # auto-match + esp-coredump
"""
import argparse
import datetime
import glob
import json
import os
import struct
import subprocess
import sys
import tempfile

ARCHIVE_DIR = os.environ.get('ELF_ARCHIVE_DIR') or os.path.join(os.getcwd(), 'elf-archive')
BLOBS_DIR = os.path.join(ARCHIVE_DIR, 'blobs')
INDEX = os.path.join(ARCHIVE_DIR, 'index.jsonl')
APP_DESC_MAGIC = 0xABCD5432
ZSTD_LEVEL = '19'
KEEP_BUILDS = int(os.environ.get('ELF_ARCHIVE_KEEP', '30'))  # prune all but the N newest builds


def default_artifacts(build_dir='build'):
    """Return (elf, bin) for the project in `build_dir`, read from
    project_description.json; fall back to the newest *.elf there. (None, None)
    if nothing is found."""
    desc = os.path.join(build_dir, 'project_description.json')
    if os.path.exists(desc):
        try:
            d = json.load(open(desc))
            elf = os.path.join(build_dir, d['app_elf'])
            bin = os.path.join(build_dir, d.get('app_bin', d['app_elf'][:-4] + '.bin'))
            return elf, bin
        except Exception:
            pass
    elfs = sorted(glob.glob(os.path.join(build_dir, '*.elf')), key=os.path.getmtime, reverse=True)
    if elfs:
        return elfs[0], elfs[0][:-4] + '.bin'
    return None, None


def read_app_desc(path):
    """Parse esp_app_desc_t {version, project, time, date, idf, sha} from a
    firmware image. The .bin holds the real app_elf_sha256; the .elf zeroes it,
    so pass the .bin for a usable sha. Returns None if the magic isn't found."""
    with open(path, 'rb') as f:
        data = f.read(0x4000)  # app_desc sits at the image head; cap the scan
    off = data.find(struct.pack('<I', APP_DESC_MAGIC))
    if off < 0:
        return None

    def s(rel, n):
        return data[off + rel:off + rel + n].split(b'\x00', 1)[0].decode('utf-8', 'replace')

    return dict(version=s(0x10, 32), project=s(0x30, 32), time=s(0x50, 16),
                date=s(0x60, 16), idf=s(0x70, 32),
                sha=data[off + 0x90:off + 0x90 + 32].hex())


def _now_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec='seconds')


def _read_index():
    if not os.path.exists(INDEX):
        return []
    out = []
    with open(INDEX) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _compress(elf, tmp, blob):
    """zstd-compress `elf` to `tmp`, then atomically rename to `blob` so a reader
    never sees a partial file. Used inline (foreground) and as a detached worker."""
    subprocess.run(['zstd', f'-{ZSTD_LEVEL}', '-q', '-f', elf, '-o', tmp], check=True)
    os.replace(tmp, blob)


def archive(device, method='ota', elf=None, bin=None, when=None, version=None,
            build_dir='build', background=True):
    """Compress+store build ELF (dedup by app_elf_sha256) and append a flash event.
    Compression (~9 s) runs detached by default so it never blocks the flash flow;
    the blob appears atomically when done. Prunes to KEEP_BUILDS afterwards.
    Returns the index entry dict, or None if no ELF could be found."""
    if elf is None or bin is None:
        de, db = default_artifacts(build_dir)
        elf, bin = elf or de, bin or db
    if not elf or not os.path.exists(elf):
        print(f'elf-archive: no ELF to archive (build-dir {build_dir!r})', file=sys.stderr)
        return None
    desc = read_app_desc(bin) if bin and os.path.exists(bin) else None
    if not desc or set(bytes.fromhex(desc['sha'])) == {0}:
        # No usable sha (e.g. .bin missing) — fall back to hashing the ELF so we
        # still dedup, but core auto-matching by sha won't work for this build.
        import hashlib
        h = hashlib.sha256(open(elf, 'rb').read()).hexdigest()
        desc = (desc or {}) | dict(sha=h)
        print(f'WARN: no app_elf_sha256 in {bin}; keyed by ELF content hash '
              f'({h[:8]}) — coredump auto-match unavailable for this build', file=sys.stderr)
    sha = desc['sha']
    sha8 = sha[:8]
    os.makedirs(BLOBS_DIR, exist_ok=True)
    blob = os.path.join(BLOBS_DIR, f'{sha8}.elf.zst')
    tmp = blob + '.tmp'
    if os.path.exists(blob):
        print(f'build {sha8} already archived')
    elif os.path.exists(tmp):
        print(f'build {sha8} compression already in progress')
    else:
        with open(os.path.join(BLOBS_DIR, f'{sha8}.json'), 'w') as f:
            json.dump(desc, f, indent=2)
        if background:
            # detached (own session) so it outlives the flash; argv-only (no
            # shell) so paths can't be misread as shell metacharacters.
            subprocess.Popen([sys.executable, os.path.abspath(__file__),
                              '_compress', elf, tmp, blob],
                             start_new_session=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f'archiving build {sha8} -> {os.path.relpath(blob)} (compressing in background)')
        else:
            _compress(elf, tmp, blob)
            print(f'archived build {sha8} ({os.path.getsize(blob) / 1e6:.1f} MB) '
                  f'-> {os.path.relpath(blob)}')
    entry = dict(ts=when or _now_iso(), device=device, method=method,
                 version=version or desc.get('version'), sha=sha,
                 built=f"{desc.get('date', '')} {desc.get('time', '')}".strip(),
                 idf=desc.get('idf'))
    with open(INDEX, 'a') as f:
        f.write(json.dumps(entry) + '\n')
    print(f'logged: {entry["ts"]}  {device:<14} {method:<6} {entry["version"]}')
    prune()
    return entry


def prune(keep=KEEP_BUILDS):
    """Delete all but the `keep` most-recently-flashed builds (blob + meta).
    Recency is the latest index ts referencing each sha. The index itself is
    kept intact as flash history; aged-out entries just lose their ELF."""
    if not os.path.isdir(BLOBS_DIR):
        return
    last_ts = {}
    for r in _read_index():
        s = r['sha'][:8]
        if r['ts'] > last_ts.get(s, ''):
            last_ts[s] = r['ts']
    keep_set = {s for s, _ in sorted(last_ts.items(), key=lambda kv: kv[1],
                                     reverse=True)[:keep]}
    for name in os.listdir(BLOBS_DIR):
        sha8 = name.split('.', 1)[0]
        if name.endswith('.tmp') or sha8 in keep_set:
            continue
        os.remove(os.path.join(BLOBS_DIR, name))
        if name.endswith('.elf.zst'):
            print(f'pruned build {sha8} (retention cap {keep})')


def _blob_for_sha(sha):
    p = os.path.join(BLOBS_DIR, f'{sha[:8]}.elf.zst')
    return p if os.path.exists(p) else None


def lookup(device=None, at=None, sha=None):
    """Resolve a flash event -> its blob sha. If `sha` given, use it directly.
    Else pick the latest entry for `device` with ts <= `at` (or the latest)."""
    if sha:
        return sha if _blob_for_sha(sha) else None
    rows = _read_index()
    if device:
        rows = [r for r in rows if r['device'] == device]
    if at:
        rows = [r for r in rows if r['ts'] <= at]
    if not rows:
        return None
    rows.sort(key=lambda r: r['ts'])
    return rows[-1]['sha']


def sha_from_core(core_path):
    """Best-effort: return the archived build sha whose 32 raw sha bytes appear
    in the coredump (the dump embeds app_elf_sha256), else None."""
    data = open(core_path, 'rb').read()
    for name in os.listdir(BLOBS_DIR) if os.path.isdir(BLOBS_DIR) else []:
        if not name.endswith('.json'):
            continue
        sha = json.load(open(os.path.join(BLOBS_DIR, name)))['sha']
        if set(bytes.fromhex(sha)) != {0} and bytes.fromhex(sha) in data:
            return sha
    return None


def extract(sha, dest=None):
    """Decompress an archived ELF to `dest` (or a tmp file). Returns the path."""
    blob = _blob_for_sha(sha)
    if not blob:
        if os.path.exists(os.path.join(BLOBS_DIR, f'{sha[:8]}.elf.zst.tmp')):
            raise FileNotFoundError(f'build {sha[:8]} is still compressing — retry shortly')
        raise FileNotFoundError(f'no archived ELF for sha {sha[:8]}')
    if dest is None:
        fd, dest = tempfile.mkstemp(prefix=f'idf-{sha[:8]}-', suffix='.elf')
        os.close(fd)
    with open(dest, 'wb') as out:
        subprocess.run(['zstd', '-dc', blob], stdout=out, check=True)
    return dest


def main():
    if len(sys.argv) >= 5 and sys.argv[1] == '_compress':
        # detached worker spawned by archive(): _compress <elf> <tmp> <blob>
        _compress(sys.argv[2], sys.argv[3], sys.argv[4])
        return 0

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)

    a = sub.add_parser('archive', help='store build ELF + log a flash event')
    a.add_argument('device')
    a.add_argument('--method', default='serial', choices=['ota', 'serial'])
    a.add_argument('--at', help='ISO timestamp of the flash (default now)')
    a.add_argument('--build-dir', default='build')
    a.add_argument('--elf', help='override ELF path (default from project_description.json)')
    a.add_argument('--bin', help='override .bin path (for the app_elf_sha256)')
    a.add_argument('--version', help='override version (default from .bin app_desc)')
    a.add_argument('--foreground', action='store_true',
                   help='compress synchronously instead of detaching')

    l = sub.add_parser('list', help='show flash history')
    l.add_argument('--device')

    f = sub.add_parser('find', help='extract the ELF for a device/time or sha')
    f.add_argument('--device')
    f.add_argument('--at')
    f.add_argument('--sha')
    f.add_argument('-o', '--out', help='write ELF here (default a tmp file)')

    d = sub.add_parser('decode', help='auto-match a coredump to its ELF + symbolicate')
    d.add_argument('core', help='decoded coredump .bin')
    d.add_argument('--device')
    d.add_argument('--at')
    d.add_argument('--sha')
    d.add_argument('--core-format', default='raw')

    args = ap.parse_args()

    if args.cmd == 'archive':
        archive(args.device, args.method, args.elf, args.bin, args.at, args.version,
                build_dir=args.build_dir, background=not args.foreground)
        return 0

    if args.cmd == 'list':
        rows = _read_index()
        if args.device:
            rows = [r for r in rows if r['device'] == args.device]
        for r in rows:
            print(f"{r['ts']}  {r['device']:<14} {r['method']:<6} {r['sha'][:8]}  "
                  f"{r.get('version', '')}")
        if not rows:
            print('(no flash events recorded)')
        return 0

    if args.cmd == 'find':
        sha = lookup(args.device, args.at, args.sha)
        if not sha:
            print('no matching archived ELF', file=sys.stderr)
            return 1
        print(extract(sha, args.out))
        return 0

    if args.cmd == 'decode':
        sha = args.sha or sha_from_core(args.core) or lookup(args.device, args.at)
        if not sha:
            print('could not match this core to an archived ELF '
                  '(try --device/--at or --sha)', file=sys.stderr)
            return 1
        how = 'sha-in-core' if (not args.sha and sha == sha_from_core(args.core)) else \
              'sha' if args.sha else f'device={args.device}'
        print(f'matched build {sha[:8]} ({how})', file=sys.stderr)
        elf = extract(sha)
        try:
            return subprocess.run(['esp-coredump', 'info_corefile',
                                   '--core-format', args.core_format,
                                   '-c', args.core, elf]).returncode
        finally:
            os.unlink(elf)


if __name__ == '__main__':
    sys.exit(main())
