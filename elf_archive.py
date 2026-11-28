#!/usr/bin/env python3
"""Archive firmware ELFs at flash time so a later coredump can be symbolicated
against the exact build it crashed on.

``esp-coredump`` is SHA-gated: it only decodes a core against the ELF whose
``app_elf_sha256`` matches the flashed image. That sha lives in the ``.bin``'s
``esp_app_desc`` (the ``.elf`` has it zeroed) and is also embedded in every
coredump. So we:

  - dedup archived ELFs by that sha (one zstd-compressed copy per unique build),
  - log every flash as a (time, device, method, version, sha) index line, and
  - match a core back to its ELF by finding the sha in the dump, as 32 raw
    bytes or as the 64 lower-case hex characters the ELF-format core stores
    (``CONFIG_APP_RETRIEVE_LEN_ELF_SHA``). "Latest build flashed to <device>"
    is used only when asked for with --device/--at, and says so.

``app_elf_sha256`` is the SHA-256 of the ELF file itself, so ``extract`` hashes
what it decompresses and refuses a blob that is not the build it claims to be.

Artifacts (``<build>/<project>.elf`` / ``.bin``) are read from
``<build>/project_description.json`` so this works in any ESP-IDF project; pass
``--elf``/``--bin`` to override. The archive lives at ``$ELF_ARCHIVE_DIR``, else the
first ``elf-archive/`` holding an index (ours, not group/world-writable) in the main
checkout behind a git worktree, then in the cwd or its parents up to the git repo
root, then likewise from this script (reaching the superproject when vendored),
else the main checkout's ``elf-archive/`` (a worktree never starts its own), else
``./elf-archive``.

Retention keeps the ``$ELF_ARCHIVE_KEEP`` (30) most recently flashed builds plus
the last ``$ELF_ARCHIVE_KEEP_PER_DEVICE`` (3) builds of every device.

Layout (under the archive dir):
  blobs/<sha8>.elf.zst   one zstd -19 ELF per unique build
  blobs/<sha8>.json      build meta {version, date, time, idf, sha}
  index.jsonl            one line per flash event

CLI:
  elf_archive.py archive <device> [--method ota|serial] [--build-dir DIR]
                                   [--elf P] [--bin P] [--at ISO] [--foreground]
  elf_archive.py list   [--device D]
  elf_archive.py find    --device D [--at ISO] | --sha SHA   # extract ELF to a tmp path
  elf_archive.py decode [--sha S | --device D [--at ISO]] [--search DIR] <core.bin>
      # match + esp-coredump; without an archived match, searches the build dirs of the
      # repo's git worktrees (and --search) for the ELF whose sha256 is in the core
"""
import argparse
import datetime
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile



def _repo_dirs(start):
    """`start` and its parents up to the enclosing git repo root (past submodule
    roots to the superproject). Outside a repo: just `start`."""
    out, p = [], os.path.abspath(start)
    while True:
        out.append(p)
        g = os.path.join(p, '.git')
        if os.path.isdir(g):
            return out
        if os.path.isfile(g):
            try:
                if '/modules/' not in open(g).read():
                    return out
            except OSError:
                return out
        up = os.path.dirname(p)
        if up == p:
            return out[:1]
        p = up


def _trusted(path):
    st = os.stat(path)
    return st.st_uid == os.getuid() and not st.st_mode & 0o022


def _main_checkout(start):
    """Main working tree behind the git worktree holding `start`, else None."""
    for p in _repo_dirs(start):
        g = os.path.join(p, '.git')
        if not os.path.isfile(g):
            continue
        try:
            line = open(g).read().strip()
        except OSError:
            return None
        if line.startswith('gitdir:') and '/worktrees/' in line:
            gd = os.path.normpath(os.path.join(p, line[7:].strip()))
            common = gd[:gd.rindex('/worktrees/')]
            if common.endswith('/.git'):
                return os.path.dirname(common)
            if '/.git/modules/' in common:
                return common.replace('/.git/modules/', '/', 1)
    return None


def _find_archive_dir(starts=None):
    """First `elf-archive/` holding an index (owned by us, not group/world-writable)
    in the main checkout behind a git worktree, then in the repo of the cwd or of
    this script; else the main checkout's, else ./elf-archive. A worktree never
    starts an archive of its own."""
    starts = starts or [os.getcwd(), os.path.dirname(os.path.abspath(__file__))]
    mains = [m for m in (_main_checkout(st) for st in starts) if m]
    for base in [d for st in mains + starts for d in _repo_dirs(st)]:
        d = os.path.join(base, 'elf-archive')
        idx = os.path.join(d, 'index.jsonl')
        if os.path.exists(idx) and _trusted(d) and _trusted(idx):
            return d
    for m in mains:  # only a main checkout that exists and is ours, with no untrusted archive
        d = os.path.join(m, 'elf-archive')
        if os.path.isdir(m) and _trusted(m) and (not os.path.exists(d) or _trusted(d)):
            return d
    return os.path.join(os.getcwd(), 'elf-archive')


ARCHIVE_DIR = os.environ.get('ELF_ARCHIVE_DIR') or _find_archive_dir()
BLOBS_DIR = os.path.join(ARCHIVE_DIR, 'blobs')
INDEX = os.path.join(ARCHIVE_DIR, 'index.jsonl')
APP_DESC_MAGIC = 0xABCD5432
ZSTD_LEVEL = '19'
KEEP_BUILDS = int(os.environ.get('ELF_ARCHIVE_KEEP', '30'))  # prune all but the N newest builds
KEEP_PER_DEVICE = int(os.environ.get('ELF_ARCHIVE_KEEP_PER_DEVICE', '3'))  # ...and each device's last N


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


def prune(keep=KEEP_BUILDS, per_device=KEEP_PER_DEVICE):
    """Delete builds (blob + meta) that are neither among the `keep`
    most-recently-flashed nor among the last `per_device` builds of any device.
    Recency is the latest index ts referencing each sha. The index itself is
    kept intact as flash history; aged-out entries just lose their ELF."""
    if not os.path.isdir(BLOBS_DIR):
        return
    last_ts = {}
    by_dev = {}
    for r in sorted(_read_index(), key=lambda r: r['ts'], reverse=True):
        s = r['sha'][:8]
        last_ts.setdefault(s, r['ts'])
        if r.get('method', '').endswith('-failed'):
            continue  # not running on the device: no per-device slot
        d = by_dev.setdefault(r['device'], [])
        if s not in d:
            d.append(s)
    keep_set = {s for s, _ in sorted(last_ts.items(), key=lambda kv: kv[1],
                                     reverse=True)[:keep]}
    for d in by_dev.values():
        keep_set.update(d[:per_device])
    for name in os.listdir(BLOBS_DIR):
        sha8 = name.split('.', 1)[0]
        if name.endswith('.tmp') or sha8 in keep_set:
            continue
        os.remove(os.path.join(BLOBS_DIR, name))
        if name.endswith('.elf.zst'):
            print(f'pruned build {sha8} (retention cap {keep})')


def _meta_sha(sha):
    """Full sha recorded for the blob that `sha` (a hex prefix of >= 8 chars)
    would select, or None. Blobs are keyed by sha[:8] only, so the caller's
    whole prefix must agree with the recorded sha, not just its first 8."""
    sha = (sha or '').lower()
    if len(sha) < 8:
        return None
    p = os.path.join(BLOBS_DIR, f'{sha[:8]}.json')
    if not os.path.exists(p):
        return None
    full = json.load(open(p)).get('sha', '').lower()
    return full if full.startswith(sha) else None


def _blob_for_sha(sha):
    p = os.path.join(BLOBS_DIR, f'{sha[:8].lower()}.elf.zst')
    return p if os.path.exists(p) else None


def lookup(device=None, at=None, sha=None):
    """Resolve a flash event -> its blob sha. If `sha` given, use it directly.
    Else pick the latest entry for `device` with ts <= `at` (or the latest)."""
    if sha:
        full = _meta_sha(sha)
        return full if full and _blob_for_sha(full) else None
    rows = [r for r in _read_index() if not r.get('method', '').endswith('-failed')]
    if device:
        rows = [r for r in rows if r['device'] == device]
    if at:
        rows = [r for r in rows if r['ts'] <= at]
    if not rows:
        return None
    rows.sort(key=lambda r: r['ts'])
    return rows[-1]['sha']


def core_sha_hex(data):
    """app_elf_sha256 prefix (hex) from an ELF-format core's ESP_CORE_DUMP_INFO
    note (stored as ASCII hex after a 4-byte version), else None."""
    m = re.search(rb'ESP_CORE_DUMP_INFO\x00+.{4}([0-9a-f]{8,64})', data, re.S)
    return m.group(1).decode() if m else None


def sha_from_core(core_path):
    """Return the archived build sha that appears in the coredump, else None.
    The dump embeds app_elf_sha256: the ELF-format core as 64 hex characters
    (CONFIG_APP_RETRIEVE_LEN_ELF_SHA=64), other formats as the 32 raw bytes.
    Both are searched."""
    data = open(core_path, 'rb').read()
    for name in sorted(os.listdir(BLOBS_DIR)) if os.path.isdir(BLOBS_DIR) else []:
        if not name.endswith('.json'):
            continue
        sha = json.load(open(os.path.join(BLOBS_DIR, name)))['sha'].lower()
        blob = os.path.join(BLOBS_DIR, name[:-5] + '.elf.zst')
        if not (os.path.exists(blob) or os.path.exists(blob + '.tmp')):
            continue  # meta left by a failed compression
        raw = bytes.fromhex(sha)
        if set(raw) == {0}:
            continue
        if raw in data or sha.encode() in data or sha.upper().encode() in data:
            return sha
    return None


def _search_dirs(extra=()):
    """Build dirs of the cwd's repo and its git worktrees, plus `extra`."""
    out = list(extra)
    try:
        wt = subprocess.run(['git', 'worktree', 'list', '--porcelain'], capture_output=True,
                            text=True, timeout=10).stdout
        roots = [l[9:] for l in wt.splitlines() if l.startswith('worktree ')]
    except (OSError, subprocess.TimeoutExpired):
        roots = []
    for r in roots or [_repo_dirs(os.getcwd())[-1]]:
        out += [os.path.join(r, 'build')] + glob.glob(os.path.join(r, 'build', '*'))
    return [d for d in out if os.path.isdir(d)]


def local_elf_for_core(core_path, extra=()):
    """ELF in a local build dir whose sha256 appears in the core, else None."""
    data = open(core_path, 'rb').read()
    for d in _search_dirs(extra):
        for elf in glob.glob(os.path.join(d, '*.elf')):
            h = hashlib.sha256()
            with open(elf, 'rb') as f:
                for chunk in iter(lambda: f.read(1 << 20), b''):
                    h.update(chunk)
            hx = h.hexdigest().encode()
            if h.digest() in data or hx in data or hx.upper() in data:
                return elf
    return None


class ShaMismatch(Exception):
    pass


def extract(sha, dest=None, verify=True):
    """Decompress an archived ELF to `dest` (or a tmp file). Returns the path.
    `sha` may be a prefix (>= 8 hex chars); all of it must match the recorded
    sha. With `verify`, the decompressed ELF must hash to the recorded sha
    (app_elf_sha256 is sha256 of the ELF file), else ShaMismatch."""
    full = _meta_sha(sha)
    if full is None and os.path.exists(os.path.join(BLOBS_DIR, f'{sha[:8].lower()}.json')):
        raise ShaMismatch(f'archived build {sha[:8]} is not {sha}')
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
    if verify and full:
        h = hashlib.sha256(open(dest, 'rb').read()).hexdigest()
        if h != full:
            os.unlink(dest)
            raise ShaMismatch(f'archived ELF {blob} hashes to {h[:16]}, '
                              f'not the recorded {full[:16]}')
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
    d.add_argument('--search', action='append', default=[], metavar='DIR',
                   help='extra build dir to search when the archive has no match')

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
        try:
            print(extract(sha, args.out))
        except ShaMismatch as e:
            print(e, file=sys.stderr)
            return 1
        return 0

    if args.cmd == 'decode':
        in_core = sha_from_core(args.core)
        if args.sha:
            sha, how = lookup(sha=args.sha), 'sha'
            if sha and in_core and in_core != sha:
                print(f'--sha {args.sha[:16]} disagrees with the sha in the core '
                      f'({in_core[:16]})', file=sys.stderr)
                return 1
        elif in_core:
            sha, how = in_core, 'sha-in-core'
        elif (elf := local_elf_for_core(args.core, args.search)):
            print(f'matched local build {elf} (not archived; archiving it)', file=sys.stderr)
            try:
                archive(args.device or 'unknown', 'found-local', elf=elf, bin=elf[:-4] + '.bin')
            except Exception as e:
                print(f'archiving failed ({e}); decoding anyway', file=sys.stderr)
            return subprocess.run(['esp-coredump', 'info_corefile', '--core-format',
                                   args.core_format, '-c', args.core, elf]).returncode
        elif args.device or args.at:
            sha = lookup(args.device, args.at)
            how = f'device={args.device} at={args.at or "latest"}'
            print('WARNING: no archived sha found in the core; guessing the ELF from '
                  'the flash history. esp-coredump will reject it if it is wrong.',
                  file=sys.stderr)
        else:
            sha, how = None, ''
        if not sha:
            print('could not match this core to an archived ELF '
                  '(pass --sha, or --device/--at to guess from the flash history)',
                  file=sys.stderr)
            return 1
        print(f'matched build {sha[:8]} ({how})', file=sys.stderr)
        try:
            elf = extract(sha)
        except (ShaMismatch, FileNotFoundError) as e:
            print(e, file=sys.stderr)
            return 1
        try:
            return subprocess.run(['esp-coredump', 'info_corefile',
                                   '--core-format', args.core_format,
                                   '-c', args.core, elf]).returncode
        finally:
            os.unlink(elf)


if __name__ == '__main__':
    sys.exit(main())
