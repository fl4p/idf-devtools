"""idf.py extension: archive the build ELF after `flash`/`app-flash`.

Wraps the stock flash callbacks so a serial flash records the project's build
ELF via elf_archive.py, letting a later coredump be symbolicated against the
exact image. Activate by putting this directory on IDF_EXTRA_ACTIONS_PATH:

    export IDF_EXTRA_ACTIONS_PATH=/path/to/idf-devtools

idf.py imports every module ending in `_ext` from those dirs. The device name
comes from $ELF_ARCHIVE_DEVICE (or $FUGU_DEVICE); absent that, the serial-port
basename is used. The archive lives at $ELF_ARCHIVE_DIR, else ./elf-archive.

Everything here is best-effort and guarded — a failure must never block a build
or flash.
"""
import os
import subprocess
import sys

_ARCHIVER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'elf_archive.py')


def _archive(global_args):
    try:
        dev = os.environ.get('ELF_ARCHIVE_DEVICE') or os.environ.get('FUGU_DEVICE')
        if not dev:
            port = getattr(global_args, 'port', None)
            dev = os.path.basename(port) if port else 'serial'
        build_dir = getattr(global_args, 'build_dir', None) or 'build'
        subprocess.run([sys.executable, _ARCHIVER, 'archive', dev,
                        '--method', 'serial', '--build-dir', build_dir], check=False)
    except Exception as e:
        print(f'elf-archive: skipped ({e})')


def action_extensions(base_actions, project_path):
    overrides = {}
    for name in ('flash', 'app-flash'):
        base = base_actions.get('actions', {}).get(name)
        if not base or 'callback' not in base:
            continue
        orig = base['callback']

        def make(orig_cb):
            def wrapped(action_name, ctx, global_args, **action_args):
                orig_cb(action_name, ctx, global_args, **action_args)
                _archive(global_args)
            return wrapped

        overrides[name] = dict(base, callback=make(orig))
    return {'actions': overrides}
