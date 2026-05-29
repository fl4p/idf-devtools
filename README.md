# idf-devtools

Small, project-agnostic host-side tools for ESP-IDF / ESP32 development:
build/flash helpers, firmware-ELF archiving for coredump symbolication, and
partition forensics. Each script stands alone (Python stdlib + a couple of
common deps); nothing here is tied to a specific firmware.

## Tools

| tool | what it does | deps |
|---|---|---|
| `elf_archive.py` | Archive the build ELF on every flash, deduped by `app_elf_sha256`, so a later coredump can be symbolicated against the exact image. Auto-matches a core to its ELF. | `zstd` |
| `elf_archive_ext.py` | idf.py extension that calls `elf_archive.py` automatically after `flash`/`app-flash`. | — |
| `nvs_dump.py` | Parse/inspect an ESP32 NVS partition binary. | stdlib |
| `flash-diff.sh` | Incremental `esptool write_flash --diff-with`, offsets read from `flasher_args.json`. | `esptool ≥ 5.2` |
| `provision.py` | Build a LittleFS image from a config dir and write it with `parttool.py`. | `littlefs-python` |
| `peek_symbols.py` | Resolve a firmware symbol (`name[.field][+off]`) to an address, or list symbols. DWARF member access. | `pyelftools` (member access only) |
| `rts.py` | Pulse a serial port's RTS line (board reset). | `pyserial` |

## ELF archive + coredump workflow

`esp-coredump` is SHA-gated: a dump only decodes against the *exact* build ELF.
This keeps that ELF around per flash.

**Activate the auto-archive hook** (any ESP-IDF project, no per-project file):

```bash
export IDF_EXTRA_ACTIONS_PATH=/path/to/idf-devtools   # idf.py loads *_ext.py from here
export ELF_ARCHIVE_DEVICE=myboard                     # optional label (else the serial-port name)
idf.py flash monitor                                  # archives the ELF after flashing
```

Each unique build is stored once as `elf-archive/blobs/<sha8>.elf.zst`
(`zstd -19`, ~3.6× smaller); every flash appends a `{ts, device, method,
version, sha}` line to `elf-archive/index.jsonl`. Compression runs detached so
it never blocks the flash. Retention keeps the newest `ELF_ARCHIVE_KEEP` (30)
builds.

**Symbolicate a coredump** — it auto-matches the ELF by the sha embedded in the
dump:

```bash
python3 elf_archive.py decode coredump.bin                # auto-match
python3 elf_archive.py decode --device myboard core.bin   # fallback: latest build for a device
python3 elf_archive.py list                               # flash history
python3 elf_archive.py find --device myboard -o fw.elf    # extract an archived ELF
```

OTA pushers can archive directly: `import elf_archive; elf_archive.archive(name, method='ota')`.

### Config (env)
- `ELF_ARCHIVE_DIR` — archive location (default `./elf-archive`).
- `ELF_ARCHIVE_DEVICE` — device label for the index (the hook also honors `FUGU_DEVICE`).
- `ELF_ARCHIVE_KEEP` — retention cap, builds (default 30).

## Install

No install needed — run the scripts directly. Optionally `pip install -e .`
puts `elf-archive`, `nvs-dump`, and `provision` on `PATH`.

## License

Apache-2.0.
