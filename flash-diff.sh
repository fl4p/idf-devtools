#!/usr/bin/env bash
# flash-diff.sh — convenience wrapper for `esptool write_flash --diff-with`.
#
# Reads build/flasher_args.json (same source idf.py uses) so you can omit:
#   * the `write_flash` subcommand
#   * the flash offset (looked up by basename in flash_files)
#   * everything (defaults to the app partition)
#
# Usage (all equivalent on a typical idf project):
#   ./flash-diff.sh -p "$ESPPORT"
#   ./flash-diff.sh -p "$ESPPORT" build/<project>.bin
#   ./flash-diff.sh -p "$ESPPORT" 0x10000 build/<project>.bin
#   ./flash-diff.sh -p "$ESPPORT" write_flash 0x10000 build/<project>.bin
#
# Cache layout (scoped by port so multiple boards don't collide):
#   "$ESPTOOL_DIFF_CACHE"/<port-tag>/<offset>.bin
# Defaults:
#   ESPTOOL_DIFF_CACHE = build/.flash-diff
#   BUILD_DIR          = build
#   ESPTOOL            = esptool.py

set -euo pipefail

# Prefer the v5 entry point (`esptool`, no .py) since --diff-with needs >=5.2.
# ESP-IDF 5.5's bundled venv only has v4 (`esptool.py`); install v5 standalone
# (`pip install --user 'esptool>=5.2'`) to get incremental flashing.
if [[ -z "${ESPTOOL:-}" ]]; then
  if command -v esptool >/dev/null 2>&1; then ESPTOOL=esptool
  else ESPTOOL=esptool.py
  fi
fi
BUILD_DIR="${BUILD_DIR:-build}"
FLASHER_ARGS="$BUILD_DIR/flasher_args.json"

args=("$@")

# --- detect esptool version --------------------------------------------------
# v5 renamed subcommands from `write_flash` to `write-flash`; v5.2 added --diff-with.
esptool_supports_diff=0
esptool_major=0
esptool_ver="$("$ESPTOOL" version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1 || true)"
if [[ -n "$esptool_ver" ]]; then
  IFS=. read -r esptool_major _min <<<"$esptool_ver"
  if (( esptool_major > 5 )) || (( esptool_major == 5 && _min >= 2 )); then
    esptool_supports_diff=1
  fi
fi
write_flash_cmd=write_flash
(( esptool_major >= 5 )) && write_flash_cmd=write-flash

# --- flasher_args.json helpers ----------------------------------------------
read_json() { # $1 = dotted path, e.g. .app.offset
  python3 - "$FLASHER_ARGS" "$1" <<'PY' 2>/dev/null || true
import json, sys
try:
    cur = json.load(open(sys.argv[1]))
    for k in sys.argv[2].lstrip('.').split('.'):
        cur = cur[k]
    print(cur)
except Exception:
    pass
PY
}

lookup_offset_for_file() { # $1 = path; matches flash_files by basename
  python3 - "$FLASHER_ARGS" "$1" <<'PY' 2>/dev/null || true
import json, sys, os
try:
    d = json.load(open(sys.argv[1]))
    target = os.path.basename(sys.argv[2])
    for off, path in d.get('flash_files', {}).items():
        if os.path.basename(path) == target:
            print(off); break
except Exception:
    pass
PY
}

# --- split user args into globals (pre-write_flash) and positional ----------
globals_=()
positional=()
had_write_flash=0

for ((i=0; i<${#args[@]}; i++)); do
  case "${args[i]}" in
    write_flash|write-flash)
      globals_=("${args[@]:0:i}")
      positional=("${args[@]:i+1}")
      had_write_flash=1
      break;;
  esac
done

if (( had_write_flash == 0 )); then
  # consume leading flags into globals; first non-flag token starts positional
  i=0
  while (( i < ${#args[@]} )); do
    tok="${args[i]}"
    if [[ "$tok" == "--" ]]; then globals_+=("$tok"); ((++i)); break; fi
    if [[ "$tok" != -* ]]; then break; fi
    case "$tok" in
      -p|--port|-b|--baud|--chip|--before|--after|--connect-attempts)
        globals_+=("$tok" "${args[i+1]:-}"); ((i+=2));;
      *) globals_+=("$tok"); ((++i));;
    esac
  done
  positional=("${args[@]:i}")
fi

# --- expand positional into (offset, file) pairs ----------------------------
pairs_off=()
pairs_file=()

if (( ${#positional[@]} == 0 )); then
  app_off="$(read_json .app.offset)"
  app_file="$(read_json .app.file)"
  if [[ -z "$app_off" || -z "$app_file" ]]; then
    echo "flash-diff: no positional args and could not read app entry from $FLASHER_ARGS" >&2
    exit 2
  fi
  pairs_off+=("$app_off")
  pairs_file+=("$BUILD_DIR/$app_file")
else
  i=0
  while (( i < ${#positional[@]} )); do
    tok="${positional[i]}"
    if [[ "$tok" =~ ^0x[0-9a-fA-F]+$ ]]; then
      nxt="${positional[i+1]:-}"
      [[ -n "$nxt" ]] || { echo "flash-diff: offset $tok without a file" >&2; exit 2; }
      pairs_off+=("$tok")
      pairs_file+=("$nxt")
      ((i+=2))
    else
      f="$tok"
      [[ -f "$f" ]] || { echo "flash-diff: file not found: $f" >&2; exit 2; }
      off="$(lookup_offset_for_file "$f")"
      if [[ -z "$off" ]]; then
        echo "flash-diff: no offset for $(basename "$f") in $FLASHER_ARGS" >&2
        exit 2
      fi
      pairs_off+=("$off")
      pairs_file+=("$f")
      ((++i))
    fi
  done
fi

# --- cache scope (by port) --------------------------------------------------
port=""
for ((i=0; i<${#globals_[@]}-1; i++)); do
  case "${globals_[i]}" in
    -p|--port) port="${globals_[i+1]}";;
  esac
done
port_tag="${port##*/}"; port_tag="${port_tag:-default}"

cache_root="${ESPTOOL_DIFF_CACHE:-build/.flash-diff}"
cache_dir="$cache_root/$port_tag"
mkdir -p "$cache_dir"

# --- assemble command -------------------------------------------------------
# esptool v5's --diff-with is variadic and zipped 1:1 with the (offset, file)
# pairs. Use 'skip' for regions we have no snapshot for, and put the whole
# --diff-with list LAST so its greedy consumption stops at end-of-args.
cmd=("$ESPTOOL" "${globals_[@]}" "$write_flash_cmd")
for ((k=0; k<${#pairs_off[@]}; k++)); do
  cmd+=("${pairs_off[k]}" "${pairs_file[k]}")
done

diff_args=()
any_snap=0
for ((k=0; k<${#pairs_off[@]}; k++)); do
  key="$(printf '%s' "${pairs_off[k]}" | tr '[:upper:]' '[:lower:]')"
  snap="$cache_dir/$key.bin"
  if [[ -f "$snap" ]]; then
    diff_args+=("$snap")
    any_snap=1
    echo "flash-diff: diffing ${pairs_file[k]} against $snap" >&2
  else
    diff_args+=("skip")
  fi
done

if (( any_snap )); then
  if (( esptool_supports_diff )); then
    cmd+=(--diff-with "${diff_args[@]}")

    # If every real snapshot is fresh, skip the pre-write MD5 verify
    # (esptool's --no-diff-verify — equivalent to "trust flash content").
    # Default age window: 6 h, override with FLASH_DIFF_TRUST_AGE_MIN.
    trust_age_min="${FLASH_DIFF_TRUST_AGE_MIN:-360}"
    all_fresh=1
    for s in "${diff_args[@]}"; do
      [[ "$s" == "skip" ]] && continue
      if [[ -z "$(find "$s" -mmin -"$trust_age_min" -print 2>/dev/null)" ]]; then
        all_fresh=0; break
      fi
    done
    if (( all_fresh )); then
      cmd+=(--no-diff-verify)
      echo "flash-diff: snapshots <${trust_age_min} min old; --no-diff-verify" >&2
    fi
  else
    echo "flash-diff: esptool ${esptool_ver:-?} lacks --diff-with (needs >=5.2); full flash. Install standalone: pip install --user 'esptool>=5.2'" >&2
  fi
else
  echo "flash-diff: no snapshots yet; full flash" >&2
fi

echo "+ ${cmd[*]}" >&2
"${cmd[@]}"

# --- snapshot for next run --------------------------------------------------
for ((k=0; k<${#pairs_off[@]}; k++)); do
  key="$(printf '%s' "${pairs_off[k]}" | tr '[:upper:]' '[:lower:]')"
  cp -f "${pairs_file[k]}" "$cache_dir/$key.bin"
done
echo "flash-diff: snapshotted ${#pairs_off[@]} file(s) to $cache_dir" >&2
