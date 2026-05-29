"""ELF symbol lookup for an ESP-IDF firmware build: resolve `<symbol>[.field…][+offset]`
to an address, or list symbols matching a pattern.

As a CLI:
    peek_symbols.py <symbol>[.field][+off]   -> 0x<addr>  <size>  <name>
    peek_symbols.py -l <pattern>             -> matching symbols (substring or /regex/)

As a library it also rewrites a `peek <symbol>` console line to `peek 0x<addr> <len>`
(`preprocess_peek`) and renders a DWARF-typed struct dump (`format_struct_dump`).
The ELF on disk must match the flashed image — there's no build-id check yet.

Dotted member access (`<obj>.<field>.<sub>`) walks DWARF to compute the field offset;
pyelftools is imported lazily — from the system environment, or the IDF venv's site-packages.
"""

import glob
import json
import os
import re
import shutil
import struct as _struct
import subprocess
import sys


# `<symbol>[+offset]` — keep symbol alphabet narrow but include common C/C++ chars.
_PEEK_TARGET_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_$:.]*)(?:\+(0x[0-9a-fA-F]+|\d+))?$")


def _build_elf_name(build_dir: str) -> str | None:
    """The app ELF filename for a build dir, from project_description.json."""
    desc = os.path.join(build_dir, "project_description.json")
    if os.path.exists(desc):
        try:
            return json.load(open(desc))["app_elf"]
        except Exception:
            pass
    return None


def find_elf(explicit: str | None = None) -> str | None:
    """Find the firmware ELF. `explicit` (or $IDF_ELF) wins; else the newest
    `<build*>/<app>.elf` under the current directory (name from
    project_description.json, falling back to any *.elf)."""
    if explicit:
        return explicit if os.path.exists(explicit) else None
    env = os.environ.get("IDF_ELF")
    if env and os.path.exists(env):
        return env
    hits = []
    for bd in glob.glob("build*"):
        if not os.path.isdir(bd):
            continue
        name = _build_elf_name(bd)
        cands = [os.path.join(bd, name)] if name else glob.glob(os.path.join(bd, "*.elf"))
        for p in cands:
            if os.path.exists(p):
                hits.append((os.path.getmtime(p), p))
    if not hits:
        return None
    hits.sort(reverse=True)  # newest mtime first
    return hits[0][1]


def _find_tool(tool: str) -> str | None:
    """Locate a binutils tool from the xtensa toolchain; fall back to llvm-/system equivalents."""
    for name in (f"xtensa-esp32s3-elf-{tool}", f"xtensa-esp-elf-{tool}", f"xtensa-esp32-elf-{tool}"):
        p = shutil.which(name)
        if p:
            return p
    base = os.path.expanduser("~/.espressif/tools/xtensa-esp-elf")
    if os.path.isdir(base):
        for ver in sorted(os.listdir(base), reverse=True):
            p = os.path.join(base, ver, f"xtensa-esp-elf/bin/xtensa-esp32s3-elf-{tool}")
            if os.path.exists(p):
                return p
    return shutil.which(f"llvm-{tool}") or shutil.which(tool)


def find_nm() -> str | None:
    return _find_tool("nm")


_SIMPLE_BASE_RE = re.compile(r"^[A-Za-z_][\w:$.]*")


def _add_demangled_aliases(syms: dict[str, tuple[int, int]]) -> None:
    """For every `_Z*` mangled name, run c++filt and add a simple-identifier alias when unambiguous.

    `_Z8setupCliv` demangles to `setupCli()` — alias `setupCli` lets the user type the natural
    function name. Methods `Ns::Cls::meth(args)` get an alias `Ns::Cls::meth`. Aliases that
    collide with an existing key (real global or another mangled symbol's base) are dropped so we
    never silently pick the wrong address.
    """
    mangled = [n for n in syms if n.startswith("_Z")]
    if not mangled:
        return
    cxxfilt = _find_tool("c++filt")
    if not cxxfilt:
        return
    try:
        out = subprocess.check_output(
            [cxxfilt], input="\n".join(mangled), text=True, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, OSError):
        return
    demangled = out.splitlines()
    if len(demangled) != len(mangled):
        return
    # candidates[alias] = (rank, mangled-or-"-ambig"). rank 0 = pure `name(args)` or bare data
    # symbol; rank 1 = something nested (lambda inside a function, local static, etc). A lower-rank
    # candidate beats higher-rank ones, so the real `setupCli` wins over its inner lambdas.
    candidates: dict[str, tuple[int, str]] = {}
    for m, d in zip(mangled, demangled):
        if d == m:
            continue
        match = _SIMPLE_BASE_RE.match(d)
        if not match:
            continue
        alias = match.group(0)
        if alias == m or alias in syms:
            continue
        tail = d[len(alias):]
        pure = (tail == "") or (tail.startswith("(") and "::" not in tail)
        rank = 0 if pure else 1
        prev = candidates.get(alias)
        if prev is None or rank < prev[0]:
            candidates[alias] = (rank, m)
        elif rank == prev[0] and prev[1] != m:
            candidates[alias] = (rank, "")  # genuine collision at the same rank — drop
    for alias, (_, m) in candidates.items():
        if m and alias not in syms:
            syms[alias] = syms[m]


# (elf_path -> (mtime, {name: (addr, size)}))
_CACHE: dict[str, tuple[float, dict[str, tuple[int, int]]]] = {}


def load_symbols(elf_path: str) -> dict[str, tuple[int, int]]:
    """Parse `nm -S --defined-only <elf>` once per (path, mtime). Returns {name: (addr, size)}."""
    if not elf_path or not os.path.exists(elf_path):
        raise FileNotFoundError(f"ELF not found: {elf_path!r}")
    mtime = os.path.getmtime(elf_path)
    cached = _CACHE.get(elf_path)
    if cached and cached[0] == mtime:
        return cached[1]
    nm = find_nm()
    if not nm:
        raise FileNotFoundError(
            "no nm found; source idf-export.sh or install the xtensa toolchain")
    out = subprocess.check_output(
        [nm, "-S", "--defined-only", elf_path],
        text=True, stderr=subprocess.DEVNULL)
    syms: dict[str, tuple[int, int]] = {}
    for line in out.splitlines():
        parts = line.split(None, 3)
        if len(parts) == 4:
            addr_hex, size_hex, _t, name = parts
        elif len(parts) == 3:
            addr_hex, _t, name = parts
            size_hex = "0"
        else:
            continue
        try:
            addr = int(addr_hex, 16)
            size = int(size_hex, 16)
        except ValueError:
            continue
        # nm sometimes emits the same name twice (weak + strong); keep the one with size.
        prev = syms.get(name)
        if prev is None or (prev[1] == 0 and size > 0):
            syms[name] = (addr, size)
    _add_demangled_aliases(syms)
    _CACHE[elf_path] = (mtime, syms)
    return syms


def resolve(target: str, symbols: dict[str, tuple[int, int]],
            elf_path: str | None = None) -> tuple[int, int, str]:
    """`<symbol>[.field…][+offset]` -> (addr, size_hint, base_name). Raises KeyError/ValueError.

    Dotted member access walks DWARF; the resolved size is the leaf field's `DW_AT_byte_size`.
    """
    m = _PEEK_TARGET_RE.match(target)
    if not m:
        raise ValueError(f"bad peek target: {target!r}")
    name, off = m.group(1), m.group(2)
    member_path: list[str] = []
    if name not in symbols and "." in name:
        head, *member_path = name.split(".")
        if head not in symbols:
            raise KeyError(f"symbol not found: {head!r} (base of {name!r})")
        base_addr, base_size = symbols[head]
        if not elf_path:
            raise KeyError(
                f"member access {name!r} needs DWARF; pass --elf or set $IDF_ELF")
        moff, leaf_size, _leaf_type = resolve_member_path(elf_path, head, member_path)
        addr, size, name = base_addr + moff, leaf_size, name
    elif name in symbols:
        addr, size = symbols[name]
    else:
        raise KeyError(f"symbol not found: {name!r}")
    if off:
        off_n = int(off, 16) if off.startswith("0x") else int(off)
        addr += off_n
        size = max(0, size - off_n)
    return addr, size, name


# ---- DWARF-based member resolution -----------------------------------------------------------

_ELFTOOLS = None
_ELFTOOLS_TRIED = False


def _get_elftools():
    """Lazy import of pyelftools; falls back to scanning the IDF venv site-packages."""
    global _ELFTOOLS, _ELFTOOLS_TRIED
    if _ELFTOOLS_TRIED:
        return _ELFTOOLS
    _ELFTOOLS_TRIED = True
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore
        _ELFTOOLS = ELFFile
        return ELFFile
    except ImportError:
        pass
    for candidate in sorted(glob.glob(os.path.expanduser(
            "~/.espressif/python_env/idf*/lib/python*/site-packages")), reverse=True):
        if os.path.isdir(os.path.join(candidate, "elftools")):
            sys.path.insert(0, candidate)
            try:
                from elftools.elf.elffile import ELFFile  # type: ignore
                _ELFTOOLS = ELFFile
                return ELFFile
            except ImportError:
                sys.path.pop(0)
    return None


_QUAL_TAGS = {
    'DW_TAG_typedef', 'DW_TAG_const_type', 'DW_TAG_volatile_type',
    'DW_TAG_restrict_type', 'DW_TAG_atomic_type',
}

# (elf_path -> (mtime, file_handle, ELFFile, {var_name: type_DIE}))
_DWARF_CACHE: dict[str, tuple] = {}


def _strip_quals(die):
    while die.tag in _QUAL_TAGS and 'DW_AT_type' in die.attributes:
        die = die.get_DIE_from_attribute('DW_AT_type')
    return die


def _type_name(die) -> str:
    nm = die.attributes.get('DW_AT_name')
    if nm:
        return nm.value.decode('utf-8', 'replace')
    if die.tag in ('DW_TAG_reference_type', 'DW_TAG_rvalue_reference_type',
                   'DW_TAG_pointer_type') and 'DW_AT_type' in die.attributes:
        sigil = '*' if die.tag == 'DW_TAG_pointer_type' else '&'
        return _type_name(die.get_DIE_from_attribute('DW_AT_type')) + sigil
    if die.tag in ('DW_TAG_structure_type', 'DW_TAG_class_type', 'DW_TAG_union_type'):
        return f"(anon {die.tag.split('_')[-2]})"
    return die.tag.replace('DW_TAG_', '')


def _byte_size(die) -> int:
    bs = die.attributes.get('DW_AT_byte_size')
    return int(bs.value) if bs else 0


def _data_member_offset(attr) -> int:
    """Decode DW_AT_data_member_location — usually a constant, sometimes a DW_OP_plus_uconst exprloc."""
    if attr is None:
        return 0
    v = attr.value
    if isinstance(v, int):
        return v
    if isinstance(v, list) and len(v) >= 2 and v[0] == 0x23:  # DW_OP_plus_uconst, ULEB128
        n, shift = 0, 0
        for b in v[1:]:
            n |= (b & 0x7f) << shift
            if not (b & 0x80):
                return n
            shift += 7
    return 0


def _get_dwarf_var_types(elf_path: str) -> dict[str, object]:
    """{global var name -> stripped type DIE}. Keeps the ELF file open for DIE lifetime."""
    mtime = os.path.getmtime(elf_path)
    cached = _DWARF_CACHE.get(elf_path)
    if cached and cached[0] == mtime:
        return cached[3]
    if cached:
        try:
            cached[1].close()
        except Exception:
            pass
    ELFFile = _get_elftools()
    if not ELFFile:
        raise RuntimeError(
            "pyelftools missing — `pip install pyelftools`, or source idf-export.sh "
            "(the IDF venv has it)")
    f = open(elf_path, "rb")
    elf = ELFFile(f)
    if not elf.has_dwarf_info():
        f.close()
        raise RuntimeError(f"{elf_path}: no DWARF (rebuild with -g)")
    dw = elf.get_dwarf_info()
    name_to_type: dict[str, object] = {}
    for cu in dw.iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag != 'DW_TAG_variable':
                continue
            nm = die.attributes.get('DW_AT_name')
            if not nm or 'DW_AT_type' not in die.attributes:
                continue
            name = nm.value.decode('utf-8', 'replace')
            if name not in name_to_type:
                name_to_type[name] = _strip_quals(die.get_DIE_from_attribute('DW_AT_type'))
    _DWARF_CACHE[elf_path] = (mtime, f, elf, name_to_type)
    return name_to_type


def _find_member(klass, field: str, base_off: int):
    """BFS over direct members + inherited bases. Returns (member_die, absolute_offset) or None."""
    target = field.encode('utf-8')
    queue = [(klass, base_off)]
    seen: set[int] = set()
    while queue:
        cur, off = queue.pop(0)
        if cur.offset in seen:
            continue
        seen.add(cur.offset)
        bases = []
        for child in cur.iter_children():
            if child.tag == 'DW_TAG_member':
                nm = child.attributes.get('DW_AT_name')
                if nm and nm.value == target:
                    moff = _data_member_offset(child.attributes.get('DW_AT_data_member_location'))
                    return child, off + moff
            elif child.tag == 'DW_TAG_inheritance':
                inh_off = _data_member_offset(child.attributes.get('DW_AT_data_member_location'))
                bases.append((_strip_quals(child.get_DIE_from_attribute('DW_AT_type')),
                              off + inh_off))
        queue.extend(bases)
    return None


def resolve_member_path(elf_path: str, base_name: str,
                        member_path: list[str]) -> tuple[int, int, str]:
    """For `base.m1.m2…`, return (offset_within_base, leaf_byte_size, leaf_type_name)."""
    _off, _sz, _name, _die = _walk_member_path(elf_path, base_name, member_path)
    return _off, _sz, _name


def _walk_member_path(elf_path: str, base_name: str, member_path: list[str]):
    """Internal: also returns the resolved leaf type DIE (used by `peek-struct`)."""
    types = _get_dwarf_var_types(elf_path)
    if base_name not in types:
        raise KeyError(f"no DWARF type info for {base_name!r}")
    cur = types[base_name]
    offset = 0
    for field in member_path:
        if cur.tag not in ('DW_TAG_structure_type', 'DW_TAG_class_type', 'DW_TAG_union_type'):
            raise KeyError(
                f"cannot access .{field} — {_type_name(cur)} is not a struct/class/union")
        hit = _find_member(cur, field, 0)
        if not hit:
            raise KeyError(f"no member {field!r} in {_type_name(cur)}")
        member_die, member_off = hit
        offset += member_off
        cur = _strip_quals(member_die.get_DIE_from_attribute('DW_AT_type'))
    return offset, _byte_size(cur), _type_name(cur), cur


def resolve_for_dump(elf_path: str, target: str) -> tuple[int, int, object, str]:
    """For `peek-struct <symbol>[.field…]`, return (addr, size, struct_DIE, label)."""
    m = _PEEK_TARGET_RE.match(target)
    if not m or m.group(2):
        raise ValueError(f"peek-struct: bad target {target!r} (no +offset)")
    name = m.group(1)
    syms = load_symbols(elf_path)
    if "." in name:
        head, *member_path = name.split(".")
    else:
        head, member_path = name, []
    if head not in syms:
        raise KeyError(f"symbol not found: {head!r}")
    base_addr, _ = syms[head]
    off, sz, _tname, leaf_die = _walk_member_path(elf_path, head, member_path)
    return base_addr + off, sz or _byte_size(leaf_die), leaf_die, name


# ---- struct/class field enumeration + decoding -----------------------------------------------
#
# `peek-struct` reads the byte image once (via chunked peek host-side) and decodes per-field
# using DWARF: base types via DW_AT_encoding+size, enums by enumerator lookup, pointers as hex,
# scalar arrays inline (up to 8 elts), nested aggregates summarised — drill in by extending the
# dotted path. Bitfields, multi-dim arrays, and unions past their first variant are intentionally
# not handled: rare in this codebase, easy to add when needed.

def iter_struct_members(type_die, base_off: int = 0):
    """Yield (offset, name, member_type_DIE) for direct members + inherited bases (recursively)."""
    if type_die.tag not in ('DW_TAG_structure_type', 'DW_TAG_class_type', 'DW_TAG_union_type'):
        return
    for child in type_die.iter_children():
        if child.tag == 'DW_TAG_inheritance':
            inh_off = _data_member_offset(child.attributes.get('DW_AT_data_member_location'))
            base_die = _strip_quals(child.get_DIE_from_attribute('DW_AT_type'))
            yield from iter_struct_members(base_die, base_off + inh_off)
        elif child.tag == 'DW_TAG_member' and 'DW_AT_type' in child.attributes:
            # Skip static class members: DWARF emits them as DW_TAG_member with no
            # DW_AT_data_member_location (and usually DW_AT_declaration). Including them
            # bunches them at offset 0 of the parent, which looks like a real member but
            # collides with the actual first field (see std::atomic<T>::_S_alignment).
            if 'DW_AT_data_member_location' not in child.attributes:
                continue
            nm = child.attributes.get('DW_AT_name')
            if not nm:
                continue
            moff = _data_member_offset(child.attributes['DW_AT_data_member_location'])
            yield (base_off + moff,
                   nm.value.decode('utf-8', 'replace'),
                   child.get_DIE_from_attribute('DW_AT_type'))


# (DW_AT_encoding, byte_size) -> (struct fmt, label, is_float)
_BASE_FMT: dict[tuple[int, int], tuple[str, str, bool]] = {
    (0x02, 1): ('?',  'bool',     False),  # DW_ATE_boolean
    (0x04, 4): ('<f', 'float',    True),   # DW_ATE_float
    (0x04, 8): ('<d', 'double',   True),
    (0x05, 1): ('b',  'int8_t',   False),  # DW_ATE_signed
    (0x05, 2): ('<h', 'int16_t',  False),
    (0x05, 4): ('<i', 'int32_t',  False),
    (0x05, 8): ('<q', 'int64_t',  False),
    (0x06, 1): ('b',  'char',     False),  # DW_ATE_signed_char
    (0x07, 1): ('B',  'uint8_t',  False),  # DW_ATE_unsigned
    (0x07, 2): ('<H', 'uint16_t', False),
    (0x07, 4): ('<I', 'uint32_t', False),
    (0x07, 8): ('<Q', 'uint64_t', False),
    (0x08, 1): ('B',  'uchar',    False),  # DW_ATE_unsigned_char
}


def _decode_base(die, buf: bytes) -> str:
    enc = die.attributes.get('DW_AT_encoding')
    sz = die.attributes.get('DW_AT_byte_size')
    if not enc or not sz:
        return "<base?>"
    sz_v = int(sz.value)
    if len(buf) < sz_v:
        return f"<short {len(buf)}/{sz_v}>"
    fmt = _BASE_FMT.get((int(enc.value), sz_v))
    if not fmt:
        return f"<enc={enc.value} sz={sz_v}> {buf[:sz_v].hex()}"
    f, _label, is_float = fmt
    val, = _struct.unpack_from(f, buf, 0)
    if is_float:
        return f"{val:.6g}"
    if isinstance(val, bool):
        return "true" if val else "false"
    return f"{val}"


def _decode_enum(die, buf: bytes) -> str:
    sz = _byte_size(die) or 4
    if len(buf) < sz:
        return f"<short {len(buf)}/{sz}>"
    val = int.from_bytes(buf[:sz], 'little', signed=False)
    for child in die.iter_children():
        if child.tag == 'DW_TAG_enumerator':
            cv = child.attributes.get('DW_AT_const_value')
            if cv is not None and cv.value == val:
                nm = child.attributes.get('DW_AT_name')
                return f"{nm.value.decode('utf-8','replace') if nm else '?'} ({val})"
    return f"{val} (<unknown enum>)"


def _decode_pointer(buf: bytes) -> str:
    if len(buf) < 4:
        return "<short ptr>"
    v = int.from_bytes(buf[:4], 'little', signed=False)
    return f"0x{v:08x}"


def _array_count(die) -> int | None:
    """Total element count across one or more DW_TAG_subrange_type children."""
    n = 1
    found = False
    for child in die.iter_children():
        if child.tag == 'DW_TAG_subrange_type':
            ub = child.attributes.get('DW_AT_upper_bound')
            cn = child.attributes.get('DW_AT_count')
            if cn is not None:
                n *= cn.value
            elif ub is not None:
                n *= (ub.value + 1)
            else:
                return None
            found = True
    return n if found else None


def _decode_array(die, buf: bytes) -> str:
    elem_die = _strip_quals(die.get_DIE_from_attribute('DW_AT_type'))
    elem_sz = _byte_size(elem_die)
    n = _array_count(die)
    if not elem_sz or not n:
        return f"<array elem_sz={elem_sz} n={n}>"
    # char[] gets a string-ish render
    if elem_die.tag == 'DW_TAG_base_type' and elem_sz == 1:
        enc = elem_die.attributes.get('DW_AT_encoding')
        if enc and int(enc.value) in (0x06, 0x08):  # char / uchar
            raw = bytes(buf[:n]).split(b'\x00', 1)[0]
            try:
                return f"{raw.decode('utf-8')!r} ({n} B)"
            except UnicodeDecodeError:
                return f"{raw!r} ({n} B)"
    show = min(n, 8)
    items = []
    for i in range(show):
        slc = buf[i * elem_sz:(i + 1) * elem_sz]
        items.append(_decode_value(elem_die, slc, depth=1))
    suffix = "" if show == n else f", … +{n - show}"
    return f"[{', '.join(items)}{suffix}]"


def _decode_value(die, buf: bytes, depth: int = 0) -> str:
    die = _strip_quals(die)
    if die.tag == 'DW_TAG_base_type':
        return _decode_base(die, buf)
    if die.tag in ('DW_TAG_pointer_type', 'DW_TAG_reference_type',
                   'DW_TAG_rvalue_reference_type'):
        return _decode_pointer(buf)
    if die.tag == 'DW_TAG_enumeration_type':
        return _decode_enum(die, buf)
    if die.tag == 'DW_TAG_array_type':
        return _decode_array(die, buf)
    if die.tag in ('DW_TAG_structure_type', 'DW_TAG_class_type', 'DW_TAG_union_type'):
        sz = _byte_size(die)
        return f"<{_type_name(die)}, {sz} B>"
    return f"<{_type_name(die)}>"


_AGGREGATE_TAGS = ('DW_TAG_structure_type', 'DW_TAG_class_type', 'DW_TAG_union_type')


def _dump_struct(type_die, image: bytes, lines: list, indent: int,
                 depth_left: int, base_off: int) -> None:
    """Append decoded-member lines for `type_die` whose bytes live at `image[base_off:]`.

    Aggregate members expand into nested lines while `depth_left > 0`; when the budget
    runs out the same member prints as a one-liner summary so the user can drill in
    explicitly via a longer dotted path or larger depth.
    """
    prefix = "  " * indent
    for off, name, mdie in iter_struct_members(type_die):
        abs_off = base_off + off
        stripped = _strip_quals(mdie)
        sz = _byte_size(stripped) or 4
        type_label = _type_name(stripped)
        if abs_off + sz > len(image):
            lines.append(f"{prefix}+0x{abs_off:04x}  {type_label:<24}  {name:<28} <out of image>")
            continue
        if stripped.tag in _AGGREGATE_TAGS and depth_left > 0 and sz > 0:
            lines.append(f"{prefix}+0x{abs_off:04x}  {type_label:<24}  {name}")
            _dump_struct(stripped, image, lines, indent + 1, depth_left - 1, abs_off)
            continue
        val = _decode_value(mdie, image[abs_off:abs_off + sz])
        lines.append(f"{prefix}+0x{abs_off:04x}  {type_label:<24}  {name:<28} = {val}")


def format_struct_dump(elf_path: str, target: str, image: bytes, base_addr: int,
                       max_depth: int = 2) -> str:
    """Render `image` (bytes at `base_addr`) as `target`'s DWARF-typed struct/class layout.

    `max_depth` controls how many levels of embedded aggregates expand inline; deeper ones
    keep the one-line `<TypeName, N B>` summary (drill in with a longer dotted path).
    """
    _, size, type_die, label = resolve_for_dump(elf_path, target)
    if type_die.tag not in _AGGREGATE_TAGS:
        return (f"{label}: not a struct/class/union ({_type_name(type_die)}); "
                f"use `peek {label}` for a scalar/pointer.")
    out = [f"{label} @ 0x{base_addr:08x}  ({_type_name(type_die)}, {size} B, depth≤{max_depth})"]
    _dump_struct(type_die, image, out, indent=1, depth_left=max_depth, base_off=0)
    return "\n".join(out)


def is_hex_address(token: str) -> bool:
    """True if `token` looks like an address literal already (skip ELF lookup)."""
    if token.startswith(("0x", "0X")):
        return all(c in "0123456789abcdefABCDEF" for c in token[2:]) and len(token) > 2
    # bare hex is ambiguous with bare-named symbols; require 0x prefix.
    return False


def preprocess_peek(cmd: str, elf_path: str | None) -> str:
    """If `cmd` is `peek <symbol>[+off] [len]`, rewrite to `peek 0x<addr> <len>`. Else passthrough."""
    parts = cmd.strip().split()
    if len(parts) < 2 or parts[0] != "peek":
        return cmd
    target = parts[1]
    if is_hex_address(target):
        return cmd
    if not elf_path:
        raise FileNotFoundError(
            "no firmware ELF found; build, set $IDF_ELF, or pass --elf to resolve symbols")
    syms = load_symbols(elf_path)
    addr, size_hint, _ = resolve(target, syms, elf_path)
    if len(parts) >= 3:
        len_arg = parts[2]
    elif size_hint > 0:
        len_arg = str(min(size_hint, 256))
    else:
        len_arg = "4"  # matches firmware default; typed u32 print is what users want most often
    return f"peek 0x{addr:08x} {len_arg}"


def format_sym_list(elf_path: str | None, pattern: str, limit: int = 40) -> str:
    """Render `sym <pattern>` output. `/regex/` runs as regex; else case-insensitive substring."""
    if not elf_path:
        return "sym: no firmware ELF found; build, set $IDF_ELF, or pass --elf"
    try:
        syms = load_symbols(elf_path)
    except Exception as e:
        return f"sym: {e}"
    if not pattern:
        return f"sym: expected <pattern> (substring, or /regex/) — {len(syms)} symbols loaded"
    if len(pattern) >= 2 and pattern.startswith("/") and pattern.endswith("/"):
        try:
            rx = re.compile(pattern[1:-1])
        except re.error as e:
            return f"sym: bad regex: {e}"
        hits = [(n, a, s) for n, (a, s) in syms.items() if rx.search(n)]
    else:
        needle = pattern.lower()
        hits = [(n, a, s) for n, (a, s) in syms.items() if needle in n.lower()]
    # Largest-first puts data objects (which are what people usually peek) above tiny stubs.
    hits.sort(key=lambda t: (-t[2], t[0]))
    lines = [f"  0x{a:08x} {s:>7}  {n}" for n, a, s in hits[:limit]]
    if not hits:
        lines.append(f"  (no symbols matching {pattern!r})")
    elif len(hits) > limit:
        lines.append(f"  ... {len(hits) - limit} more (refine pattern)")
    return "\n".join(lines)


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="Resolve ESP-IDF firmware symbols to addresses from the build ELF.")
    ap.add_argument("target", nargs="?",
                    help="symbol[.field…][+offset] to resolve to an address")
    ap.add_argument("-l", "--list", metavar="PATTERN",
                    help="list symbols matching a substring, or /regex/")
    ap.add_argument("-e", "--elf",
                    help="ELF path (default: $IDF_ELF, else newest build*/<app>.elf)")
    ap.add_argument("-n", "--limit", type=int, default=40, help="max rows for --list")
    args = ap.parse_args()

    elf = find_elf(args.elf)
    if not elf:
        print("no firmware ELF found; build, set $IDF_ELF, or pass --elf", file=sys.stderr)
        return 2
    if args.list is not None:
        print(format_sym_list(elf, args.list, args.limit))
        return 0
    if not args.target:
        ap.error("give a symbol to resolve, or --list <pattern>")
    try:
        addr, size, name = resolve(args.target, load_symbols(elf), elf)
    except (KeyError, ValueError, FileNotFoundError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"0x{addr:08x}\t{size}\t{name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
