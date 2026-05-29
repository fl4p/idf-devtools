#!/usr/bin/env python3
"""Build a littlefs image from a board config dir and flash it via parttool.py.

Usage:
    ./provision.py <board-name-under-config/>
    ./provision.py <path/to/dir/containing/conf/>

Env:
    ESPPORT    - serial port (required)
    IDF_TARGET - if set, must match board.conf::mcu when present
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

FOLDER = Path("config")


def die(msg: str, code: int = 1):
    print(msg, file=sys.stderr)
    sys.exit(code)


def resolve_src(board: str) -> Path:
    if not board:
        die(f"usage: {sys.argv[0]} <board>")
    p = Path(board.rstrip("/"))
    if (p / "conf").is_dir():
        return p
    p = FOLDER / board
    if p.is_dir():
        return p
    entries = sorted(e.name for e in FOLDER.iterdir() if not e.name.startswith(".")) if FOLDER.is_dir() else []
    die(f"invalid board '{board}', choose from\n" + "\n".join(entries))


def read_mcu(board_conf: Path) -> str | None:
    if not board_conf.is_file():
        return None
    for line in board_conf.read_text().splitlines():
        if line.startswith("mcu="):
            return line.split("=", 1)[1].strip()
    return None


def run(cmd: list[str]):
    print(" ".join(cmd))
    subprocess.run(cmd, check=True)


def main():
    board = sys.argv[1] if len(sys.argv) > 1 else ""
    src = resolve_src(board)
    print(f"SRC={src}")

    mcu = read_mcu(src / "conf" / "board.conf")
    idf_target = os.environ.get("IDF_TARGET")
    if mcu and idf_target and mcu != idf_target:
        die(f"ERROR: board.conf mcu='{mcu}' does not match IDF_TARGET='{idf_target}'")

    esp_port = os.environ.get("ESPPORT")
    if not esp_port:
        die("ERROR: ESPPORT is not set")

    bin_path = src.with_suffix(".bin")
    littlefs = shutil.which("littlefs-python") or "littlefs-python"
    parttool = shutil.which("parttool.py") or "parttool.py"
    # On Windows, a .py file isn't directly executable; route through the IDF interpreter.
    parttool_cmd = [sys.executable, parttool] if os.name == "nt" else [parttool]

    part = os.environ.get("LITTLEFS_PARTITION", "littlefs")
    fs_size = os.environ.get("LITTLEFS_SIZE", "0x20000")
    block_size = os.environ.get("LITTLEFS_BLOCK_SIZE", "4096")
    run([littlefs, "create", str(src), str(bin_path), "-v",
         f"--fs-size={fs_size}", "--name-max=64", f"--block-size={block_size}"])
    run([littlefs, "list", str(bin_path), "--block-size", block_size])
    run(parttool_cmd + ["--port", esp_port, "write_partition",
                        "--partition-name", part, "--input", str(bin_path)])


if __name__ == "__main__":
    main()
