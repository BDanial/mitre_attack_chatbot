"""Small terminal progress display for offline data jobs."""

import sys


def show_progress(completed: int, total: int, stage: str) -> None:
    percent = completed * 100 // total if total else 100
    filled = percent * 25 // 100
    bar = "#" * filled + "-" * (25 - filled)
    line = f"[{bar}] {percent:3d}%  {completed:,}/{total:,} rows | {stage}"
    if sys.stdout.isatty():
        print("\r" + line.ljust(100), end="", flush=True)
    else:
        print(line, flush=True)
