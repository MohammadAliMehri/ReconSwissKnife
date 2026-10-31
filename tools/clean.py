#!/usr/bin/env python3
"""List/remove ignored Python/Jython cache files only; preserve tracked/user files."""
import argparse
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def candidates():
    for directory, children, files in os.walk(ROOT, followlinks=False):
        children[:] = [name for name in children if name not in ('.git', '.venv', 'venv')
                       and not (Path(directory)/name).is_symlink()]
        for name in files:
            path = Path(directory)/name
            if path.is_symlink() or not (name.endswith(('.pyc', '.pyo', '$py.class'))):
                continue
            relative = str(path.relative_to(ROOT))
            ignored = subprocess.run(['git', 'check-ignore', '-q', '--', relative], cwd=ROOT).returncode == 0
            if ignored:
                yield path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    paths = sorted(candidates())
    for path in paths:
        print(path.relative_to(ROOT))
        if args.apply:
            path.unlink()
    if args.apply:
        for path in sorted(set(p.parent for p in paths), key=str, reverse=True):
            if path.name == '__pycache__' and not path.is_symlink() and not any(path.iterdir()):
                path.rmdir()
    print(('%d cache files removed.' if args.apply else '%d removable cache files; use --apply to remove.') % len(paths))


if __name__ == '__main__':
    main()
