#!/usr/bin/env python3
"""Read-only check. Never downloads or changes a reference."""
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parents[1]
pins = json.loads((root / 'refs/pins.json').read_text())
folders = {'teleportAPI': 'teleport', 'reviewReference': 'cad0p-swift-teleport'}
failed = False
for name, pin in pins.items():
    path = root / 'refs' / folders[name]
    if not path.exists():
        print(name + ': optional checkout absent')
        continue
    def git(*args):
        return subprocess.run(['git', '-C', str(path), *args], check=True,
                              stdout=subprocess.PIPE, text=True).stdout.strip()
    try:
        actual = git('rev-parse', 'HEAD')
        dirty = bool(git('status', '--porcelain', '--untracked-files=all'))
        valid = actual == pin['revision'] and not dirty
        print(name + ': ' + ('OK' if valid else 'FAIL') + ' expected=' + pin['revision'] + ' actual=' + actual)
        failed |= not valid
    except subprocess.CalledProcessError:
        failed = True
sys.exit(1 if failed else 0)
