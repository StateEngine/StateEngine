"""Retain output and build evidence without state homes, tokens or compiler caches."""
import os
from pathlib import Path
import shutil
import sys

root, destination = map(Path, sys.argv[1:])
destination.mkdir(exist_ok=True)
for directory, children, files in os.walk(root):
    children[:] = [name for name in children if name not in
                   ('fixture', 'home', 'source', 'target', 'native-build', 'extracted')
                   and not name.endswith('.symbols')]
    for name in files:
        source = Path(directory) / name
        if source.suffix in ('.json', '.jsonl', '.log', '.stdout', '.stderr', '.patch', '.rs') or name.endswith('.tar.gz'):
            target = destination / source.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
