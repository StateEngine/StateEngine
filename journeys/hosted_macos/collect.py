#!/usr/bin/env python3
"""Export finite account-free receipts; never upload fixture homes or extracted packages."""
import argparse
from pathlib import Path
import shutil
from common import digest, require, save


def collect(source, destination):
    source, destination = Path(source), Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    files, excluded, errors, total = [], [], [], 0
    for path in sorted(source.iterdir()) if source.is_dir() else []:
        if path.is_symlink() or not path.is_file() or path.suffix not in ('.json', '.stdout', '.stderr'):
            excluded.append(path.name)
            continue
        size = path.stat().st_size
        if size > 4 * 1024**2 or total + size > 64 * 1024**2 or len(files) >= 300:
            errors.append(dict(path=path.name, bytes=size, reason='Finite artifact bound exceeded; not uploaded'))
            continue
        shutil.copyfile(path, destination / path.name)
        require(digest(path) == digest(destination / path.name), 'Evidence changed during collection')
        files.append(dict(path=path.name, bytes=size, sha256=digest(destination / path.name)))
        total += size
    if not any(row['path'] == 'results.json' for row in files):
        errors.append(dict(reason='Five-row results receipt is missing'))
    save(destination / 'artifact-manifest.json', dict(schema='se.hosted-evidence/v1', files=files,
         excluded=excluded, errors=errors, complete=not errors, bytes=total,
         scope='Only top-level account-free receipts; private homes, source and binary packages excluded'))
    return not errors


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(0 if collect(args.source, args.out) else 1)
