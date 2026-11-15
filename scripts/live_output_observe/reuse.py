"""Observe a retained package after rechecking its complete archive provenance."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from build import TARGET, digest, save, unpack

root = Path(sys.argv[1]).resolve()
prior = Path(os.environ['OUTPUT_REUSE_ROOT']).resolve()
expected = os.environ['OUTPUT_REUSE_SHA256']
if not re.fullmatch(r'[0-9a-f]{64}', expected):
    raise ValueError('An exact archive digest is required')
native = subprocess.check_output(['rustc', '--print', 'host-tuple'], text=True).strip()
if native != TARGET:
    raise ValueError('The measured package must match the native runner')
archives = [p for p in (prior / 'archive').iterdir() if p.name.endswith(('.tar.gz', '.zip'))]
if len(archives) != 1 or digest(archives[0]) != expected:
    raise ValueError('Retained archive differs')
build = json.loads((prior / 'build.json').read_text())
if build['source_commit'] != os.environ['MEASURE_SOURCE'] or build['target'] != TARGET:
    raise ValueError('Retained source or target differs')
root.mkdir(parents=True, exist_ok=False)
(root / 'archive').mkdir()
archive = root / 'archive' / archives[0].name
shutil.copyfile(archives[0], archive)
image, manifest = unpack(archive, root / 'extracted', build)
save(root / 'build.json', build)
save(root / 'manifest.json', manifest)
save(root / 'image.json', dict(image=str(image), source=build['source_commit'],
    bytes=image.stat().st_size, sha256=digest(image), stripping=build['stripping'],
    archive=dict(path=str(archive), bytes=archive.stat().st_size, sha256=expected)))
save(root / 'reuse.json', dict(archive_sha256=expected,
    scope='Same verified stripped native release package; corrected control flush'))
subprocess.run([sys.executable, '-B', Path(__file__).with_name('observe.py'), root],
               check=True, timeout=1200)
