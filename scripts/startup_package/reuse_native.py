"""Observe a previously verified native package without rebuilding the product."""
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

from build import TARGET, digest, save, unpack

EXPECTED = {
    'aarch64-apple-darwin': 'eb6370d7e910175fe7bd166cfab781bf194ece14951cb05975279b995789d9f8',
    'x86_64-pc-windows-msvc': '47f06315b76a6125e3b4ea5b88aeb7425c1414f247eea2d8993d4c8adebda210',
}
root = Path(sys.argv[1]).resolve()
prior = Path(os.environ['STARTUP_REUSE_ROOT']).resolve()
root.mkdir(parents=True, exist_ok=False)
archives = [p for p in (prior/'archive').iterdir() if p.name.endswith(('.tar.gz','.zip'))]
if len(archives) != 1 or digest(archives[0]) != EXPECTED[TARGET]:
    raise ValueError('Retained native archive differs')
build = json.loads((prior/'build.json').read_text())
if build['source_commit'] != 'b7a3c1c5d9d4f016b237a97c5c0d883645276eda' or build['target'] != TARGET:
    raise ValueError('Retained source or native target differs')
(root/'archive').mkdir()
archive = root/'archive'/archives[0].name
shutil.copyfile(archives[0], archive)
image, manifest = unpack(archive, root/'extracted', build)
save(root/'build.json', build)
save(root/'manifest.json', manifest)
save(root/'image.json', dict(image=str(image), sha256=digest(image), bytes=image.stat().st_size,
    source=build['source_commit'], archive=dict(path=str(archive), bytes=archive.stat().st_size,
    sha256=EXPECTED[TARGET]), stripping=build['stripping']))
save(root/'reuse.json', dict(prior_run=43672343400, archive_sha256=EXPECTED[TARGET],
    scope='same stripped release package; corrected observer on a new hosted native runner'))
save(root/'environment.json', dict(platform=platform.platform(), cpu=platform.processor(),
    scope='startup only; no provider or transport helpers; native-only archive',
    installation='byte-identical private copy; not installer qualification'))
subprocess.run([sys.executable,'-B',Path(__file__).with_name('observe.py'), root],
               check=True, timeout=5400)
