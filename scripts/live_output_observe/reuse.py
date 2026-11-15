"""Observe the identical archive retained by an earlier hosted package build."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from build import digest, unpack, save, ROOT


def main():
    prior, output = map(lambda p: Path(p).resolve(), sys.argv[1:])
    output.mkdir(exist_ok=False)
    source = os.environ['MEASURE_SOURCE']
    metadata = json.loads((prior / 'build.json').read_text())
    identity = json.loads((prior / 'image.json').read_text())
    if metadata['source_commit'] != source or identity['source'] != source:
        raise ValueError('Retained package source differs')
    archives = list((prior / 'archive').glob('*.tar.gz'))
    if len(archives) != 1 or digest(archives[0]) != identity['archive']['sha256']:
        raise ValueError('Retained package archive differs')
    (output / 'archive').mkdir()
    archive = output / 'archive' / archives[0].name
    shutil.copyfile(archives[0], archive)
    image, manifest = unpack(archive, output / 'extracted', metadata)
    if digest(image) != identity['sha256']:
        raise ValueError('Retained native image differs')
    subprocess.run(['git', 'worktree', 'add', '--detach', str(output / 'source'), source],
                   cwd=ROOT, check=True)
    identity['image'] = str(image)
    identity['archive']['path'] = str(archive)
    save(output / 'build.json', metadata)
    save(output / 'manifest.json', manifest)
    save(output / 'image.json', identity)
    save(output / 'reuse.json', {'prior_run': os.environ['PRIOR_RUN'],
                               'archive_sha256': digest(archive), 'executable_sha256': digest(image),
                               'scope': 'Same native package; controlled assistant-to-result pause, separate hosted runner'})
    help_result = subprocess.run([str(image), 'watch', '--help'], check=True,
                                 capture_output=True, timeout=15)
    (output / 'watch-help.stdout').write_bytes(help_result.stdout)
    subprocess.run([sys.executable, '-B', Path(__file__).with_name('observe.py'), output],
                   cwd=ROOT, check=True, timeout=1200)


if __name__ == '__main__':
    main()
