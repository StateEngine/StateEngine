"""Build frozen CLI pairs on one disposable Linux runner, then observe them.

This is an author measurement, separate from independent correctness review.
Run from a full-history checkout with: python3 -B scripts/cli_latency/build.py OUTPUT
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
SOURCES = {
    'base': 'dadd5cafb413ba3187de65bf59f5e0cfa96bf5ad',
    'head': '0cf88be7472a372a8395b619de5420f8f1f7e449',
}


def save(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')


def main():
    if sys.platform != 'linux':
        raise RuntimeError('This measurement requires a disposable Linux runner')
    parent = subprocess.check_output(['git', 'rev-parse', SOURCES['head'] + '^'],
                                     cwd=ROOT, text=True).strip()
    if parent != SOURCES['base']:
        raise RuntimeError('The comparison base is not the frozen head parent')
    output = Path(sys.argv[1]).resolve()
    output.mkdir(parents=True, exist_ok=False)
    images = output / 'images'
    images.mkdir()
    sources = output / 'sources'
    sources.mkdir()
    manifest = {}
    for name, revision in SOURCES.items():
        tree = sources / name
        target = output / ('target-' + name)
        subprocess.run(['git', 'cat-file', '-e', revision + '^{commit}'], cwd=ROOT, check=True)
        subprocess.run(['git', 'worktree', 'add', '--detach', str(tree), revision],
                       cwd=ROOT, check=True)
        observed = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=tree, text=True).strip()
        if observed != revision:
            raise RuntimeError('The selected source revision changed')
        environment = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_INCREMENTAL='0',
                           CARGO_PROFILE_DEV_DEBUG='0', CARGO_TERM_COLOR='never')
        command = ['cargo', 'build', '-p', 'se', '--bin', 'se', '--locked',
                   '--no-default-features', '--features', 'remote', '--jobs', '2']
        started = time.monotonic()
        with (output / (name + '-build.log')).open('xb') as log:
            built = subprocess.run(command, cwd=tree, env=environment,
                                   stdout=log, stderr=subprocess.STDOUT, timeout=1800)
        record = dict(source=revision, command=command, exit=built.returncode,
                      seconds=time.monotonic() - started, profile='dev; debug=0; incremental=0')
        manifest[name] = record
        save(output / 'images.json', manifest)
        if built.returncode != 0:
            raise RuntimeError(name + ': build failed; original log retained')
        image = images / name
        shutil.copyfile(target / 'debug/se', image)
        image.chmod(0o500)
        record.update(image=str(image), sha256=hashlib.sha256(image.read_bytes()).hexdigest())
        save(output / 'images.json', manifest)
        # The exact child has joined and the image has been copied. Each build had
        # a distinct target directory, so timestamps cannot reuse another tree.
        shutil.rmtree(target)
        print(json.dumps(dict(name=name, **record)), flush=True)
    subprocess.run([sys.executable, '-B', str(Path(__file__).with_name('observe.py')),
                    str(output)], cwd=ROOT, check=True, timeout=1800)


if __name__ == '__main__':
    main()
