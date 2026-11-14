"""Build frozen CLI pairs on one disposable hosted runner, then observe them.

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
    'status-base': '8fbd7a24dee2582c2fbc1a1de2c641915b739ffd',
    'status-head': '89468c389488cd2f4a47c577cb14e8d16f68ad1b',
}
PLATFORMS = ('linux', 'win32', 'darwin')


def save(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')


def main():
    if sys.platform not in PLATFORMS:
        raise RuntimeError('This measurement requires a disposable hosted runner (linux, win32 or darwin)')
    output = Path(sys.argv[1]).resolve()
    output.mkdir(parents=True, exist_ok=False)
    images = output / 'images'
    images.mkdir()
    sources = output / 'sources'
    sources.mkdir()
    binary = 'se.exe' if sys.platform == 'win32' else 'se'
    manifest = {}
    for name, revision in SOURCES.items():
        if subprocess.run(['git', 'cat-file', '-e', revision + '^{commit}'],
                          cwd=ROOT).returncode != 0:
            # The pinned pair may sit on a branch this checkout did not fetch.
            subprocess.run(['git', 'fetch', 'origin', revision], cwd=ROOT, check=True)
        subprocess.run(['git', 'cat-file', '-e', revision + '^{commit}'], cwd=ROOT, check=True)
        subprocess.run(['git', 'worktree', 'add', '--detach', str(sources / name), revision],
                       cwd=ROOT, check=True)
        tree = sources / name
        target = output / ('target-' + name)
        observed = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=tree, text=True).strip()
        if observed != revision:
            raise RuntimeError('The selected source revision changed')
        environment = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_INCREMENTAL='0',
                           CARGO_PROFILE_DEV_DEBUG='0', CARGO_TERM_COLOR='never')
        command = ['cargo', 'build', '-p', 'se', '--bin', 'se', '--locked',
                   '--no-default-features', '--features', 'remote', '--jobs', '2']
        if sys.platform == 'darwin':
            # The macos-15 toolchain loses the proc-macro crate (E0463,
            # zerofrom_derive) unless the host target tuple is stated.
            host = subprocess.check_output(['rustc', '--print', 'host-tuple'],
                                           cwd=ROOT, text=True).strip()
            command += ['--target', host]
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
        if sys.platform == 'darwin':
            shutil.copyfile(target / host / 'debug' / binary, image)
        else:
            shutil.copyfile(target / 'debug' / binary, image)
        image.chmod(0o500)
        record.update(image=str(image), sha256=hashlib.sha256(image.read_bytes()).hexdigest())
        save(output / 'images.json', manifest)
        # The exact child has joined and the image has been copied. Each build had
        # a distinct target directory, so timestamps cannot reuse another tree.
        shutil.rmtree(target)
        print(json.dumps(dict(name=name, **record)), flush=True)
    if len({record['sha256'] for record in manifest.values()}) != len(manifest):
        raise RuntimeError('Distinct frozen sources produced identical images; investigate before timing')
    subprocess.run([sys.executable, '-B', str(Path(__file__).with_name('observe.py')),
                    str(output)], cwd=ROOT, check=True, timeout=1800)


if __name__ == '__main__':
    main()
