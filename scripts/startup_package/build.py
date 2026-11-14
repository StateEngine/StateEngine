"""Measure the native image produced by the committed release packaging recipe."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[2]
TARGET = 'x86_64-unknown-linux-gnu'


def save(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(argv, cwd, log, timeout=5400):
    started = time.monotonic()
    with log.open('xb') as output:
        subprocess.run(list(map(str, argv)), cwd=cwd, check=True, stdout=output,
                       stderr=subprocess.STDOUT, timeout=timeout)
    return time.monotonic() - started


def unpack(archive, destination, metadata):
    # The package-manager extractor accepts full archives only. This measurement
    # selects assemble.py's explicit native-only flavor, without renaming it or
    # changing the contents to pretend that it includes remote companions.
    stem = f"stateengine-{metadata['version']}-{TARGET}-native-only-unsigned"
    if archive.name != stem + '.tar.gz':
        raise ValueError('Unexpected native-only archive name')
    with tarfile.open(archive, 'r:gz') as package:
        members = package.getmembers()
        names = set()
        total = 0
        if not 1 <= len(members) <= 10000:
            raise ValueError('Archive member count is outside its bound')
        for member in members:
            path = Path(member.name)
            total += member.size
            if (not re.fullmatch(r'[A-Za-z0-9_./+-]+', member.name)
                    or path.is_absolute() or '..' in path.parts
                    or path.parts[0] != stem or path.as_posix() != member.name.rstrip('/')
                    or member.name.casefold() in names
                    or not (member.isdir() or member.isreg())
                    or member.size > 4 * 1024**3 or total > 8 * 1024**3):
                raise ValueError('Archive member is unsafe, duplicate or oversized')
            names.add(member.name.casefold())
        destination.mkdir()
        package.extractall(destination, members=members, filter='data')
    bundle = destination / stem
    manifest = json.loads((bundle / 'manifest.json').read_text())
    for key, value in dict(schema='se.release/v1', variant='standalone', trust='unsigned',
                           target=TARGET, source_commit=metadata['source_commit'],
                           version=metadata['version']).items():
        if manifest[key] != value:
            raise ValueError('Archive provenance differs: ' + key)
    actual = {p.relative_to(bundle).as_posix() for p in bundle.rglob('*') if p.is_file()}
    if actual != set(manifest['files']) | {'manifest.json', 'SHA256SUMS'}:
        raise ValueError('Archive inventory differs')
    for name, record in manifest['files'].items():
        path = bundle / name
        if path.stat().st_size != record['bytes'] or digest(path) != record['sha256']:
            raise ValueError('Archive member differs: ' + name)
    if json.loads((bundle / 'build.json').read_text()) != metadata:
        raise ValueError('Extracted build provenance differs')
    image = bundle / 'se'
    if not (digest(image) == metadata['files']['se']
            == metadata['stripping']['stripped']['sha256']
            == manifest['files']['se']['sha256']):
        raise ValueError('Extracted executable differs from stripped build')
    return image, manifest


def main():
    if sys.platform != 'linux' or platform.machine() != 'x86_64':
        raise ValueError('This observation requires native x86_64 Linux')
    output = Path(sys.argv[1]).resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = os.environ['MEASURE_SOURCE']
    if not re.fullmatch(r'[0-9a-f]{40}', source):
        raise ValueError('An exact product revision is required')
    tree = output / 'source'
    subprocess.run(['git', 'worktree', 'add', '--detach', str(tree), source], cwd=ROOT, check=True)
    profile = tomllib.loads((tree / 'Cargo.toml').read_text())['profile']['distribution']
    if profile['lto'] != 'fat':
        raise ValueError('The measured product must include full LTO')
    facts = dict(source=source, profile=profile, os=platform.platform(),
                 cpu=Path('/proc/cpuinfo').read_text(), load_before=os.getloadavg(),
                 scope='native-only assembled unsigned Linux archive; no remote companions',
                 installation='byte-identical private copy of verified extracted executable; not installer qualification')
    save(output / 'environment.json', facts)
    facts['build_seconds'] = run([sys.executable, '-B', tree / 'scripts/release/build.py',
        '--target', TARGET, '--out', output / 'native-build', '--target-dir', output / 'target'],
        tree, output / 'build.log')
    run([sys.executable, '-B', tree / 'scripts/release/assemble.py', '--build', output / 'native-build',
         '--native-only', '--out', output / 'archive'], tree, output / 'assemble.stdout')
    assembled = json.loads((output / 'assemble.stdout').read_text())
    archive = Path(assembled['archive'])
    if assembled['source_commit'] != source or digest(archive) != assembled['sha256']:
        raise ValueError('Assembled archive identity differs')
    build = json.loads((output / 'native-build/build.json').read_text())
    if build['source_commit'] != source or build['profile'] != 'distribution':
        raise ValueError('Build source or profile differs')
    image, manifest = unpack(archive, output / 'extracted', build)
    save(output / 'build.json', build)
    save(output / 'manifest.json', manifest)
    save(output / 'image.json', dict(image=str(image), sha256=digest(image), bytes=image.stat().st_size,
        source=source, archive=dict(path=str(archive), bytes=archive.stat().st_size,
                                   sha256=assembled['sha256']), stripping=build['stripping']))
    subprocess.run([sys.executable, '-B', Path(__file__).with_name('observe.py'), output],
                   cwd=ROOT, check=True, timeout=1200)
    facts['load_after'] = os.getloadavg()
    save(output / 'environment.json', facts)


if __name__ == '__main__':
    main()
