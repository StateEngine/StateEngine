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
import zipfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[2]
TARGET = os.environ['MEASURE_TARGET']
BINARY = 'se.exe' if TARGET.endswith('windows-msvc') else 'se'


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
    suffix = '.zip' if TARGET.endswith('windows-msvc') else '.tar.gz'
    if archive.name != stem + suffix:
        raise ValueError('Unexpected native-only archive name')
    if suffix == '.zip':
        unpack_zip(archive, destination, stem)
    else:
        unpack_tar(archive, destination, stem)
    bundle = destination / stem
    return verify_bundle(bundle, metadata)


def unpack_zip(archive, destination, stem):
    with zipfile.ZipFile(archive) as package:
        names = set()
        total = 0
        for member in package.infolist():
            path = Path(member.filename)
            total += member.file_size
            if (not re.fullmatch(r'[A-Za-z0-9_./+-]+', member.filename)
                    or path.is_absolute() or '..' in path.parts
                    or path.parts[0] != stem or path.as_posix() != member.filename.rstrip('/')
                    or member.filename.casefold() in names or (member.external_attr >> 16) & 0o170000 == 0o120000
                    or member.file_size > 4 * 1024**3 or total > 8 * 1024**3):
                raise ValueError('Archive member is unsafe, duplicate or oversized')
            names.add(member.filename.casefold())
        if not 1 <= len(names) <= 10000:
            raise ValueError('Archive member count is outside its bound')
        destination.mkdir()
        package.extractall(destination)


def unpack_tar(archive, destination, stem):
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


def verify_bundle(bundle, metadata):
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
    checksums = {}
    for line in (bundle / 'SHA256SUMS').read_text().splitlines():
        checksum, name = line.split('  ', 1)
        if name in checksums:
            raise ValueError('Duplicate checksum-list entry')
        checksums[name] = checksum
    if set(checksums) != actual - {'SHA256SUMS'}:
        raise ValueError('Checksum-list inventory differs')
    for name, checksum in checksums.items():
        if digest(bundle / name) != checksum:
            raise ValueError('Checksum-list member differs: ' + name)
    if json.loads((bundle / 'build.json').read_text()) != metadata:
        raise ValueError('Extracted build provenance differs')
    image = bundle / BINARY
    if not (digest(image) == metadata['files'][BINARY]
            == metadata['stripping']['stripped']['sha256']
            == manifest['files'][BINARY]['sha256']):
        raise ValueError('Extracted executable differs from stripped build')
    return image, manifest


def main():
    native = subprocess.check_output(['rustc', '--print', 'host-tuple'], text=True).strip()
    if native != TARGET:
        raise ValueError('The measured target must be native to this runner')
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
                 cpu=Path('/proc/cpuinfo').read_text() if sys.platform == 'linux' else platform.processor(),
                 load_before=os.getloadavg() if hasattr(os, 'getloadavg') else None,
                 scope='native-only assembled unsigned release archive; no remote companions',
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
    if os.environ.get('OUTPUT_BUILD_ONLY') != '1':
        subprocess.run([sys.executable, '-B', Path(__file__).with_name('observe.py'), output],
                       cwd=ROOT, check=True, timeout=5400)
    facts['load_after'] = os.getloadavg() if hasattr(os, 'getloadavg') else None
    save(output / 'environment.json', facts)


if __name__ == '__main__':
    main()
