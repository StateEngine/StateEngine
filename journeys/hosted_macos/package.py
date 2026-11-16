"""One exact-nightly native package, verified again after artifact transfer."""
import argparse
import json
from pathlib import Path, PurePosixPath
import platform
import subprocess
import sys
import tarfile
from common import binding, digest, require, save

TARGET = 'aarch64-apple-darwin'


def verify(root, expected_digest, extract):
    root = Path(root)
    metadata_path = root / 'package.json'
    require(not metadata_path.is_symlink() and digest(metadata_path) == expected_digest, 'Package metadata digest changed after transfer')
    metadata = json.loads(metadata_path.read_text())
    require(metadata.get('schema') == 'se.hosted-nightly-package/v1', 'Unexpected package metadata schema')
    binding(metadata['nightly'])
    require(metadata['target'] == TARGET, 'Unexpected native target')
    require(Path(metadata['archive']).name == metadata['archive'], 'Archive path is not a basename')
    archive = root / metadata['archive']
    require(not archive.is_symlink() and digest(archive) == metadata['archive_sha256'], 'Native archive digest differs')
    extract = Path(extract)
    extract.mkdir(mode=0o700)
    with tarfile.open(archive, 'r:gz') as stream:
        members = stream.getmembers()
        require(0 < len(members) <= 10000, 'Archive member count is out of bounds')
        names, total, roots = set(), 0, set()
        for member in members:
            p = PurePosixPath(member.name)
            require(not p.is_absolute() and '..' not in p.parts and p.as_posix() == member.name.rstrip('/'), 'Archive path is not normal')
            require(member.isdir() or member.isfile(), 'Archive links and special entries are refused')
            require(member.name not in names, 'Duplicate archive path')
            names.add(member.name); roots.add(p.parts[0]); total += member.size
            require(total <= 1024**3, 'Archive expansion exceeds one GiB')
        require(len(roots) == 1, 'Archive has multiple roots')
        for member in members:
            p = extract / member.name
            if member.isdir():
                p.mkdir(parents=True, exist_ok=True)
            else:
                p.parent.mkdir(parents=True, exist_ok=True)
                with p.open('xb') as destination, stream.extractfile(member) as source:
                    while data := source.read(1024 * 1024):
                        destination.write(data)
                p.chmod(member.mode & 0o777)
    bundle = extract / next(iter(roots))
    sums = {}
    for line in (bundle / 'SHA256SUMS').read_text().splitlines():
        checksum, name = line.split('  ', 1)
        require(name not in sums and len(checksum) == 64, 'Duplicate or malformed checksum inventory')
        sums[name] = checksum
    actual = {p.relative_to(bundle).as_posix() for p in bundle.rglob('*') if p.is_file()}
    require(actual == set(sums) | {'SHA256SUMS'}, 'Archive file inventory differs from checksums')
    for name, checksum in sums.items():
        require(digest(bundle / name) == checksum, 'Archive member digest differs: ' + name)
    build = json.loads((bundle / 'build.json').read_text())
    manifest = json.loads((bundle / 'manifest.json').read_text())
    require(build['schema'] == 'se.release-build/v1' and build['source_commit'] == metadata['nightly']['product_commit']
            and build['target'] == TARGET and build['variant'] == 'standalone' and build['trust'] == 'unsigned', 'Native package is not this exact nightly product')
    require(manifest['schema'] == 'se.release/v1' and manifest['target'] == TARGET
            and manifest['variant'] == 'standalone' and manifest['trust'] == 'unsigned'
            and manifest['source_commit'] == build['source_commit'], 'Native manifest identity differs')
    require(digest(bundle / 'se') == metadata['binary_sha256'] and digest(bundle / 'build.json') == metadata['build_sha256'], 'Native package build or binary differs')
    return bundle, metadata


def build(source, nightly, out):
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'Build requires native arm64 macOS')
    source, out = Path(source).resolve(), Path(out).resolve()
    require(subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() == nightly['product_commit'], 'Checkout differs from Linux nightly')
    require(not subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain'], text=True).strip(), 'Product checkout is dirty')
    out.mkdir()
    subprocess.run([sys.executable, '-B', str(source / 'scripts/release/build.py'), '--target', TARGET, '--out', str(out / 'build')], check=True, timeout=6000)
    subprocess.run([sys.executable, '-B', str(source / 'scripts/release/assemble.py'), '--build', str(out / 'build'), '--native-only', '--out', str(out / 'archives')], check=True, timeout=600)
    archives = list((out / 'archives').glob('*.tar.gz'))
    require(len(archives) == 1, 'Expected one native archive')
    archive = archives[0]
    destination = out / 'transfer'
    destination.mkdir()
    archive.replace(destination / archive.name)
    record = dict(schema='se.hosted-nightly-package/v1', nightly=nightly, target=TARGET, archive=archive.name,
                  archive_sha256=digest(destination / archive.name), build_sha256=digest(out / 'build/build.json'), binary_sha256=digest(out / 'build/se'),
                  scope='Native-only same-source sibling of the Linux archive; remote-image packaging is not qualified')
    save(destination / 'package.json', record)
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--binding', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    output = build(args.source, binding(json.loads(args.binding.read_text())), args.out)
    print(json.dumps(dict(directory=str(output), metadata_sha256=digest(output / 'package.json'))))
