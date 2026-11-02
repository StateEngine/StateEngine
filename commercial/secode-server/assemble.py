#!/usr/bin/env python3
"""Build and assemble the private linked server from two clean source trees."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import struct
import subprocess
import sys

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
MAX_FILE = 512 * 1024 * 1024
MAX_JSON = 4 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024


def fingerprint(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
        raise ValueError(f"expected a bounded regular input: {path}")
    with path.open('rb') as stream:
        sha = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'sha256': sha, 'bytes': info.st_size}


def document(path):
    if fingerprint(path)['bytes'] > MAX_JSON:
        raise ValueError(f"manifest exceeds 4 MiB: {path}")
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict):
        raise ValueError(f"manifest must be an object: {path}")
    return value


def relative(name):
    path = PurePosixPath(name)
    if (not name or '\\' in name or ':' in name or path.is_absolute()
            or any(part in ('', '.', '..') for part in name.split('/'))):
        raise ValueError(f"unsafe package coordinate: {name!r}")
    return Path(*path.parts)


def git(root, *arguments):
    return subprocess.check_output(['git', *arguments], cwd=root, text=True).strip()


def clean(root):
    if git(root, 'status', '--porcelain', '--untracked-files=all'):
        raise ValueError(f"commit the private release source first: {root}")
    return git(root, 'rev-parse', 'HEAD')


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load the existing package implementation: {path}")
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def tree(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"expected a real package directory: {root}")
    files = {}
    total = 0
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError(f"package contains a link or special object: {path}")
        if path.is_file():
            name = path.relative_to(root).as_posix()
            relative(name)
            files[name] = fingerprint(path)
            total += files[name]['bytes']
            if total > MAX_TOTAL:
                raise ValueError('package exceeds its total byte bound')
            if len(files) > 10000:
                raise ValueError('package exceeds its file inventory bound')
    return files


def copy_file(source, destination, expected):
    if fingerprint(source) != expected:
        raise ValueError(f"input changed before copy: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open('rb') as reader, destination.open('xb') as writer:
        shutil.copyfileobj(reader, writer)
    destination.chmod(stat.S_IMODE(source.stat().st_mode))
    if fingerprint(destination) != expected or fingerprint(source) != expected:
        raise ValueError(f"copy readback disagrees: {source}")


def write_json(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    if len(raw) > MAX_JSON:
        raise ValueError(f"output manifest exceeds 4 MiB: {path}")
    path.write_bytes(raw)
    return fingerprint(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--secode-root', type=Path, required=True)
    parser.add_argument('--public-package', type=Path, required=True)
    parser.add_argument('--native-build', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    secode = args.secode_root.resolve()
    public = args.public_package.resolve()
    native = args.native_build.resolve()
    out = args.out.resolve()
    for source in (ROOT, secode, public, native):
        if out == source or source in out.parents:
            raise ValueError('private output must be new and outside every input tree')
    if out.exists():
        raise ValueError(f"output already exists: {out}")
    sources = {'stateengine': clean(ROOT), 'secode': clean(secode)}
    if (ROOT.parent / 'rust-secode').resolve() != secode.resolve():
        raise ValueError('the private assembly requires sibling rust-se and rust-secode source trees')
    manifest = document(public / 'release-manifest.json')
    build = document(native / 'build.json')
    target = manifest['target']
    if target not in ('x86_64-unknown-linux-gnu', 'x86_64-pc-windows-msvc'):
        raise ValueError('the linked package currently supports native Linux and Windows')
    windows = target.endswith('windows-msvc')
    helper = 'se.exe' if windows else 'se'
    server = 'secode-server.exe' if windows else 'secode-server'
    if (build.get('schema') != 'se.release-build/v1' or build.get('variant') != 'standalone'
            or build.get('trust') != 'unsigned' or build.get('target') != target
            or build.get('source_commit') != sources['stateengine']
            or build.get('panic') != 'unwind' or build.get('fresh_target') is not True):
        raise ValueError('native helper must be an unsigned standalone build of this exact private source')
    if manifest.get('engine_version') != sources['secode'] or manifest.get('publisher') is not None:
        raise ValueError('public package must be unsigned and match this exact SE Code source')
    stateengine = manifest.get('stateengine')
    if not isinstance(stateengine, dict) or stateengine.get('status') != 'not-included':
        raise ValueError('start with a public package that contains no StateEngine payload')
    sys.path.insert(0, str(secode / 'scripts/release'))
    packaging = module(secode / 'scripts/release/package.py', 'private_public_packaging')
    packaging.complete(list(manifest['binaries']), public, '.exe' if windows else '')
    receipt_names = {row['build_receipt'] for row in manifest['binaries'].values()}
    if len(receipt_names) != 1:
        raise ValueError('public package must carry one common build receipt')
    receipt_name = next(iter(receipt_names))
    relative(receipt_name)
    receipt_path = public / receipt_name
    receipt = packaging.load_receipt(receipt_path)
    profile = manifest['profile']
    packaging.custody(receipt, receipt_path, secode, profile, target)
    packaging.accounted_for(receipt, receipt_path, list(manifest['binaries']))
    public_files = tree(public)
    for name, row in manifest['binaries'].items():
        actual = public_files[name]
        if (actual != {'sha256': row['sha256'], 'bytes': row['bytes']}
                or actual != {key: receipt['outputs'][name].get(key) for key in ('sha256', 'bytes')}
                or public_files[receipt_name]['sha256'] != row['build_receipt_sha256']):
            raise ValueError(f"public package provenance disagrees: {name}")
    plugin = manifest.get('plugin_runtime', {})
    for name, expected in plugin.get('assets', {}).items():
        relative(name)
        if public_files.get(name) != expected:
            raise ValueError(f"public plugin resource differs from its manifest: {name}")
    native_files = tree(native)
    if set(native_files) != set(build['files']) | {'build.json'}:
        raise ValueError('native helper output differs from its build inventory')
    for name, sha in build['files'].items():
        relative(name)
        if native_files[name]['sha256'] != sha or (name != helper and not name.startswith('notices/')):
            raise ValueError(f"native build file differs: {name}")
    if sum(row['bytes'] for row in native_files.values()) > 512 * 1024 * 1024:
        raise ValueError('native payload exceeds 512 MiB')
    if helper not in build['files']:
        raise ValueError('native build has no helper executable')
    native_packaging = module(ROOT / 'scripts/release/assemble.py', 'private_native_packaging')
    native_packaging.native_binary(native / helper, windows, target)
    lock = ROOT / 'commercial/secode-server/Cargo.lock'
    argv = ['cargo', 'build', '--offline', '--locked', '--manifest-path',
            str(ROOT / 'commercial/secode-server/Cargo.toml'), '--target', target,
            '--bin', 'secode-server', '--message-format=json-render-diagnostics']
    if profile == 'release':
        argv.append('--release')
    elif profile != 'debug':
        raise ValueError('public build profile must be debug or release')
    built = subprocess.run(argv, cwd=secode, check=True, text=True, stdout=subprocess.PIPE)
    artifacts = [json.loads(line) for line in built.stdout.splitlines() if line.strip()]
    binaries = [row['executable'] for row in artifacts if row.get('reason') == 'compiler-artifact'
                and row.get('executable') and row['target']['name'] == 'secode-server']
    if len(binaries) != 1:
        raise ValueError('Cargo did not report one private server executable')
    private_binary = Path(binaries[0])
    native_packaging.native_binary(private_binary, windows, target)
    if {'stateengine': clean(ROOT), 'secode': clean(secode)} != sources:
        raise ValueError('source changed while building the linked server')
    out.mkdir(mode=0o700, parents=True)
    for name, expected in public_files.items():
        if name not in (server, receipt_name, 'release-manifest.json'):
            copy_file(public / name, out / relative(name), expected)
    private_hash = fingerprint(private_binary)
    copy_file(private_binary, out / server, private_hash)
    linked = copy.deepcopy(receipt)
    linked['public_base_receipt'] = receipt
    linked['linked_sources'] = {**sources, 'cargo_lock_sha256': fingerprint(lock)['sha256']}
    linked['commands'].append({'argv': argv, 'cwd': str(secode), 'exit_code': 0,
                               'produces': [server], 'replaces': receipt['outputs'][server]})
    linked['outputs'][server] = {**private_hash, 'package': 'stateengine-secode-server',
                                 'bin': 'secode-server', 'built_from': str(private_binary)}
    common = 'linked-build-receipt.json'
    receipt_hash = write_json(out / common, linked)
    for name, row in manifest['binaries'].items():
        if name == server:
            row.update(private_hash)
        row.update(build_receipt=common, build_receipt_sha256=receipt_hash['sha256'])
    for name, expected in native_files.items():
        copy_file(native / name, out / 'stateengine' / relative(name), expected)
    notice = ROOT / 'scripts/release/NOTICE.txt'
    notice_hash = fingerprint(notice)
    if build['release_assets'].get('NOTICE.txt') != notice_hash['sha256']:
        raise ValueError('native license notice changed since the helper build')
    copy_file(notice, out / 'stateengine/NOTICE.txt', notice_hash)
    payload_files = tree(out / 'stateengine')
    payload = {'schema': 'stateengine.native-payload/v1', 'name': 'stateengine',
               'runtime': 'rust-embedded', 'version': build['version'], 'target': target,
               'source_commit': sources['stateengine'], 'entry': helper,
               'license_path': 'NOTICE.txt', 'notices_path': 'NOTICE.txt', 'files': payload_files}
    payload_hash = write_json(out / 'stateengine/native-payload.json', payload)
    assets = {'stateengine/' + name: row for name, row in tree(out / 'stateengine').items()}
    manifest['stateengine'] = {'status': 'included', 'runtime': 'rust-embedded',
        'version': build['version'], 'source_commit': sources['stateengine'], 'target': target,
        'entry': 'stateengine/' + helper, 'manifest_sha256': payload_hash['sha256'],
        'license': 'separately licensed; see stateengine/NOTICE.txt',
        'composition': linked['linked_sources'], 'assets': assets}
    manifest['assembly_provenance'] = {'public_base': manifest.get('assembly_provenance'),
        'private_source_commit': sources['stateengine'], 'public_source_commit': sources['secode']}
    write_json(out / 'release-manifest.json', manifest)
    # Byte readback is assembly evidence only; the actual installer and the
    # provider journey still qualify the completed package separately.
    if {key: document(out / common)['outputs'][server][key] for key in ('sha256', 'bytes')} != fingerprint(out / server):
        raise ValueError('private server differs on final package readback')
    print(json.dumps({'package': str(out), 'linked_sources': linked['linked_sources'],
                      'trust': 'unsigned', 'installed_qualification': 'not-run'}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, struct.error, subprocess.CalledProcessError) as error:
        print(f'private assembly refused: {error}', file=sys.stderr)
        sys.exit(1)
