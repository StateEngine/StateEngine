"""Validate a downloaded standalone archive before giving it to the guest."""
import hashlib
import json
from pathlib import PurePosixPath, PureWindowsPath
import re
import stat
import zipfile


def extract_artifact(path, expected_digest, destination):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', expected_digest or ''):
        raise ValueError('hosted artifact has no usable digest')
    with path.open('rb') as source:
        if hashlib.file_digest(source,'sha256').hexdigest() != expected_digest[7:]:
            raise ValueError('downloaded hosted artifact digest differs')
    with zipfile.ZipFile(path) as archive:
        candidates = [entry for entry in archive.infolist()
                      if re.fullmatch(r'[^/\\]+-x86_64-pc-windows-msvc-unsigned\.zip', entry.filename)]
        if len(candidates) != 1 or candidates[0].file_size > 512*1024**2:
            raise ValueError('hosted artifact has no unique bounded Windows archive')
        destination.mkdir(mode=0o700)
        target = destination/candidates[0].filename
        with archive.open(candidates[0]) as source, target.open('xb') as output:
            count = 0
            while block := source.read(1024**2):
                count += len(block)
                if count > 512*1024**2:
                    raise ValueError('Windows archive exceeds its finite bound')
                output.write(block)
        return target


def validate(path, commit):
    with zipfile.ZipFile(path) as archive:
        files = {}
        total = 0
        folded = set()
        for entry in archive.infolist():
            name = entry.filename
            posix, windows = PurePosixPath(name), PureWindowsPath(name)
            key = name.casefold()
            reserved = {'CON','PRN','AUX','NUL',*[f'COM{i}' for i in range(1,10)],*[f'LPT{i}' for i in range(1,10)]}
            if (not name or '\\' in name or posix.is_absolute() or windows.anchor
                or '..' in posix.parts or any(':' in part or part != part.rstrip(' .') for part in posix.parts)
                or any(part.split('.')[0].upper() in reserved for part in posix.parts)
                or key in folded or stat.S_ISLNK(entry.external_attr >> 16) or entry.external_attr & 0x400):
                raise ValueError('release archive contains an unsafe or duplicate path')
            folded.add(key)
            total += entry.file_size
            if total > 1024**3:
                raise ValueError('release archive exceeds its extraction bound')
            if not entry.is_dir():
                files[name] = entry
        roots = {PurePosixPath(name).parts[0] for name in files}
        if len(roots) != 1:
            raise ValueError('release archive does not contain one package')
        root = next(iter(roots)) + '/'
        required = {root + name for name in ('build.json','install.ps1','se.exe','SHA256SUMS')}
        if not required.issubset(files):
            raise ValueError('release archive lacks required package files')
        build = json.loads(archive.read(files[root+'build.json']))
        if build.get('source_commit') != commit or build.get('target') != 'x86_64-pc-windows-msvc':
            raise ValueError('release archive source or target differs')
        checks = {}
        for line in archive.read(files[root+'SHA256SUMS']).decode('utf-8').splitlines():
            match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_./+-]+)', line)
            if not match or match[2] in checks or '..' in match[2].split('/') or match[2].startswith('/'):
                raise ValueError('release checksum inventory is invalid')
            checks[match[2]] = match[1]
        if set(files) != {root+name for name in checks} | {root+'SHA256SUMS'}:
            raise ValueError('release archive has missing or unlisted files')
        for relative, expected in checks.items():
            with archive.open(files[root+relative]) as source:
                if hashlib.file_digest(source,'sha256').hexdigest() != expected:
                    raise ValueError('release member checksum differs: '+relative)
