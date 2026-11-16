"""Copy or download and authenticate one real Windows release without source edits."""
import json
from pathlib import Path, PureWindowsPath
import re
import stat
import time
import urllib.parse
import urllib.request
import zipfile

from harness_matrix.io import digest, require


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        require(urllib.parse.urlsplit(newurl).scheme == 'https', 'Release redirect is not HTTPS')
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def local_archive(value):
    path = Path(value)
    require(path.is_absolute() and path.suffix.lower() == '.zip',
            'Bundled release must be an absolute ZIP path')
    for part in [path, *path.parents]:
        row = part.lstat()
        require(not stat.S_ISLNK(row.st_mode)
                and not getattr(row, 'st_file_attributes', 0) & 0x400,
                'Bundled release path contains a link or reparse point')
    row = path.stat()
    require(stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and row.st_size <= 512 * 1024**2,
            'Bundled release must be a bounded plain file')
    return path, (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns)


def download(specification, output):
    require(('path' in specification) != ('url' in specification)
            and 'authorization_environment' not in specification,
            'Select one bundled ZIP or public HTTPS release, without a download credential')
    expected = specification['sha256']
    require(re.fullmatch('[0-9a-f]{64}', expected), 'Exact release archive digest is required')
    local, identity = local_archive(specification['path']) if 'path' in specification else (None, None)
    if local is None:
        url = urllib.parse.urlsplit(specification['url'])
        require(url.scheme == 'https' and url.hostname and not url.username and not url.password
                and not url.query and not url.fragment,
                'Release URL must be public HTTPS without credentials or query secrets')
        source = urllib.request.build_opener(Redirect()).open(specification['url'], timeout=30)
    else:
        source = local.open('rb')
    path = output / 'release.zip'
    until = time.monotonic() + 180
    with source, path.open('xb') as target:
        count = 0
        while True:
            require(time.monotonic() < until, 'Release transfer exceeded its absolute time bound')
            data = source.read(1024**2)
            if not data:
                break
            count += len(data)
            require(count <= 512 * 1024**2, 'Release transfer exceeds its finite bound')
            target.write(data)
    if local is not None:
        require(local_archive(str(local))[1] == identity, 'Bundled release changed during copy')
    require(digest(path) == expected, 'Release archive identity differs')
    extracted = output / 'release'
    extracted.mkdir()
    inventory = set()
    with zipfile.ZipFile(path) as archive:
        total = 0
        for entry in archive.infolist():
            name = PureWindowsPath(entry.filename)
            key = str(name).casefold()
            require(not name.anchor and '..' not in name.parts and key not in inventory
                    and all(':' not in part and part == part.rstrip(' .') for part in name.parts),
                    'Release archive contains an unsafe or duplicate path')
            require(not stat.S_ISLNK(entry.external_attr >> 16), 'Release archive contains a link')
            inventory.add(key)
            total += entry.file_size
            require(total <= 1024**3, 'Release extraction exceeds its finite bound')
        archive.extractall(extracted)
    packages = [p.parent for p in extracted.rglob('build.json') if (p.parent / 'install.ps1').is_file()]
    require(len(packages) == 1, 'Expected exactly one distributable Windows package')
    package = packages[0]
    build = json.loads((package / 'build.json').read_text())
    require(build['source_commit'] == specification['source_commit']
            and build['target'] == 'x86_64-pc-windows-msvc', 'Downloaded release source or target differs')
    checksums = {}
    for line in (package / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_./+-]+)', line)
        require(match is not None, 'Release checksum inventory is unreadable')
        value, relative = match.groups()
        require(not relative.startswith('/') and '..' not in relative.split('/')
                and relative not in checksums, 'Release checksum path is unsafe or duplicated')
        require(digest(package / relative) == value, 'Release member checksum differs')
        checksums[relative] = value
    actual = {str(p.relative_to(package)).replace('\\', '/') for p in package.rglob('*') if p.is_file()}
    require(actual == set(checksums) | {'SHA256SUMS'}, 'Release has missing or unlisted members')
    return package, dict(origin='bundled' if local is not None else 'public-https',
                         path=str(local) if local is not None else None,
                         url=specification.get('url'), archive_sha256=expected,
                         source_commit=build['source_commit'], build_sha256=digest(package / 'build.json'))
