"""Download and authenticate one real Windows release without source edits."""
import json
import os
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
        result = super().redirect_request(request, fp, code, msg, headers, newurl)
        if urllib.parse.urlsplit(request.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            result.remove_header('Authorization')
        return result


def download(specification, output):
    url = urllib.parse.urlsplit(specification['url'])
    require(url.scheme == 'https' and url.hostname and not url.username and not url.password
            and not url.query and not url.fragment, 'Release URL must be HTTPS without credentials or query secrets')
    expected = specification['sha256']
    require(re.fullmatch('[0-9a-f]{64}', expected), 'Exact release archive digest is required')
    headers = {}
    name = specification.get('authorization_environment')
    if name:
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', name) and os.environ.get(name),
                'Named release download credential is absent')
        headers['Authorization'] = 'Bearer ' + os.environ[name]
    path = output / 'release.zip'
    request = urllib.request.Request(specification['url'], headers=headers)
    until = time.monotonic() + 180
    with urllib.request.build_opener(Redirect()).open(request, timeout=30) as source, path.open('xb') as target:
        count = 0
        while True:
            require(time.monotonic() < until, 'Release download exceeded its absolute time bound')
            data = source.read(1024**2)
            if not data:
                break
            count += len(data)
            require(count <= 512 * 1024**2, 'Release download exceeds its finite bound')
            target.write(data)
    require(digest(path) == expected, 'Downloaded release archive identity differs')
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
    return package, dict(url=specification['url'], archive_sha256=expected,
                         source_commit=build['source_commit'], build_sha256=digest(package / 'build.json'))
