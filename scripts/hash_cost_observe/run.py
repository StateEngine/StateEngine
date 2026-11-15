"""Observe SHA-256 costs on an authenticated shipping image, without launching it."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import urllib.error
import urllib.request
import zipfile

ROOT = Path(os.environ['RUNNER_TEMP']) / 'shipping-hash-cost'
ROOT.mkdir()
SOURCE = os.environ['HASH_SOURCE']
RUN = int(os.environ['HASH_RUN'])
ARTIFACT = os.environ['HASH_ARTIFACT']
TOKEN = os.environ['GH_TOKEN']
BASE = 'https://api.github.com/repos/' + os.environ['GITHUB_REPOSITORY'] + '/'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def api(path):
    request = urllib.request.Request(BASE + path, headers={
        'Authorization': 'Bearer ' + TOKEN, 'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def command(name, args, timeout):
    with (ROOT / (name + '.stdout')).open('wb') as stdout, (ROOT / (name + '.stderr')).open('wb') as stderr:
        result = subprocess.run(args, stdout=stdout, stderr=stderr, timeout=timeout)
    (ROOT / (name + '-receipt.json')).write_text(json.dumps({'exit': result.returncode}) + '\n', encoding='utf-8')
    result.check_returncode()


matches = [row for row in api(f'actions/runs/{RUN}/artifacts')['artifacts'] if row['name'] == ARTIFACT]
assert len(matches) == 1 and not matches[0]['expired']
artifact = matches[0]
request = urllib.request.Request(artifact['archive_download_url'], headers={
    'Authorization': 'Bearer ' + TOKEN, 'Accept': 'application/vnd.github+json'})
try:
    with urllib.request.build_opener(NoRedirect).open(request, timeout=60) as response:
        raw = response.read()
except urllib.error.HTTPError as error:
    if error.code != 302:
        raise
    # The signed storage URL receives no repository token.
    with urllib.request.urlopen(error.headers['Location'], timeout=120) as response:
        raw = response.read()
assert 'sha256:' + hashlib.sha256(raw).hexdigest() == artifact['digest']
with zipfile.ZipFile(io.BytesIO(raw)) as outer:
    image = json.loads(outer.read('startup-paired-evidence/head/image.json'))
    assert image['source'] == SOURCE
    archive_name = Path(image['archive']['path'].replace('\\', '/')).name
    archive = outer.read('startup-paired-evidence/head/archive/' + archive_name)
assert len(archive) == image['archive']['bytes']
assert hashlib.sha256(archive).hexdigest() == image['archive']['sha256']
with zipfile.ZipFile(io.BytesIO(archive)) as shipping:
    names = shipping.namelist()
    manifests = [name for name in names if name.endswith('/manifest.json')]
    assert len(manifests) == 1
    prefix = manifests[0].removesuffix('manifest.json')
    files = {name[len(prefix):]: shipping.read(name) for name in names if not name.endswith('/') and name.startswith(prefix)}
manifest = json.loads(files['manifest.json'])
build = json.loads(files['build.json'])
assert manifest['source_commit'] == build['source_commit'] == SOURCE
assert set(files) == set(manifest['files']) | {'manifest.json', 'SHA256SUMS'}
for name, item in manifest['files'].items():
    assert len(files[name]) == item['bytes'] and hashlib.sha256(files[name]).hexdigest() == item['sha256']
for line in files['SHA256SUMS'].decode().splitlines():
    digest, name = line.split('  ', 1)
    assert hashlib.sha256(files[name]).hexdigest() == digest
assert hashlib.sha256(files['se.exe']).hexdigest() == image['sha256'] == build['stripping']['stripped']['sha256']
assert len(files['se.exe']) == image['bytes'] and 0 < image['bytes'] <= 512 * 1024 * 1024
binary = ROOT / 'shipping.exe'
binary.write_bytes(files['se.exe'])
receipt = {'artifact': artifact, 'image': image, 'manifest': manifest,
           'scope': 'Full-byte author performance observation only; shipping image is never launched'}
(ROOT / 'input.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
del raw, archive, files
target = 'x86_64-pc-windows-msvc'
command('build', ['cargo', 'build', '--locked', '-p', 'se-proc', '--example', 'hash_cost_observe',
                  '--profile', 'distribution', '--target', target, '--target-dir', str(ROOT / 'target')], 2400)
observer = ROOT / 'target' / target / 'distribution' / 'examples' / 'hash_cost_observe.exe'
receipt['observer_sha256'] = hashlib.sha256(observer.read_bytes()).hexdigest()
command('measure', [str(observer), str(binary), image['sha256']], 600)
result = json.loads((ROOT / 'measure.stdout').read_bytes())
assert result['image_bytes'] == image['bytes'] and result['image_sha256'] == image['sha256']
summary = {}
for mode in sorted({sample['mode'] for sample in result['samples']}):
    rows = [sample for sample in result['samples'] if sample['mode'] == mode]
    values = sorted(sample['ms'] for sample in rows if not sample['warmup'])
    assert len(rows) == 110 and len(values) == 100
    assert all(sample['bytes'] == image['bytes'] for sample in rows)
    summary[mode] = {'p50_ms': values[49], 'p95_ms': values[94], 'max_ms': values[-1], 'measured': 100}
assert hashlib.sha256(binary.read_bytes()).hexdigest() == image['sha256']
receipt.update(cpu=result['cpu'], summary=summary, completed=True)
(ROOT / 'readback.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'cpu': result['cpu'], 'summary': summary}), flush=True)
