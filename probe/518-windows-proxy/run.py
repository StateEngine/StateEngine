"""Fetch the public Codex npm package for this platform, verify it, and run xprobe.py.

No credentials are read or used: the probe serves a synthetic login and model on loopback.
Exit 0 means every check passed. Usage: python run.py [work-dir]
"""
import hashlib, io, os, subprocess, sys, tarfile, tempfile, urllib.request
from pathlib import Path

PACKAGES = {
    'win32': ('https://registry.npmjs.org/@openai/codex/-/codex-0.169.0-win32-x64.tgz',
              'c48d07b46034d2b0a6c091227993c50e19c389680169244d0dcbb96c4ebc429f',
              'package/vendor/x86_64-pc-windows-msvc/bin/codex.exe'),
    'linux': ('https://registry.npmjs.org/@openai/codex/-/codex-0.169.0-linux-x64.tgz',
              '89801b4b97faba562eb80fe0a833159ac79399be674022f4b1a0ccab1d153faa',
              'package/vendor/x86_64-unknown-linux-musl/bin/codex'),
}
platform = 'win32' if os.name == 'nt' else sys.platform
if platform not in PACKAGES:
    sys.exit(f'no pinned Codex package for {platform}')
url, digest, member = PACKAGES[platform]
work = Path(sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp(prefix='xprobe-')).resolve()
work.mkdir(parents=True, exist_ok=True)
data = urllib.request.urlopen(url, timeout=300).read()
actual = hashlib.sha256(data).hexdigest()
if actual != digest:
    sys.exit(f'package checksum differs: {actual}')
with tarfile.open(fileobj=io.BytesIO(data)) as archive:
    archive.extractall(work / 'codex', filter='data')
binary = work / 'codex' / member
print(f'codex {binary} sha256 verified package', flush=True)
codes = {}
for mode in ('default', 'explicit'):
    print(f'== case {mode}', flush=True)
    codes[mode] = subprocess.run([sys.executable, '-I', str(Path(__file__).with_name('xprobe.py')), str(binary),
                                  str(work / f'run-{mode}'), mode], timeout=600).returncode
    print(f'xprobe {mode} exit {codes[mode]}', flush=True)
# The product listens on the default control socket, which is the path the stock proxy dials.
sys.exit(codes['default'])
