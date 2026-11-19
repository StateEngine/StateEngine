import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import threading
import time

import psutil

helper = Path(sys.argv[1]).resolve(strict=True)
root = Path(sys.argv[2]).resolve()
root.mkdir()
image_dir = root / 'image'
image_dir.mkdir()
image = image_dir / helper.name
shutil.copy2(helper, image)
for key in list(os.environ):
    if key.startswith(('SE_', 'STATEENGINE_', 'CODEX_', 'CLAUDE', 'OPENAI_', 'ANTHROPIC_')):
        del os.environ[key]
for key, sub in [('HOME', 'owner'), ('USERPROFILE', 'owner'), ('XDG_CONFIG_HOME', 'config'),
                 ('XDG_DATA_HOME', 'data'), ('XDG_CACHE_HOME', 'cache'), ('APPDATA', 'appdata'),
                 ('LOCALAPPDATA', 'localappdata'), ('TMPDIR', 'temp'), ('TEMP', 'temp'), ('TMP', 'temp')]:
    path = root / sub
    path.mkdir(exist_ok=True)
    os.environ[key] = str(path)
os.environ['SE_W3_SE_BIN'] = str(image)
probe = Path(sys.argv[3]).resolve(strict=True)
measurements = []
for trial in range(3):
    with (root / f'stderr-{trial}.log').open('w') as stderr:
        child = subprocess.Popen([str(probe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=stderr, text=True, bufsize=1)
        messages = queue.Queue()
        def read_lines():
            for line in child.stdout:
                messages.put(line.strip())
            messages.put(None)
        threading.Thread(target=read_lines, daemon=True).start()
        def receive():
            line = messages.get(timeout=120)
            if line is None:
                raise RuntimeError(f'probe exited {child.poll()}; see stderr-{trial}.log')
            return line
        try:
            if receive() != 'baseline':
                raise RuntimeError('baseline missing')
            process = psutil.Process(child.pid)
            baseline = process.memory_info().rss
            child.stdin.write('start\n')
            child.stdin.flush()
            ready = receive().split()
            if len(ready) != 2 or ready[0] != 'ready':
                raise RuntimeError(f'ready missing: {ready}')
            rss = process.memory_info().rss
            measurements.append({'startup_ms': float(ready[1]), 'baseline_rss_bytes': baseline,
                                 'ready_rss_bytes': rss, 'rss_delta_bytes': rss - baseline})
            child.stdin.write('stop\n')
            child.stdin.flush()
            if receive() != 'closed':
                raise RuntimeError('closed receipt missing')
            code = child.wait(timeout=60)
            if code:
                raise RuntimeError(f'probe exited {code}')
        finally:
            if child.poll() is None:
                child.stdin.close()
                try:
                    child.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    raise RuntimeError(f'owned probe {child.pid} remains live')
    lines = (root / f'stderr-{trial}.log').read_text(errors='replace').splitlines()
    measurements[-1]['phases'] = {key: float(value) for key, value in
                                  (line.split('=', 1) for line in lines if line.startswith(('open_ms=', 'epoch_ms=', 'activate_ms=')))}
print(json.dumps({'platform': sys.platform, 'measurements': measurements}, sort_keys=True))
