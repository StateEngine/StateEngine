"""Measure an isolated host after one provider turn has completed."""
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import time
import uuid

import psutil

repo = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo / 'crates/se/tests/judges'))
from mail_cli import Fixture

def switches(process, status):
    if sys.platform == 'linux':
        resources = status['runtime']['resources']
        return resources['self_voluntary_switches'] + resources['self_involuntary_switches']
    value = process.num_ctx_switches()
    return value.voluntary + value.involuntary


binary = Path(sys.argv[1]).resolve()
root = Path(sys.argv[2]).resolve()
f = Fixture(binary, root, provider_helper=repo / 'probes/idle-provider.py')
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(('127.0.0.1', 0))
listener.listen(1)
listener.settimeout(60)
nonce = uuid.uuid4().hex
(f.repo / 'idle-control.json').write_text(json.dumps({'port': listener.getsockname()[1], 'nonce': nonce}))
connection = None
result = {'platform': sys.platform, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
          'fixture': 'one live session with a completed turn and account-free provider',
          'warmup_seconds': 10, 'requested_seconds': 60}
try:
    f.ok('up')
    f.launch()
    connection, _ = listener.accept()
    connection.settimeout(30)
    control = connection.makefile('rb')
    if control.readline().strip().decode() != nonce:
        raise RuntimeError('provider control identity mismatch')
    connection.sendall(b'complete\n')
    if control.readline() != b'completed\n':
        raise RuntimeError('turn completion was not witnessed')
    status = f.ok('--project', f.project, 'status')
    pid = status['runtime']['process']['pid']
    active = [item for item in status['agents']['items'] if (item.get('session') or {}).get('state') == 'running']
    if len(active) != 1 or active[0]['id'] != f.agent:
        raise RuntimeError('expected exactly one running session')
    process = psutil.Process(pid)
    birth = process.create_time()
    time.sleep(10)
    before_status = f.ok('--project', f.project, 'status') if sys.platform == 'linux' else None
    start = time.monotonic()
    cpu_start = process.cpu_times()
    switches_start = switches(process, before_status)
    time.sleep(60)
    end_status = f.ok('--project', f.project, 'status') if sys.platform == 'linux' else None
    switches_end = switches(process, end_status)
    cpu_end = process.cpu_times()
    seconds = time.monotonic() - start
    if process.create_time() != birth:
        raise RuntimeError('host process identity changed')
    after_status = f.ok('--project', f.project, 'status')
    after_active = [item for item in after_status['agents']['items']
                    if (item.get('session') or {}).get('state') == 'running']
    if (len(after_active) != 1 or after_active[0]['id'] != f.agent
            or after_active[0]['session']['session_id'] != f.session
            or after_status['runtime']['process']['pid'] != pid):
        raise RuntimeError('host or live session changed during measurement')
    cpu = (cpu_end.user + cpu_end.system) - (cpu_start.user + cpu_start.system)
    switch_count = switches_end - switches_start
    if switch_count < 0:
        raise RuntimeError('context switch counter regressed')
    result.update(pid=pid, seconds=seconds, cpu_seconds=cpu, cpu_percent_one_core=100 * cpu / seconds,
                  context_switches=switch_count, context_switches_per_second=switch_count / seconds,
                  accounting='native process context switches; proxy for wakeups, not a direct wakeup count',
                  observer='Linux status calls bracket the measurement; their host work is included')
    print(json.dumps(result, sort_keys=True), flush=True)
finally:
    try:
        f.close()
    finally:
        if connection is not None:
            connection.close()
        listener.close()
