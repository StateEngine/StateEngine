"""Measure an isolated host after one provider turn has completed."""
import hashlib
import csv
from collections import Counter
import re
import json
import os
from pathlib import Path
import socket
import subprocess
import shutil
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


source_binary = Path(sys.argv[1]).resolve()
root = Path(sys.argv[2]).resolve()
image_dir = root.parent / (root.name + '-binary')
image_dir.mkdir()
binary = image_dir / source_binary.name
shutil.copy2(source_binary, binary)
f = Fixture(binary, root, provider_helper=repo / 'probes/idle-provider.py')
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(('127.0.0.1', 0))
listener.listen(1)
listener.settimeout(60)
nonce = uuid.uuid4().hex
(f.repo / 'idle-control.json').write_text(json.dumps({'port': listener.getsockname()[1], 'nonce': nonce}))
connection = None
child = None
out = (root / 'up.stdout').open('wb')
err = (root / 'up.stderr').open('wb')
result = {'platform': sys.platform, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
          'fixture': 'one live session with a completed turn and account-free provider',
          'warmup_seconds': 10, 'requested_seconds': 60}
try:
    child = subprocess.Popen([str(binary), '--json', '--home', str(f.home), 'up', '--foreground'],
                             stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                             env=f.env, cwd=f.repo)
    until = time.monotonic() + 90
    while not (f.home / 'endpoint.json').exists():
        if child.poll() is not None or time.monotonic() >= until:
            raise RuntimeError(f"foreground host unavailable: {(root / 'up.stderr').read_text(errors='replace')}")
        time.sleep(.05)
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
    counter_error = 'context switch counter regressed as threads changed' if switch_count < 0 else None
    if counter_error:
        switch_count = None
    result.update(pid=pid, seconds=seconds, cpu_seconds=cpu, cpu_percent_one_core=100 * cpu / seconds,
                  context_switches=switch_count,
                  context_switches_per_second=(switch_count / seconds if switch_count is not None else None),
                  counter_error=counter_error,
                  accounting='native process context switches; proxy for wakeups, not a direct wakeup count',
                  observer='Linux status calls bracket the measurement; their host work is included')
    if sys.platform == 'win32':
        # An independent second window records context-switch events even when
        # short-lived threads make the process aggregate go backwards.
        kits = Path(os.environ.get('ProgramFiles(x86)', ''))
        xperf = kits / 'Windows Kits/10/Windows Performance Toolkit/xperf.exe'
        trace = root / 'switches.etl'
        if not xperf.is_file():
            result['trace_status'] = 'unavailable: Windows Performance Toolkit missing'
        else:
            start_trace = subprocess.run([str(xperf), '-on', 'PROC_THREAD+CSWITCH'],
                                         capture_output=True, text=True, timeout=30)
            if start_trace.returncode != 0:
                result['trace_status'] = 'unavailable: ' + start_trace.stderr[-2000:]
            else:
                try:
                    time.sleep(62)
                finally:
                    stopped = subprocess.run([str(xperf), '-d', str(trace)],
                                             capture_output=True, text=True, timeout=60)
                if stopped.returncode != 0:
                    result['trace_status'] = 'unavailable: ' + stopped.stderr[-2000:]
                else:
                    report = subprocess.run([str(xperf), '-i', str(trace), '-a', 'cswitch', '-process'],
                                            capture_output=True, text=True, timeout=60)
                    result['trace_status'] = 'captured' if report.returncode == 0 else 'analysis failed'
                    result['trace_report'] = report.stdout[-30000:]
                    result['trace_report_truncated'] = len(report.stdout) > 30000
                    result['trace_error'] = report.stderr[-2000:]
                    dump_path = root / 'switches.txt'
                    dump = subprocess.run([str(xperf), '-i', str(trace), '-o', str(dump_path), '-a', 'dumper'],
                                          capture_output=True, text=True, timeout=180)
                    result['dump_status'] = dump.returncode
                    if dump.returncode == 0:
                        lost = reliable = trace_length = None
                        incoming = 0
                        wait_reasons = Counter()
                        pattern = re.compile(r'\(\s*' + str(pid) + r'\s*\)$')
                        with dump_path.open(errors='replace', newline='') as rows:
                            for line in rows:
                                if line.startswith('OS Version:'):
                                    metadata = re.search(r'Events Lost: (\d+), Buffers lost: (\d+).*Trace Length: (\d+) sec', line)
                                    if metadata:
                                        lost = int(metadata[1]) + int(metadata[2])
                                        trace_length = int(metadata[3])
                                parts = next(csv.reader([line]))
                                if len(parts) == 2 and parts[0].strip() == 'FirstReliableCSwitchEventTimeStamp':
                                    value = parts[1].strip()
                                    if value.isdigit():
                                        reliable = int(value)
                                if len(parts) < 14 or parts[0].strip() != 'CSwitch':
                                    continue
                                stamp = parts[1].strip()
                                if not stamp.isdigit() or not 1_000_000 <= int(stamp) < 61_000_000:
                                    continue
                                if pattern.search(parts[2].strip()):
                                    incoming += 1
                                if pattern.search(parts[8].strip()):
                                    wait_reasons[parts[13].strip()] += 1
                        if lost == 0 and reliable is not None and reliable <= 1_000_000 and trace_length is not None and trace_length >= 61:
                            after_trace = f.ok('--project', f.project, 'status')
                            if process.create_time() != birth or after_trace['runtime']['process']['pid'] != pid:
                                raise RuntimeError('host process changed during trace')
                            result['trace_switch_ins'] = incoming
                            result['trace_switch_ins_per_second'] = incoming / 60
                            result['trace_wait_reasons'] = dict(wait_reasons)
                            result['trace_window'] = '60 seconds after first second; all host switch-ins, including preemptions'
                        else:
                            result['trace_status'] = f'unavailable: lost={lost}, reliable={reliable}, length={trace_length}'
    print(json.dumps(result, sort_keys=True), flush=True)
finally:
    try:
        f.close()
    finally:
        if connection is not None:
            connection.close()
        listener.close()
        if child is not None:
            code = child.wait(timeout=60)
            if code != 0:
                raise RuntimeError(f'foreground host exited {code}')
        out.close()
        err.close()
