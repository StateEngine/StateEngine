"""Measure every synthetic output ID through the public persistent CLI watcher.

This is a performance observation, not an independent correctness judge. Sources,
raw pages, producer brackets, sample counts and failed attempts remain explicit.
"""
import ctypes
import json
import math
import os
from pathlib import Path
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'crates/se/tests/judges'))
from mail_cli import Fixture


def save(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')


def native(pid):
    try:
        root = Path('/proc') / str(pid)
        parts = (root / 'stat').read_text().rsplit(') ', 1)[1].split()
        return {'pid': pid, 'birth': parts[19], 'state': parts[0],
                'argv': (root / 'cmdline').read_bytes().hex()}
    except FileNotFoundError:
        return None


def same(old):
    row = native(old['pid'])
    return row is not None and row['birth'] == old['birth'] and row['argv'] == old['argv']


def stats(values):
    ordered = sorted(values)
    return {'count': len(ordered), 'median_ms': ordered[len(ordered) // 2],
            'p95_ms': ordered[math.ceil(len(ordered) * .95) - 1], 'max_ms': ordered[-1]}


def pump(stream, path, items):
    with path.open('wb') as log:
        for line in iter(stream.readline, b''):
            at = time.monotonic_ns()
            log.write(line)
            log.flush()
            items.put((at, line))
    items.put((time.monotonic_ns(), None))


def cohort(image, root, count=120):
    f = Fixture(image, root / 'fixture', provider_helper=Path(__file__).with_name('provider.py'))
    # Retain no ambient provider credentials or profile variables.
    f.env = {k: v for k, v in f.env.items() if k in ('HOME', 'USERPROFILE', 'PATH', 'LANG', 'SHELL', 'TMPDIR')
             or k.startswith('XDG_')}
    trace = os.environ.get('OUTPUT_OBSERVER_TRACE')
    if trace:
        f.env['OUTPUT_OBSERVER_TRACE'] = trace
    delay_ms = int(os.environ.get('OUTPUT_RESULT_DELAY_MS', '0'))
    if not 0 <= delay_ms <= 1000:
        raise ValueError('Result delay must be between zero and 1000 ms')
    (f.repo / 'result-delay-ms').write_text(str(delay_ms))
    os.mkfifo(f.repo / 'output-control', 0o600)
    records, measurements = queue.Queue(), queue.Queue()
    watcher = None
    known, threads, rows, cleanup = [], [], [], []
    failure = None
    try:
        up = f.ok('up')
        known.append(native(up['process']['pid']))
        f.launch()
        known.extend(native(pid) for pid, _ in f.processes)
        if any(row is None for row in known):
            raise ValueError('Owned process identity is absent before measurement')
        argv = [str(image), '--home', str(f.home), '--project', f.project, '--json',
                'client', 'watch', '--target', f.project + '/' + f.agent, '--measure',
                '--wait-ms', '1000', '--budget', '65536']
        watcher = subprocess.Popen(argv, cwd=f.repo, env=f.env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        known.append(native(watcher.pid))
        for stream, name, items in [(watcher.stdout, 'watch.stdout', records),
                                     (watcher.stderr, 'watch.stderr', measurements)]:
            worker = threading.Thread(target=pump, args=(stream, root / name, items))
            worker.start()
            threads.append(worker)
        # Drain the initial finite snapshot and manifest before timing live output.
        ready = False
        until = time.monotonic() + 30
        while time.monotonic() < until:
            _, line = records.get(timeout=30)
            if line is None:
                raise ValueError('Watcher exited before its initial snapshot')
            page = json.loads(line)
            if page.get('complete') and not page.get('reset_required'):
                ready = True
                break
        if not ready:
            raise ValueError('Watcher never completed its initial snapshot')
        with (f.repo / 'output-control').open('w', buffering=1) as control:
            for index in range(count + 10):
                marker = f'output-probe-{index:05d}'
                control.write(marker + '\n')
                deadline = time.monotonic() + 15
                visible = measured = None
                while visible is None:
                    at, line = records.get(timeout=max(.001, deadline - time.monotonic()))
                    if line is None:
                        raise ValueError('Watcher ended during output observation')
                    page = json.loads(line)
                    for record in page.get('records', []):
                        if record.get('type') == 'provisional' and record.get('item', {}).get('item_id') == marker:
                            visible = {'at_ns': at, 'record': record, 'clock': page.get('observation_clock')}
                while measured is None:
                    at, line = measurements.get(timeout=max(.001, deadline - time.monotonic()))
                    if line is None:
                        raise ValueError('Watcher timing stream ended')
                    event = json.loads(line)
                    if event.get('boundary') == 'provisional_flushed' and event.get('item_id') == marker:
                        measured = {'at_ns': at, 'record': event}
                rows.append({'id': marker, 'warmup': index < 10, 'visible': visible, 'flushed': measured})
                # Avoid an artificial synchronized producer/watcher phase.
                time.sleep(.013 + ((index * 17) % 47) / 1000)
        until = time.monotonic() + 15
        while True:
            producers = {row['id']: row for row in map(json.loads, (f.repo / 'producer.jsonl').read_text().splitlines())}
            if len(producers) == count + 10 or time.monotonic() >= until:
                break
            time.sleep(.01)
        if len(producers) != count + 10 or len(rows) != count + 10:
            raise ValueError('Producer/reader sample accounting differs')
        for row in rows:
            producer = producers[row['id']]
            row['producer'] = producer
            row['latency_ms'] = (row['visible']['at_ns'] - producer['emit_begin_ns']) / 1e6
            row['post_flush_observer_ms'] = (row['flushed']['at_ns'] - producer['emit_begin_ns']) / 1e6
            if row['latency_ms'] < 0:
                raise ValueError('Same-boot monotonic clock ordering is inconsistent')
        summary = {'producer_to_reader_upper_bound': stats([r['latency_ms'] for r in rows if not r['warmup']]),
                   'producer_to_post_flush_observer_upper_bound': stats([r['post_flush_observer_ms'] for r in rows if not r['warmup']])}
    except Exception as error:
        failure = f'{type(error).__name__}: {error}'
        summary = None
    finally:
        if watcher is not None:
            old = next((p for p in known if p and p['pid'] == watcher.pid), None)
            if watcher.poll() is None and old and same(old):
                watcher.terminate()
            try:
                watcher.wait(timeout=10)
            except subprocess.TimeoutExpired:
                cleanup.append('Watcher did not terminate within ten seconds')
            for worker in threads:
                worker.join(timeout=5)
                if worker.is_alive():
                    cleanup.append('Reader thread did not join')
        try:
            f.close()
        except Exception as error:
            cleanup.append(f'Public shutdown: {error}')
        until = time.monotonic() + 10
        while time.monotonic() < until:
            for old in known:
                if old:
                    try:
                        os.waitpid(old['pid'], os.WNOHANG)
                    except ChildProcessError:
                        pass
            if all(not same(old) for old in known if old):
                break
            time.sleep(.02)
        remaining = [old for old in known if old and same(old)]
        if remaining:
            cleanup.append('Owned native identities remain after shutdown')
        result = {'failure': failure, 'cleanup_errors': cleanup, 'summary': summary,
                  'completion_delay_ms': delay_ms,
                  'samples': rows, 'known_instances': known, 'remaining': remaining,
                  'scope': 'Synthetic Claude protocol, real native transcript/host/IPC and persistent CLI; same hosted Linux boot; no GUI paint or paid provider',
                  'qualified': failure is None and not cleanup and len(rows) == count + 10}
        save(root / 'result.json', result)
        for source in f.log_root.glob('call-*.*'):
            shutil.copyfile(source, root / source.name)
        for name in ('producer.jsonl', 'provider-error.txt'):
            source = f.repo / name
            if source.exists():
                shutil.copyfile(source, root / name)
    if not result['qualified']:
        raise ValueError(json.dumps({'failure': failure, 'cleanup': cleanup}))
    print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0):
        raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER')
    output = Path(sys.argv[1]).resolve()
    image = Path(json.loads((output / 'image.json').read_text())['image'])
    cohort(image, output)
