"""Measure automatic whole-home closure using the same native consumer fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import threading
import time

import probe


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def observe(home, finished, samples):
    pending = home / 'staging' / '.se-stage-backup-pending'
    index = home / 'backups' / 'backup-index.json'
    # The production grace period is ten minutes. Observe only near expiry.
    if finished.wait(570):
        return
    try:
        baseline = index.stat().st_mtime_ns
    except FileNotFoundError:
        baseline = None
    while not finished.is_set():
        now = time.monotonic_ns()
        if 'pending_first_ns' not in samples and pending.exists():
            samples['pending_first_ns'] = now
        try:
            stamp = index.stat().st_mtime_ns
        except FileNotFoundError:
            stamp = None
        if stamp is not None and stamp != baseline and 'index_changed_ns' not in samples:
            samples['index_changed_ns'] = now
        finished.wait(.01)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--images', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'nt':
        raise SystemExit('Native Windows is required')
    args.output.mkdir(parents=True, exist_ok=False)
    original_wait = probe.wait_for
    results = []
    for number in range(3):
        for side in ('frozen', 'main', 'head'):
            image = (args.images / side / 'se.exe').resolve(strict=True)
            out = args.output / f'{number + 1}-{side}'
            out.mkdir()
            probe.protect(out)
            receipt = {'side': side, 'iteration': number + 1,
                       'binary_sha256': sha256(image), 'result': 'FAIL'}
            samples = {}
            finished = threading.Event()
            worker = None

            def wait_for(test, seconds, reason):
                nonlocal worker
                if reason == 'Expiry never retired the endpoint':
                    worker = threading.Thread(target=observe,
                        args=(out / 'fixture' / 'state', finished, samples), daemon=True)
                    worker.start()
                return original_wait(test, seconds, reason)

            probe.wait_for = wait_for
            probe.ROOT = image.parent
            try:
                probe.run(out, receipt, {'files': {'se.exe': receipt['binary_sha256']}})
                if receipt.get('cleanup_errors'):
                    raise RuntimeError('Fixture cleanup is incomplete')
                receipt['result'] = 'PASS'
            except Exception as error:
                receipt['failure'] = str(error) or type(error).__name__
            finally:
                finished.set()
                if worker is not None:
                    worker.join()
                probe.wait_for = original_wait
            if 'pending_first_ns' in samples and 'index_changed_ns' in samples:
                receipt['observed_stage_to_index_ms'] = (
                    samples['index_changed_ns'] - samples['pending_first_ns']) / 1_000_000
            else:
                receipt['observed_stage_to_index_ms'] = None
            report = out / 'fixture' / 'state' / 'runtime-spawner-close.json'
            if report.exists():
                record = json.loads(report.read_bytes())
                receipt['resources_closed'] = record.get('resources_closed')
                receipt['pending'] = record.get('pending')
            receipt['observation'] = samples
            results.append(receipt)
            (args.output / 'results.json').write_text(json.dumps(results, indent=2))
            print(json.dumps(receipt), flush=True)
    return 0 if len(results) == 9 and all(r['result'] == 'PASS' for r in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
