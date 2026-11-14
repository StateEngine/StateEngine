#!/usr/bin/env python3
"""Protects: G6/G8 — two Windows state homes own distinct authenticated native pipes.

Native Windows: python -I windows_two_homes.py --se IMAGE --out NEW_DIRECTORY.
Stage this file, windows_runtime_events.py and the tests/judges directory together.
No provider account or vendor process is required.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / 'judges'))
from windows_runtime_events import Pin, api, read_json, wait_for
from mail_cli import Fixture


def run(args):
    root = Path(tempfile.mkdtemp(prefix='se-two-homes-'))
    print("fixture root (retained on failed or interrupted closure):", root, flush=True)
    image = root / 'se.exe'
    shutil.copy2(args.se, image)
    report = {'binary_sha256': hashlib.sha256(image.read_bytes()).hexdigest(),
              'stage': 'public init of two private homes', 'passed': 0, 'failed': 1,
              'failures': [], 'cleanup_errors': [], 'fixture': str(root)}
    fixtures, pins = [], []
    kernel = api()
    try:
        for label in ('first', 'second'):
            fixture = Fixture(image, root / label)
            (fixture.repo / 'user.txt').write_bytes(b'Keep independent user work.\r\n')
            fixtures.append(fixture)
        starts, endpoints = [], []
        for fixture in fixtures:
            report['stage'] = 'public up: ' + fixture.root.name
            starts.append(fixture.ok('up'))
            endpoint = read_json(fixture.home / 'endpoint.json')
            endpoints.append(endpoint)
            pins.append(Pin(kernel, endpoint['epoch']['owner']['pid']))
        report['endpoints'] = [entry['address'] for entry in endpoints]
        if endpoints[0]['address'] == endpoints[1]['address']:
            raise AssertionError('different homes advertise the same native pipe')
        if pins[0].record['pid'] == pins[1].record['pid']:
            raise AssertionError('different homes share one native host')
        report['stage'] = 'authenticate both existing hosts while both are running'
        for fixture, pin in zip(fixtures, pins):
            repeated = fixture.ok('up')
            if repeated['process']['pid'] != pin.record['pid'] or pin.exited():
                raise AssertionError('existing-host discovery lost its exact home owner')
        report['stage'] = 'stop first home and independently read back second host'
        stopped = fixtures[0].ok('down')
        if not stopped['complete'] or stopped['witness']['state'] != 'witnessed':
            raise AssertionError('first home did not witness shutdown')
        wait_for(pins[0].exited, 'first host did not exit')
        if (fixtures[0].home / 'endpoint.json').exists():
            raise AssertionError('first endpoint retained after witnessed down')
        repeated = fixtures[1].ok('up')
        if repeated['process']['pid'] != pins[1].record['pid'] or pins[1].exited():
            raise AssertionError('stopping one home disrupted the second home')
        if read_json(fixtures[1].home / 'endpoint.json') != endpoints[1]:
            raise AssertionError('second endpoint identity changed after first home shutdown')
        report['stage'] = 'both independent native homes verified'
    except Exception as error:
        report['failures'].append(type(error).__name__ + ': ' + str(error))
        report['traceback'] = traceback.format_exc()
    finally:
        for fixture in fixtures:
            try:
                if (fixture.home / 'endpoint.json').exists():
                    result = fixture.ok('down')
                    if not result['complete'] or result['witness']['state'] != 'witnessed':
                        raise AssertionError('public cleanup has no closure witness')
                if (fixture.home / 'endpoint.json').exists():
                    raise AssertionError('public cleanup retained endpoint')
                if (fixture.repo / 'user.txt').read_bytes() != b'Keep independent user work.\r\n':
                    raise AssertionError('user work changed')
            except Exception as error:
                report['cleanup_errors'].append(fixture.root.name + ': ' + str(error))
        try:
            wait_for(lambda: all(pin.exited() for pin in pins), 'known native hosts remain after public cleanup')
        except Exception as error:
            report['cleanup_errors'].append(str(error))
        report['known_instances'] = [pin.record for pin in pins]
        for pin in pins:
            pin.close()
    if not report['failures'] and not report['cleanup_errors']:
        try:
            shutil.rmtree(root)
        except OSError as error:
            report['cleanup_errors'].append('fixture removal: ' + str(error))
    passed = not report['failures'] and not report['cleanup_errors']
    report.update(passed=int(passed), failed=int(not passed))
    (args.out / 'results.json').write_text(json.dumps(report, indent=2))
    print(f"Windows independent homes: {report['passed']} passed, {report['failed']} failed", flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    options = parser.parse_args()
    if os.name != 'nt':
        parser.error('native Windows required')
    options.se = options.se.resolve(strict=True)
    options.out.mkdir(mode=0o700)
    sys.exit(run(options))
