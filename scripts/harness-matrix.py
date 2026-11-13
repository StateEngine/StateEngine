#!/usr/bin/env python3
"""Run a native harness smoke matrix using installed public commands.

Python 3.11+ is required. Inputs select an extracted native distribution and a
private JSON manifest of descriptor configurations, exact installed images and
native permission choices. Credential values come only from explicitly named
environment variables; no account credential file is read. Keep the new output
directory private: command evidence contains conversation text.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import sys

from harness_matrix.flow import PHASES, Smoke
from harness_matrix.inputs import Unavailable, name, preflight
from harness_matrix.io import InterruptedRun, digest, require, runner_files, save

PLATFORMS = {'linux': 'unknown-linux', 'darwin': 'apple-darwin', 'win32': 'pc-windows'}


def execute(args):
    require(sys.platform in PLATFORMS, 'This platform has no native observer')
    require(re.fullmatch(r'[a-f0-9]{40}', args.source_commit), 'An exact source commit is required')
    forbidden = [key for key in os.environ if key == 'SE_SESSION' or key.startswith(('STATEENGINE_', 'SECODE_'))]
    require(not forbidden, 'Start from an OS scheduler outside managed agent trees; runtime authority is present')
    source = json.loads(args.manifest.read_text(encoding='utf-8'))
    require(source.get('schema') == 'se.harness-matrix-input/v1', 'Unsupported matrix input schema')
    entries = source.get('harnesses')
    require(isinstance(entries, list) and 1 <= len(entries) <= 64, 'Expected 1..64 planned harnesses')
    require(all(isinstance(row, dict) and name(row.get('id')) for row in entries), 'Invalid harness identifier')
    require(len({row['id'] for row in entries}) == len(entries), 'Duplicate planned harness identifiers')
    metadata = json.loads((args.package / 'build.json').read_text(encoding='utf-8'))
    require(metadata.get('source_commit') == args.source_commit, 'Package source identity differs')
    require(PLATFORMS[sys.platform] in metadata.get('target', ''), 'Package is for a different native platform')
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    record = dict(schema='se.harness-matrix/v1', source_commit=args.source_commit,
                  platform=sys.platform, manifest_sha256=digest(args.manifest),
                  build_sha256=digest(args.package / 'build.json'), runner_sha256=runner_files(),
                  qualification='smoke-only; clean-machine and performance qualification unassessed',
                  expected=[row['id'] for row in entries], state='running', result='NOT RUN',
                  cells=[dict(harness=entry['id'], driver=entry.get('driver'), platform=sys.platform,
                              result='NOT RUN', phases={phase: dict(result='NOT RUN') for phase in PHASES},
                              cleanup=None, process_closure=None) for entry in entries])
    save(args.out / 'results.json', record)
    for entry, row in zip(entries, record['cells'], strict=True):
        output = args.out / entry['id']
        output.mkdir(mode=0o700)
        row['receipt'] = str(output / 'receipt.json')
        save(args.out / 'results.json', record)
        try:
            settings, observation = preflight(entry)
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
            state = error.state if isinstance(error, Unavailable) else ('ABSENT' if isinstance(error, FileNotFoundError)
                    else 'UNREADABLE' if isinstance(error, PermissionError) else 'FAIL')
            row.update(state='finished', result=state, reason=str(error))
            save(output / 'receipt.json', row)
        else:
            smoke = None
            try:
                smoke = Smoke(output, args.package, entry, settings, os.environ)
                smoke.record.update(inputs=observation, source_commit=args.source_commit,
                                    manifest_sha256=record['manifest_sha256'],
                                    build_sha256=record['build_sha256'], runner_sha256=record['runner_sha256'])
                row.update(smoke.run())
            except (InterruptedRun, KeyboardInterrupt) as error:
                if smoke is not None:
                    row.update(smoke.record)
                record.update(state='interrupted', result='INCOMPLETE', reason=str(error))
                save(args.out / 'results.json', record)
                raise
            except Exception as error:
                row.update(result='FAIL', reason='Runner interrupted: ' + str(error))
                save(output / 'receipt.json', row)
        save(args.out / 'results.json', record)
    record.update(state='finished', result='PASS' if all(row['result'] == 'PASS' for row in record['cells'])
                  else 'FAIL' if any(row['result'] in ('FAIL', 'UNREADABLE') for row in record['cells']) else 'INCOMPLETE')
    save(args.out / 'results.json', record)
    print(json.dumps({key: record[key] for key in ('platform', 'state', 'result', 'expected')}))
    return 0 if record['result'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True, help='extracted native distribution')
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--manifest', type=Path, required=True, help='private pinned harness inputs; no secret values')
    parser.add_argument('--out', type=Path, required=True, help='new private evidence directory')
    def interrupt(signum, frame):
        raise InterruptedRun('Native matrix interrupted by signal ' + str(signum))
    signal.signal(signal.SIGTERM, interrupt)
    try:
        return execute(parser.parse_args())
    except (InterruptedRun, KeyboardInterrupt):
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
