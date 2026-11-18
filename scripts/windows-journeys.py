#!/usr/bin/env python3
"""Run one real native Windows harness through the five public user journeys.

Use Python 3.11+ from a registered disposable installation-test account outside
managed agent trees. Each invocation selects a harness id from the same private
manifest as harness-matrix.py. Provision an access-only seed immediately before
the invocation. Evidence and credential homes must remain private.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import sys

from harness_matrix.inputs import Unavailable, name, preflight
from harness_matrix.io import InterruptedRun, digest, raw_census, require, runner_files, save
from windows_journeys.credentials import Credentials, Prerequisite, protect, provision
from windows_journeys.flow import JOURNEYS, Journeys
from windows_journeys.foreground import DETACHED_HOST_COVERAGE


def execute(args):
    require(sys.platform == 'win32', 'The five Windows journeys require native Windows')
    baseline_rows = raw_census()
    require(re.fullmatch(r'[A-Za-z0-9_.:+-]{1,128}', args.cycle), 'A bounded cycle identity is required')
    require(args.manifest.stat().st_size <= 1024**2, 'Private manifest exceeds one MiB')
    source = json.loads(args.manifest.read_text(encoding='utf-8'))
    require(source.get('schema') == 'se.harness-matrix-input/v1', 'Unsupported matrix manifest schema')
    entries = source.get('harnesses')
    require(isinstance(entries, list) and 1 <= len(entries) <= 64
            and all(isinstance(entry, dict) and name(entry.get('id')) for entry in entries),
            'Expected a bounded harness-id table')
    require(len({entry['id'] for entry in entries}) == len(entries), 'Harness ids are duplicated')
    selected = [entry for entry in entries if entry['id'] == args.harness]
    require(len(selected) == 1, 'Selected harness id is absent from the shared table')
    require(not any(key.upper() == 'SE_SESSION' or key.upper().startswith(('STATEENGINE_', 'SECODE_'))
                    for key in os.environ), 'Start outside managed agent trees; runtime authority is present')
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    protect(args.out)
    scripts = Path(__file__).resolve().parent
    runners = runner_files()
    for path in [Path(__file__), *sorted((scripts / 'windows_journeys').glob('*.py')),
                 scripts / 'windows_journeys/terminal.ps1']:
        runners[str(path.relative_to(scripts)).replace('\\', '/')] = digest(path)
    record = dict(schema='se.windows-journeys/v1', platform=sys.platform, cycle=args.cycle,
                  harness=args.harness, manifest_sha256=digest(args.manifest), runner_sha256=runners,
                  registry=[dict(id=entry['id'], driver=entry.get('driver')) for entry in entries],
                  result='NOT RUN', phases={key: dict(result='NOT RUN') for key in JOURNEYS})
    if args.foreground_runtime:
        record['detached_host_start'] = DETACHED_HOST_COVERAGE
    save(args.out / 'results.json', record)
    runner = None
    try:
        entry = selected[0]
        if entry.get('driver') == 'secode-native':
            raise Prerequisite('NOT READY', 'Native registry credential contract is not available for this row')
        require(entry.get('driver') in ('claude-stream-json', 'codex-app-server'),
                'This row has no real-provider journey adapter')
        windows = entry.get('platforms', {}).get('win32', {})
        require(isinstance(windows, dict), 'Windows harness settings must be an object')
        require(not windows.get('environment') and not windows.get('required_environment'),
                'Provider credentials must come from the private access-only seed, never inherited environment')
        homes = windows.get('home_environment', {})
        require(homes in ({}, {'CODEX_HOME': '.codex'}), 'Use the standard private native credential homes')
        terminal = [sys.executable, '-B', str(scripts / 'windows_journeys/terminal.py')]
        adapted = {**entry, 'platforms': {**entry.get('platforms', {}),
                                        'win32': {**windows, 'terminal_prefix': terminal}}}
        settings, observation = preflight(adapted)
        Credentials(settings['credential_seed'], settings['provider'])
        release = source['windows_journeys']['release']
        require(re.fullmatch(r'[a-f0-9]{40}', release.get('source_commit', '')),
                'Release source requires one full commit identity')
        runner = Journeys(args.out, args.out / 'release', entry, settings, os.environ,
                          release=release, baseline_rows=baseline_rows, foreground_runtime=args.foreground_runtime)
        runner.record.update(inputs=observation, manifest_sha256=record['manifest_sha256'],
                             runner_sha256=runners, cycle=args.cycle)
        record.update(runner.run())
    except (Prerequisite, Unavailable, FileNotFoundError, PermissionError) as error:
        record.update(result='INCOMPLETE', prerequisite=dict(
            state=getattr(error, 'state', 'ABSENT' if isinstance(error, FileNotFoundError) else 'UNREADABLE'),
            reason=str(error)))
    except (InterruptedRun, KeyboardInterrupt):
        if runner is not None:
            record.update(runner.record)
        record.update(result='INCOMPLETE', interrupted=True)
    except Exception as error:
        if runner is not None:
            record.update(runner.record)
        record.update(result='FAIL', failure=str(error))
    finally:
        record['state'] = 'finished'
        save(args.out / 'results.json', record)
    print(json.dumps({key: record[key] for key in ('harness', 'state', 'result')}))
    return 0 if record['result'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    run = commands.add_parser('run', help='run one harness-id row')
    run.add_argument('--manifest', required=True, type=Path)
    run.add_argument('--harness', required=True)
    run.add_argument('--cycle', required=True)
    run.add_argument('--out', required=True, type=Path)
    run.add_argument('--foreground-runtime', action='store_true',
                     help='Use the public foreground host for a hosted Windows job that forbids breakaway')
    seed = commands.add_parser('provision', help='accept freshly minted native JSON on stdin')
    seed.add_argument('--provider', choices=['claude', 'codex'], required=True)
    seed.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, lambda signum, frame: interrupt(signum))
    if args.command == 'provision':
        raw = sys.stdin.buffer.read(65537)
        require(len(raw) <= 65536, 'Provisioning input exceeds its finite bound')
        print(json.dumps(provision(args.provider, json.loads(raw), args.out)))
        return 0
    return execute(args)


def interrupt(signum):
    raise InterruptedRun('Windows journeys interrupted by signal ' + str(signum))


if __name__ == '__main__':
    raise SystemExit(main())
