"""Read completed native smoke receipts without promoting missing evidence."""
import argparse
import json
import math
from pathlib import Path
import re

from .flow import PHASES
from .io import require, runner_files, save
from .inputs import DRIVERS, RESULTS

PLATFORMS = ('linux', 'win32', 'darwin')


def text(value):
    return isinstance(value, str) and bool(value)


def proof(phases, provider):
    for phase in phases.values():
        if phase['result'] != 'PASS':
            continue
        require(isinstance(phase.get('evidence'), dict), 'passing phase lacks evidence')
        elapsed = phase.get('elapsed_seconds')
        require(type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0,
                'passing phase has no measured duration')
    require(phases['Launch']['result'] == 'PASS', 'passing work requires a proven native launch')
    launch = phases['Launch']['evidence']
    require(launch.get('state') == 'running' and launch.get('surface') == 'headless'
            and launch.get('provider') == provider
            and type(launch.get('process', {}).get('pid')) is int and launch['process']['pid'] > 0
            and text(launch.get('conversation_id')) and text(launch.get('session_id')),
            'launch evidence lacks native process or conversation identity')
    captures = {}
    for name in ('Work', 'Mail', 'Resume'):
        if phases[name]['result'] != 'PASS':
            continue
        evidence = phases[name]['evidence']
        messages = evidence.get('replies' if name == 'Mail' else 'messages')
        capture = evidence.get('capture')
        if name == 'Mail':
            require(isinstance(messages, list) and messages and all(text(value) for value in messages),
                    'mail lacks an authenticated owner reply')
        require(isinstance(capture, dict) and text(capture.get('conversation'))
                and text(capture.get('session')) and isinstance(capture.get('events'), list)
                and capture['events'] and all(text(value) for value in capture['events']),
                name + ' lacks canonical assistant capture identity')
        require(capture['conversation'] == launch['conversation_id'], 'provider conversation changed')
        require((capture['session'] != launch['session_id']) if name == 'Resume'
                else (capture['session'] == launch['session_id']), 'managed session continuity differs')
        if name in ('Work', 'Resume'):
            require(isinstance(evidence.get('file_sha256'), str)
                    and re.fullmatch(r'[a-f0-9]{64}', evidence['file_sha256'])
                    and evidence['file_sha256'] == evidence.get('expected_sha256'),
                    name + ' lacks witnessed file bytes')
        if name == 'Mail':
            require(text(evidence.get('sent')), 'mail has no committed send identity')
        captures[name] = set(capture['events'])
    require(not captures.get('Resume', set()).intersection(
                captures.get('Work', set()) | captures.get('Mail', set())),
            'resume substituted an earlier captured event')


def read(path):
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        require(isinstance(value, dict), 'receipt is not an object')
        return value, None
    except FileNotFoundError:
        return None, 'absent'
    except (OSError, ValueError, RuntimeError) as error:
        return None, 'unreadable or invalid: ' + str(error)


def native(directory, source_commit, manifest_sha256, expected, cycle):
    result, error = read(directory / 'results.json')
    require(error is None, 'results.json: ' + str(error))
    observed_files = result.get('runner_sha256')
    expected_files = runner_files()
    require(isinstance(observed_files, dict) and set(observed_files) == set(expected_files),
            'native producer file inventory is incomplete')
    # The native producer does not execute either report entry point. Its
    # captures remain usable when only the independently pinned reader changes.
    report_files = {'harness-matrix-report.py', 'harness_matrix/report.py'}
    require(all(observed_files[name] == digest for name, digest in expected_files.items()
                if name not in report_files), 'native producer source identity differs')
    require(result.get('schema') == 'se.harness-matrix/v1'
            and result.get('platform') in PLATFORMS
            and result.get('source_commit') == source_commit and result.get('cycle') == cycle
            and result.get('manifest_sha256') == manifest_sha256,
            'matrix receipt identity differs from the selected run')
    require(isinstance(result.get('expected'), list) and result['expected'] == expected,
            'planned matrix coverage differs')
    cells = result.get('cells')
    require(isinstance(cells, list) and len(cells) == len(expected)
            and [row.get('harness') for row in cells] == expected, 'incomplete or duplicate matrix rows')
    verified = {}
    for row in cells:
        try:
            verified[row['harness']] = verify_cell(directory, row, result, source_commit, manifest_sha256)
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
            verified[row['harness']] = dict(result='UNREADABLE', reason=str(error),
                phases={phase: dict(result='NOT RUN') for phase in PHASES})
    return result['platform'], verified, result.get('state') == 'finished'


def verify_cell(directory, row, result, source_commit, manifest_sha256):
    # Resolve from the declared id, not a path supplied by the producer receipt.
    receipt, error = read(directory / row['harness'] / 'receipt.json')
    require(error is None, row['harness'] + ': ' + str(error))
    require(row.get('platform') == result['platform']
            and receipt.get('harness') == row['harness']
            and receipt.get('platform') == row['platform']
            and row.get('result') in RESULTS
            and receipt.get('result') == row['result'], 'native cell identity or result differs')
    phases = row.get('phases')
    require(isinstance(phases, dict) and set(phases) == set(PHASES)
            and phases == receipt.get('phases'), 'native phase coverage differs')
    for phase in phases.values():
        require(isinstance(phase, dict) and phase.get('result') in ('PASS', 'FAIL', 'NOT RUN'),
                'invalid native phase result')
    if any(phase['result'] == 'PASS' for phase in phases.values()):
        require(receipt.get('state') == 'finished'
                and receipt.get('source_commit') == source_commit and receipt.get('cycle') == result['cycle']
                and receipt.get('manifest_sha256') == manifest_sha256
                and receipt.get('build_sha256') == result.get('build_sha256')
                and receipt.get('runner_sha256') == result['runner_sha256']
                and isinstance(result.get('build_sha256'), str), 'passing phase source identity differs')
        require(row.get('driver') in DRIVERS and receipt.get('driver') == row['driver'],
                'passing phase has no matching adapter driver')
        proof(phases, DRIVERS[row['driver']])
    if row['result'] == 'PASS':
        require(receipt.get('cleanup') == row.get('cleanup') == []
                and receipt.get('process_closure') == row.get('process_closure') == []
                and not receipt.get('failure') and all(phase['result'] == 'PASS' for phase in phases.values()),
                'passing cell lacks complete native evidence')
    return dict(result=row['result'], phases=phases,
                reason=row.get('reason', row.get('failure')))


def summarize(inputs, source_commit, manifest_sha256, expected, cycle):
    require(expected and len(set(expected)) == len(expected)
            and all(isinstance(name, str) and name and '/' not in name and '\\' not in name
                    and name not in ('.', '..') for name in expected), 'invalid expected harness ids')
    platforms, errors = {}, []
    for directory in inputs:
        try:
            platform, values, finished = native(directory, source_commit, manifest_sha256, expected, cycle)
            require(platform not in platforms, 'duplicate native platform receipt')
            platforms[platform] = values
            if not finished:
                errors.append(platform + ': native matrix producer did not finish')
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
            errors.append(str(directory) + ': ' + str(error))
    rows = []
    for harness in expected:
        rows.append(dict(harness=harness, platforms={platform: platforms.get(platform, {}).get(harness,
            dict(result='ABSENT', reason='native receipt unavailable',
                 phases={phase: dict(result='NOT RUN') for phase in PHASES})) for platform in PLATFORMS}))
    passed = not errors and all(cell['result'] == 'PASS' for row in rows for cell in row['platforms'].values())
    failed = bool(errors) or any(cell['result'] in ('FAIL', 'UNREADABLE') for row in rows for cell in row['platforms'].values())
    return dict(schema='se.harness-matrix-summary/v1', source_commit=source_commit,
                manifest_sha256=manifest_sha256, runner_sha256=runner_files(), cycle=cycle,
                result='PASS' if passed else 'FAIL' if failed else 'INCOMPLETE', errors=errors,
                qualification='smoke-only; clean-machine and performance qualification unassessed', rows=rows)


def markdown(summary):
    lines = ['| Harness | Linux | Windows | macOS |', '| --- | --- | --- | --- |']
    for row in summary['rows']:
        lines.append('| ' + ' | '.join([row['harness'],
            *[row['platforms'][platform]['result'] for platform in PLATFORMS]]) + ' |')
    return '\n'.join(lines) + '\n\n' + summary['qualification'] + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cycle', required=True)
    parser.add_argument('--input', type=Path, action='append', default=[])
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--expected', nargs='+', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    summary = summarize(args.input, args.source_commit, args.manifest_sha256, args.expected, args.cycle)
    save(args.out / 'matrix.json', summary)
    (args.out / 'matrix.md').write_text(markdown(summary), encoding='utf-8')
    return 0 if summary['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
