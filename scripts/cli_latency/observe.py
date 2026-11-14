"""Uninstrumented status cost of retaining authenticated host resource counters.

The baseline includes the accepted IPC encoder. Providers are configured only;
this is an author paired observation, not idle/session/provider qualification.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from support import ROUNDS, load, prepare, require, save, summaries, timed


def validate(sample, smoke, pid, side, dirty):
    require(sample['exit'] == 0 and sample['error'] is None, 'Public status failed')
    value = json.loads(sample['stdout'])
    require(value.get('schema') == 'se.status/v1' and value.get('ok') is not False,
            'Wrong status response family')
    project = value['project']
    require(project['state'] == 'present' and project['value']['id'] == smoke.project,
            'Project absent or changed')
    git = project['value']['git']
    require(git['commits'] == 2 and git['branch'] == 'feature/measurement'
            and git['uncommitted'] is dirty, 'Repository display changed')
    runtime = value['runtime']
    require(runtime['state'] == 'running' and runtime['process']['pid'] == pid
            and runtime['host'] == 'daemon', 'Serving host changed')
    require(len(value['agents']['items']) == 1
            and value['agents']['items'][0]['session']['state'] == 'never-launched',
            'Configured provider unexpectedly launched')
    if side == 'base':
        require('resources' not in runtime and 'resources_unavailable' not in runtime,
                'Base no longer reproduces the dropped resource fields')
    else:
        counters = runtime.get('resources')
        require(isinstance(counters, dict) and not runtime.get('resources_unavailable'),
                'Head dropped its fresh resource observation')
        require(counters['method'] == 'linux:getrusage(RUSAGE_SELF)+/proc/self/statm',
                'Host counter scope changed')
        for name in ('self_voluntary_switches', 'self_involuntary_switches',
                     'cpu_user_us', 'cpu_system_us', 'rss_bytes'):
            require(type(counters.get(name)) is int and counters[name] >= 0,
                    'Host counter absent, unreadable or not a native integer')
        require(counters['rss_bytes'] > 0, 'Live host RSS is falsely zero')
        at = datetime.fromisoformat(counters['sampled_at'].replace('Z', '+00:00'))
        require(datetime.fromtimestamp(sample['wall_started_ns'] / 1e9, timezone.utc) <= at
                <= datetime.fromtimestamp(sample['wall_ended_ns'] / 1e9, timezone.utc),
                'Resource timestamp lies outside its public call')


def identity(smoke, pid):
    rows = [row for row in smoke.commands.observer.observe(pid) if row['pid'] == pid]
    require(len(rows) == 1 and rows[0]['birth'] and rows[0]['command'],
            'Native host identity is unavailable')
    return {key: rows[0][key] for key in ('pid', 'birth', 'command')}


def close(smokes, record):
    for side, smoke in smokes.items():
        try:
            if smoke.initialization_attempted:
                stopped = smoke.call(['down'], 'down', project=False)
                record['cleanup'][side] = stopped
                require(stopped.get('complete') is True
                        and stopped.get('witness', {}).get('state') == 'witnessed'
                        and isinstance(stopped.get('stops'), list)
                        and all(row.get('complete') is True for row in stopped['stops']),
                        'Incomplete authenticated shutdown')
        except Exception as error:
            record['cleanup'][side] = dict(error=str(error))
            record['exit'] = 1
        try:
            remaining = smoke.commands.observer.observe()
            record['process_closure'][side] = remaining
            require(remaining == [], 'Owned process remains after shutdown')
        except Exception as error:
            record['process_closure'][side] = dict(error=str(error))
            record['exit'] = 1


def condition(output, images, provider, dirty):
    directory = output / (provider + '-' + ('dirty' if dirty else 'clean'))
    directory.mkdir()
    record = dict(provider=provider, dirty=dirty, exit=1, load_before=load(),
                  sources={side: image['source'] for side, image in images.items()},
                  pairs=[], identities={}, cleanup={}, process_closure={})
    smokes, pids = {}, {}
    try:
        for side in ('base', 'head'):
            smoke, pid = prepare(directory / side, images[side], provider, dirty, smokes, side)
            pids[side] = pid
            record['identities'][side] = identity(smoke, pid)
        for index in range(ROUNDS + 1):
            order = ('base', 'head') if index % 2 == 0 else ('head', 'base')
            pair = dict(index=index, kind='first-timed' if index == 0 else 'warm',
                        order=order, before=load(), samples={})
            for side in order:
                pair['samples'][side] = timed(smokes[side], ['status'])
            pair['after'] = load()
            record['pairs'].append(pair)
            if index % 25 == 0:
                save(directory / 'samples.json', record)
        for side, smoke in smokes.items():
            for pair in record['pairs']:
                validate(pair['samples'][side], smoke, pids[side], side, dirty)
            require(identity(smoke, pids[side]) == record['identities'][side],
                    'Native host instance changed during status timing')
        record['summary'] = summaries(record['pairs'])
        record['exit'] = 0
    except Exception as error:
        record['error'] = str(error)
    finally:
        close(smokes, record)
        record['load_after'] = load()
        save(directory / 'samples.json', record)
    return {key: value for key, value in record.items() if key != 'pairs'}


def main():
    output = Path(sys.argv[1]).resolve()
    images = json.loads((output / 'images.json').read_text())
    help_rows = {}
    for side, image in images.items():
        require(image['exit'] == 0 and hashlib.sha256(Path(image['image']).read_bytes()).hexdigest()
                == image['sha256'], 'Frozen image or build receipt changed')
        child = subprocess.run([image['image'], 'help', 'status'], capture_output=True,
                               text=True, timeout=30)
        help_rows[side] = dict(exit=child.returncode, stdout=child.stdout, stderr=child.stderr)
        save(output / 'public-status-help.json', help_rows)
        require(child.returncode == 0 and child.stdout.strip(), 'Public status help unavailable')
    observations = output / 'observations'
    observations.mkdir()
    result = dict(scope='Author paired Linux status observation; accepted encoder on both '
                        'images, uninstrumented; configured providers never launched; no '
                        'independent review, idle/session budget or Windows/macOS qualification',
                  method='spawn through pipe EOF and exact child join; 200 alternating warm '
                         'pairs per cohort; first separate; complete field checks and native '
                         'censuses outside timing; all tails retained',
                  images=images, cohorts=[], exit=1)
    for provider in ('claude', 'codex', 'acp'):
        for dirty in (False, True):
            row = condition(observations, images, provider, dirty)
            result['cohorts'].append(row)
            save(output / 'result.json', result)
            if any(value != [] for value in row['process_closure'].values()):
                raise RuntimeError('Process closure failed; later fixtures were not started')
    result['exit'] = 0 if len(result['cohorts']) == 6 and all(
        row['exit'] == 0 for row in result['cohorts']) else 1
    save(output / 'result.json', result)
    raise SystemExit(result['exit'])


if __name__ == '__main__':
    main()
