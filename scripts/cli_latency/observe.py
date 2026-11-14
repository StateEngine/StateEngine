"""Paired public agent-list cost after exact-size IPC encoding.

The source cut reuses a principal already enumerated by the same immutable
snapshot. These are author measurements, not independent correctness gates.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from support import ROUNDS, load, prepare, require, save, summaries, timed


def identity(smoke, pid):
    rows = [row for row in smoke.commands.observer.observe(pid) if row['pid'] == pid]
    require(len(rows) == 1 and rows[0]['birth'] and rows[0]['command'],
            'Native host identity is unavailable')
    return {key: rows[0][key] for key in ('pid', 'birth', 'command')}


def status(smoke, pid, dirty, count, label):
    value = smoke.call(['status'], label)
    project = value['project']
    require(project['state'] == 'present' and project['value']['id'] == smoke.project,
            'Selected project changed')
    git = project['value']['git']
    require(git['commits'] == 2 and git['branch'] == 'feature/measurement'
            and git['uncommitted'] is dirty, 'Repository display changed')
    require(value['runtime']['state'] == 'running'
            and value['runtime']['process']['pid'] == pid, 'Serving host changed')
    require(len(value['agents']['items']) == count
            and all(row['session']['state'] == 'never-launched'
                    and row['session']['session_id'] is None
                    for row in value['agents']['items']), 'Configured provider launched')
    return identity(smoke, pid)


def validate(sample, smoke, count, provider, saved_ids):
    require(sample['exit'] == 0 and sample['error'] is None, 'Public agent list failed')
    value = json.loads(sample['stdout'])
    require(value.get('schema') == 'se.agent-page/v1' and value.get('ok') is not False,
            'Wrong agent-list family')
    require(value['project']['id'] == smoke.project and value['consistency'] == 'live-keyset',
            'Agent-list scope changed')
    window = value['window']
    require(window['complete'] is True and window['omitted'] == dict(count=0, reason=None)
            and value['next'] is None, 'Finite page omitted saved agents')
    rows = value['items']
    require(len(rows) == count and len({row['id'] for row in rows}) == count,
            'Agent population changed or duplicated')
    require({row['name']: row['id'] for row in rows} == saved_ids,
            'Saved display names or exact agent IDs changed')
    require(sorted(saved_ids) == ['reader-' + str(index).zfill(2) for index in range(count)],
            'Fixture names are incomplete')
    for row in rows:
        require(row['provider'] == provider and row['unread'] == 0,
                'Provider or fresh unread count changed')
        require(row['session']['state'] == 'never-launched'
                and row['session']['session_id'] is None
                and row['conversation']['id'] is None and row['conversation']['state'] == 'none',
                'A saved identity invented a provider session')
        require(row['resume']['ready'] is False and row['resume']['mode'] == 'new'
                and row['resume']['argv'] and str(smoke.state) in row['resume']['argv'],
                'Saved resume guidance changed')
    return value


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


def condition(output, images, provider, dirty, count):
    directory = output / (provider + '-' + str(count) + '-' + ('dirty' if dirty else 'clean'))
    directory.mkdir()
    record = dict(provider=provider, count=count, dirty=dirty, exit=1, load_before=load(),
                  sources={side: image['source'] for side, image in images.items()},
                  pairs=[], identities={}, saved_ids={}, cleanup={}, process_closure={})
    smokes, pids = {}, {}
    try:
        for side in ('base', 'head'):
            smoke, pid = prepare(directory / side, images[side], provider, dirty, smokes, side, count)
            pids[side] = pid
            record['identities'][side] = status(smoke, pid, dirty, count, 'host-before')
            initial = smoke.call(['agent', 'list'], 'initial-list')
            saved_ids = {row['name']: row['id'] for row in initial['items']}
            require(saved_ids.get('reader-00') == smoke.agent, 'Initial agent identity changed')
            record['saved_ids'][side] = saved_ids
        for index in range(ROUNDS + 1):
            order = ('base', 'head') if index % 2 == 0 else ('head', 'base')
            pair = dict(index=index, kind='first-timed' if index == 0 else 'warm',
                        order=order, before=load(), samples={})
            for side in order:
                pair['samples'][side] = timed(smokes[side], ['agent', 'list'])
            pair['after'] = load()
            record['pairs'].append(pair)
            if index % 25 == 0:
                save(directory / 'samples.json', record)
        save(directory / 'samples.json', record)
        for side, smoke in smokes.items():
            for pair in record['pairs']:
                validate(pair['samples'][side], smoke, count, provider, record['saved_ids'][side])
            require(status(smoke, pids[side], dirty, count, 'host-after') == record['identities'][side],
                    'Native host identity changed during timing')
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
        child = subprocess.run([image['image'], 'help', 'agent', 'list'], capture_output=True,
                               text=True, timeout=30)
        help_rows[side] = dict(exit=child.returncode, stdout=child.stdout, stderr=child.stderr)
        save(output / 'public-help.json', help_rows)
        require(child.returncode == 0 and child.stdout.strip(), 'Public agent-list help unavailable')
    observations = output / 'observations'
    observations.mkdir()
    result = dict(scope='Author paired Linux public agent-list cost; accepted exact-size IPC encoder '
                        'on both images; configured providers never launched; no independent review '
                        'or Windows/macOS runtime qualification',
                  method='spawn through pipe EOF and exact child join; 200 alternating warm pairs '
                         'per cohort; first separate; one and ten saved agents per provider and '
                         'repository state; output validation and native censuses outside timer',
                  images=images, cohorts=[], exit=1)
    for provider in ('claude', 'codex', 'acp'):
        for dirty in (False, True):
            for count in (1, 10):
                row = condition(observations, images, provider, dirty, count)
                result['cohorts'].append(row)
                save(output / 'result.json', result)
                print(json.dumps(row), flush=True)
                if any(value != [] for value in row['process_closure'].values()):
                    raise RuntimeError('Process closure failed; later fixtures were not started')
    result['exit'] = 0 if len(result['cohorts']) == 12 and all(
        row['exit'] == 0 for row in result['cohorts']) else 1
    save(output / 'result.json', result)
    raise SystemExit(result['exit'])


if __name__ == '__main__':
    main()
