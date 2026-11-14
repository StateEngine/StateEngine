"""Interleave four common CLI commands on exact frozen base/head images.

Six configured-provider/repository cohorts run four independent populations.
Providers are never launched; resume is explicitly owner context inspection.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from support import ROUNDS, load, prepare, require, save, summaries, timed
from workloads import ACTIONS, arguments, readback, setup, validate


def preflight(output, images):
    """Retain each binary's actual public help before using its command flags."""
    result = {}
    for side, image in images.items():
        require(image['exit'] == 0 and hashlib.sha256(Path(image['image']).read_bytes()).hexdigest()
                == image['sha256'], 'Build receipt or image digest differs')
        result[side] = {}
        for words in (['msg', 'list'], ['msg', 'send'], ['msg', 'read'], ['resume']):
            child = subprocess.run([image['image'], 'help', *words], capture_output=True,
                                   text=True, timeout=30)
            result[side][' '.join(words)] = dict(exit=child.returncode, stdout=child.stdout,
                                                 stderr=child.stderr)
            save(output / 'public-help.json', result)
            require(child.returncode == 0 and child.stdout.strip(), 'Command help unavailable')


def status(smoke, pid, dirty, label):
    value = smoke.call(['status'], label)
    project = value['project']
    require(project['state'] == 'present' and project['value']['id'] == smoke.project,
            'Project became absent or changed')
    git = project['value']['git']
    require(git['commits'] == 2 and git['branch'] == 'feature/measurement'
            and git['uncommitted'] is dirty, 'Repository display changed')
    require(value['runtime']['state'] == 'running'
            and value['runtime']['process']['pid'] == pid, 'Serving host changed')
    require(len(value['agents']['items']) == 1
            and value['agents']['items'][0]['session']['state'] == 'never-launched',
            'Configured provider unexpectedly launched')
    observed = smoke.commands.observer.observe(pid)
    identities = [item for item in observed if item['pid'] == pid]
    require(len(identities) == 1 and identities[0]['birth'] and identities[0]['command'],
            'Serving host native identity is unavailable')
    return {key: identities[0][key] for key in ('pid', 'birth', 'command')}


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
                        'Incomplete public shutdown')
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


def condition(output, images, provider, dirty, action):
    name = provider + '-' + ('dirty' if dirty else 'clean') + '-' + action
    directory = output / name
    directory.mkdir()
    record = dict(provider=provider, dirty=dirty, action=action, load_before=load(), exit=1,
                  sources={side: image['source'] for side, image in images.items()},
                  pairs=[], cleanup={}, process_closure={}, readback={})
    smokes, facts = {}, {}
    try:
        for side in ('base', 'head'):
            # Retain partially initialized homes for shutdown on setup failure.
            smoke, pid = prepare(directory / side, images[side], provider, dirty, smokes, side)
            state = setup(smoke, action)
            facts[side] = dict(state=state, pid=pid,
                               identity=status(smoke, pid, dirty, 'host-before'))
        record['fixtures'] = facts
        save(directory / 'samples.json', record)
        for index in range(ROUNDS + 1):
            order = ('base', 'head') if index % 2 == 0 else ('head', 'base')
            pair = dict(index=index, kind='first-timed' if index == 0 else 'warm',
                        order=order, before=load(), samples={})
            for side in order:
                argv = arguments(smokes[side], action, facts[side]['state'], index)
                pair['samples'][side] = timed(smokes[side], argv)
            pair['after'] = load()
            record['pairs'].append(pair)
            if index % 25 == 0:
                save(directory / 'samples.json', record)
        save(directory / 'samples.json', record)
        for side, smoke in smokes.items():
            fact = facts[side]
            values = [validate(pair['samples'][side], smoke, action, fact['state'], index)
                      for index, pair in enumerate(record['pairs'])]
            record['readback'][side] = readback(smoke, action, fact['state'], values)
            after = status(smoke, fact['pid'], dirty, 'host-after')
            require(after == fact['identity'], 'Native serving identity changed during timing')
        record['summary'] = summaries(record['pairs'])
        record['exit'] = 0
    except Exception as error:
        record['error'] = str(error)
    finally:
        close(smokes, record)
        record['load_after'] = load()
        save(directory / 'samples.json', record)
    return {key: value for key, value in record.items() if key not in ('pairs', 'fixtures')}


def main():
    output = Path(sys.argv[1]).resolve()
    images = json.loads((output / 'images.json').read_text())
    preflight(output, images)
    observations = output / 'observations'
    observations.mkdir()
    result = dict(scope='Author hosted Linux measurements; configured providers never launched; '
                        'resume-preview is owner inspection, not bound session resume or restart; '
                        'no independent, native Windows/macOS or cross-machine qualification',
                  method='spawn through pipe EOF and child exit; alternating image pairs; first '
                         'timed call separate; 200 warm calls per image; nearest-rank p95; '
                         'validation, write readback and process inventory outside timer',
                  images=images, cohorts=[], exit=1)
    for provider in ('claude', 'codex', 'acp'):
        for dirty in (False, True):
            for action in ACTIONS:
                observed = condition(observations, images, provider, dirty, action)
                result['cohorts'].append(observed)
                save(output / 'result.json', result)
                print(json.dumps(observed), flush=True)
                if any(value != [] for value in observed['process_closure'].values()):
                    raise RuntimeError('Process closure failed; later fixtures were not started')
    result['exit'] = 0 if len(result['cohorts']) == 24 and all(
        item['exit'] == 0 for item in result['cohorts']) else 1
    save(output / 'result.json', result)
    raise SystemExit(result['exit'])


if __name__ == '__main__':
    main()
