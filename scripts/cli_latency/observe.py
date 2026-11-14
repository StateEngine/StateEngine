"""Interleaved public CLI observations; no provider launch or account credentials.

The first timed call is separate from 200 warm calls per image and condition.
All output validation and process censuses happen outside the measured interval.
Absolute hosted latency does not qualify a different machine's latency budget.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import random
import shutil
import statistics
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from harness_matrix.flow import Smoke
from harness_matrix.io import require, save

ROUNDS = 200


def load():
    return dict(unix=time.time(), load_average=list(os.getloadavg()),
                cpu_count=os.cpu_count(), io_pressure=Path('/proc/pressure/io').read_text())


def percentile(values, quantile):
    ordered = sorted(values)
    return ordered[math.ceil(quantile * len(ordered)) - 1]


def timed(smoke, action):
    arguments = {'status': ['status'], 'agents': ['agent', 'list'],
                 'inbox': ['msg', 'inbox', smoke.agent]}[action]
    argv = list(map(str, [smoke.binary, *arguments, '--home', smoke.state,
                          '--project', smoke.project, '--json']))
    started = time.perf_counter_ns()
    child = subprocess.Popen(argv, cwd=smoke.repository, env=smoke.commands.environment,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    error = None
    try:
        stdout, stderr = child.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        error = 'Public read exceeded 30 seconds'
        current = Path(f'/proc/{child.pid}/cmdline').read_bytes().split(b'\0')[:-1]
        require(current == [os.fsencode(arg) for arg in argv], 'Timed-out command identity differs')
        child.kill()
        stdout, stderr = child.communicate(timeout=5)
    elapsed = (time.perf_counter_ns() - started) / 1e6
    return dict(ms=elapsed, exit=child.returncode, error=error,
                stdout=stdout.decode('utf-8'), stderr=stderr.decode('utf-8'))


def validate(sample, smoke, action, count, bodies, dirty, host_pid):
    require(sample['exit'] == 0 and sample['error'] is None, 'Public read failed')
    value = json.loads(sample['stdout'])
    schema = {'status': 'se.status/v1', 'agents': 'se.agent-page/v1',
              'inbox': 'se.message-page/v1'}[action]
    require(value.get('schema') == schema and value.get('ok') is not False, 'Wrong response family')
    if action == 'status':
        project = value['project']
        require(project['state'] == 'present' and project['value']['id'] == smoke.project,
                'Project absent or changed')
        git = project['value']['git']
        require(git['commits'] == 2 and git['branch'] == 'feature/measurement'
                and git['uncommitted'] is dirty, 'Repository display changed')
        require(value['runtime']['state'] == 'running'
                and value['runtime']['process']['pid'] == host_pid, 'Serving host changed')
        require(len(value['agents']['items']) == 1
                and value['agents']['items'][0]['session']['state'] == 'never-launched',
                'Agent session changed')
        return
    window = value['window']
    require(window['complete'] is True and window['omitted']['count'] == 0
            and window['omitted']['reason'] is None and value['next'] is None,
            'Read returned an incomplete or unreadable page')
    rows = value['items']
    if action == 'agents':
        require(value['project']['id'] == smoke.project and len(rows) == count,
                'Agent population or project changed')
        require(sorted(row['name'] for row in rows)
                == ['reader-' + str(index).zfill(2) for index in range(count)],
                'Agent display names changed')
        require(all(row['session']['state'] == 'never-launched'
                    and row['session']['session_id'] is None for row in rows),
                'Agent session unexpectedly launched')
    else:
        require(len(rows) == len(bodies) and value['unread_total'] == len(bodies),
                'Unread count or inbox population changed')
        for row in rows:
            require(row['from']['id'] == smoke.owner and row['to']['id'] == smoke.agent
                    and row['body']['complete'] is True and row['unreadable'] is None
                    and row['disposition']['state'] == 'unread', 'Message facts changed')
        require(sorted(row['body']['text'] for row in rows) == sorted(bodies),
                'Message contents changed')


def prepare(directory, image, provider, count, mail_count, dirty, with_commits, smokes, side):
    directory.mkdir(mode=0o700)
    smoke = Smoke(directory, None, {'id': provider, 'driver': 'native'},
                  {'provider': provider}, {'PATH': os.environ['PATH']})
    smokes[side] = smoke
    smoke.state = smoke.home / 'stateengine-state'
    smoke.commands.environment['SE_HOME'] = str(smoke.state)
    smoke.binary.parent.mkdir(parents=True)
    shutil.copyfile(image['image'], smoke.binary)
    smoke.binary.chmod(0o500)

    def git(args, body=None):
        subprocess.run(['git', '-C', str(smoke.repository), '-c', 'user.name=Measurement',
                        '-c', 'user.email=measurement@example.invalid', *args],
                       input=body, env=smoke.commands.environment, capture_output=True, check=True)

    git(['init', '--initial-branch=feature/measurement'])
    if with_commits:
        for text in ('first\n', 'second\n'):
            (smoke.repository / 'user.txt').write_text(text)
            git(['add', '--', 'user.txt'])
            git(['commit', '-F', '-', '--', 'user.txt'], b'Preserve measurement work.\n')
    if dirty:
        (smoke.repository / 'user.txt').write_text('uncommitted user work\n')
        (smoke.repository / 'untracked.txt').write_text('untracked user work\n')
    selection = ['--harness', 'probe'] if provider == 'acp' else ['--provider', provider]
    if provider == 'acp':
        smoke.state.mkdir(mode=0o700)
        (smoke.state / 'config.toml').write_text(
            'version = 1\n[harnesses.probe]\ndriver = "acp-stdio"\n'
            'command = "/bin/true"\narguments = ["acp"]\n'
            '[harnesses.probe.permissions.default]\narguments = []\nmode = ""\n'
            '[harnesses.probe.permissions.default.environment]\n')
        (smoke.state / 'config.toml').chmod(0o600)
    smoke.initialization_attempted = True
    profile = smoke.call(['init', '--repo', smoke.repository, '--agent', 'reader-00', *selection],
                         'init', terminal=True, project=False)['profile']
    smoke.project, smoke.agent, smoke.owner = (profile[key] for key in ('project', 'agent_id', 'human_id'))
    started = smoke.call(['up'], 'up', project=False)
    smoke.commands.observer.observe(started['process']['pid'])
    for index in range(1, count):
        name = 'reader-' + str(index).zfill(2)
        added = smoke.call(['agent', 'add', name, *selection], 'add-' + name)
        require(added.get('agent', {}).get('name') == name, 'Agent creation readback differs')
    bodies = ['Latency sample ' + str(index).zfill(2) for index in range(mail_count)]
    for index, body in enumerate(bodies):
        sent = smoke.call(['msg', 'send', smoke.agent, body, '--no-wake'], 'send-' + str(index))
        require(sent.get('state') == 'committed' and sent.get('message_id'), 'Mail was not committed')
    return smoke, bodies, started['process']['pid']


def summaries(pairs):
    result = {}
    for side in ('base', 'head'):
        values = [row['samples'][side]['ms'] for row in pairs[1:]]
        result[side] = dict(first_ms=pairs[0]['samples'][side]['ms'], warm_count=len(values),
                            p50_ms=percentile(values, .5), p95_ms=percentile(values, .95),
                            max_ms=max(values), blocks=[])
        for start in range(0, len(values), 50):
            block = values[start:start + 50]
            result[side]['blocks'].append(dict(count=len(block), p95_ms=percentile(block, .95)))
    deltas = [row['samples']['base']['ms'] - row['samples']['head']['ms'] for row in pairs[1:]]
    rng = random.Random(0)
    bootstrap = [statistics.median(rng.choices(deltas, k=len(deltas))) for _ in range(2000)]
    result['comparison'] = dict(
        median_paired_saved_ms=statistics.median(deltas),
        median_paired_bootstrap_95_percent_interval_ms=[percentile(bootstrap, .025),
                                                      percentile(bootstrap, .975)],
        p95_saved_ms=result['base']['p95_ms'] - result['head']['p95_ms'])
    return result


def cohort(output, images, provider, name, action, count=1, mail_count=0, dirty=False):
    directory = output / (provider + '-' + name)
    directory.mkdir()
    record = dict(provider=provider, case=name, action=action, load_before=load(), exit=1,
                  sources={side: image['source'] for side, image in images.items()},
                  pairs=[], cleanup={}, process_closure={})
    smokes = {}
    facts = {}
    try:
        for side in ('base', 'head'):
            # Retain partially initialized homes for closure even if setup fails.
            smoke, bodies, pid = prepare(directory / side, images[side], provider,
                                         count, mail_count, dirty, action == 'status', smokes, side)
            facts[side] = (bodies, pid)
        for index in range(ROUNDS + 1):
            order = ('base', 'head') if index % 2 == 0 else ('head', 'base')
            pair = dict(index=index, kind='first-timed' if index == 0 else 'warm',
                        order=order, before=load(), samples={})
            for side in order:
                pair['samples'][side] = timed(smokes[side], action)
            pair['after'] = load()
            record['pairs'].append(pair)
        save(directory / 'samples.json', record)
        for side, smoke in smokes.items():
            bodies, pid = facts[side]
            for pair in record['pairs']:
                validate(pair['samples'][side], smoke, action, count, bodies, dirty, pid)
            current = smoke.call(['status'], 'host-after')
            require(current['runtime']['process']['pid'] == pid, 'Serving host changed during reads')
        record['summary'] = summaries(record['pairs'])
        record['exit'] = 0
    except Exception as error:
        record['error'] = str(error)
    finally:
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
        record['load_after'] = load()
        save(directory / 'samples.json', record)
    return {key: value for key, value in record.items() if key != 'pairs'}


def main():
    output = Path(sys.argv[1]).resolve()
    images = json.loads((output / 'images.json').read_text())
    for image in images.values():
        require(image['exit'] == 0 and hashlib.sha256(Path(image['image']).read_bytes()).hexdigest()
                == image['sha256'], 'Build receipt or image digest differs')
    observations = output / 'observations'
    observations.mkdir()
    result = dict(scope='Author Linux hosted measurements; no independent or cross-machine qualification',
                  method='spawn through pipe EOF and child exit; alternating pairs; first call separate; '
                         '200 warm calls; nearest-rank p95; validation and census outside timer',
                  images=images, cohorts=[], exit=1)
    cases = [('inbox-empty', 'inbox', 1, 0, False),
             ('inbox-populated', 'inbox', 1, 20, False)]
    for provider in ('claude', 'codex', 'acp'):
        for name, action, count, mail_count, dirty in cases:
            base = 'status-base' if action == 'status' else 'reads-base'
            head = {'status': 'status-head', 'agents': 'agents-head', 'inbox': 'inbox-head'}[action]
            row = cohort(observations, {side: images[key] for side, key in
                                       [('base', base), ('head', head)]},
                         provider, name, action, count, mail_count, dirty)
            result['cohorts'].append(row)
            save(output / 'result.json', result)
            print(json.dumps(row), flush=True)
    result['exit'] = 0 if all(row['exit'] == 0 for row in result['cohorts']) else 1
    save(output / 'result.json', result)
    raise SystemExit(result['exit'])


if __name__ == '__main__':
    main()
