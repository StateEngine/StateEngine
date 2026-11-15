"""Private startup fixtures and off-timer correctness/closure observations."""
import json
import hashlib
import os
from pathlib import Path
import shutil
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


def timed(smoke, arguments):
    argv = list(map(str, [smoke.binary, *arguments, '--home', smoke.state,
                          '--project', smoke.project, '--json']))
    started = time.perf_counter_ns()
    child = subprocess.Popen(argv, cwd=smoke.repository, env=smoke.commands.environment,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    error = None
    try:
        stdout, stderr = child.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        error = 'Public command exceeded 30 seconds'
        current = Path(f'/proc/{child.pid}/cmdline').read_bytes().split(b'\0')[:-1]
        require(current == [os.fsencode(arg) for arg in argv], 'Timed-out command identity differs')
        child.kill()
        stdout, stderr = child.communicate(timeout=5)
    elapsed = (time.perf_counter_ns() - started) / 1e6
    return dict(ms=elapsed, exit=child.returncode, error=error, argv=argv,
                stdout=stdout.decode('utf-8'), stderr=stderr.decode('utf-8'))

def prepare(directory, image, provider, dirty, smokes, side, count):
    directory.mkdir(mode=0o700)
    smoke = Smoke(directory, None, {'id': provider, 'driver': 'native'},
                  {'provider': provider}, {'PATH': os.environ['PATH']})
    smokes[side] = smoke
    smoke.state = smoke.home / 'stateengine-state'
    smoke.commands.environment['SE_HOME'] = str(smoke.state)
    smoke.binary.parent.mkdir(parents=True)
    shutil.copyfile(image['image'], smoke.binary)
    smoke.binary.chmod(0o500)
    with smoke.binary.open('rb') as stream:
        require(hashlib.file_digest(stream, 'sha256').hexdigest() == image['sha256'],
                'Private image differs from the verified extracted package')

    def git(args, body=None):
        subprocess.run(['git', '-C', str(smoke.repository), '-c', 'user.name=Measurement',
                        '-c', 'user.email=measurement@example.invalid', *args],
                       input=body, env=smoke.commands.environment, capture_output=True, check=True)

    git(['init', '--initial-branch=feature/measurement'])
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
    return smoke, started['process']['pid']


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
