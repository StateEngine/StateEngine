"""Private startup fixtures and off-timer correctness/closure observations."""
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from harness_matrix.flow import Smoke
from harness_matrix.io import require, save
from native import NativeObserver
from public_ready import PublicReady

ROUNDS = int(os.environ.get('LIST_OBSERVE_ROUNDS', '200'))
require(1 <= ROUNDS <= 200, 'Observation count is outside its bound')


class Fixture(Smoke):
    """Public commands with evidence outside the timed interval; no provider runs."""
    startup = None

    def call(self, args, label, terminal=False, project=True):
        require(not terminal, 'Explicit initialization must not require a terminal')
        argv = list(map(str, [self.binary, *args, '--home', self.state, '--json', '--no-color']))
        if project and self.project:
            argv += ['--project', self.project]
        result = execute(self, argv, 90)
        self.commands.sequence += 1
        prefix = self.output / f'{self.commands.sequence:04d}-{label}'
        prefix.with_suffix('.stdout').write_text(result['stdout'], encoding='utf-8')
        prefix.with_suffix('.stderr').write_text(result['stderr'], encoding='utf-8')
        save(prefix.with_suffix('.json'), {key: value for key, value in result.items()
                                         if key not in ('stdout', 'stderr')})
        require(result['exit'] == 0 and result['error'] is None,
                label + ' failed; see retained command evidence')
        return json.loads(result['stdout'])


def load():
    return dict(unix=time.time(), platform=sys.platform,
                load_average=list(os.getloadavg()) if hasattr(os, 'getloadavg') else None,
                cpu_count=os.cpu_count(), io_pressure=Path('/proc/pressure/io').read_text()
                if sys.platform == 'linux' else None,
                timer=dict(implementation=time.get_clock_info('perf_counter').implementation,
                           resolution_seconds=time.get_clock_info('perf_counter').resolution))


def execute(smoke, argv, timeout):
    started = time.perf_counter_ns()
    child = subprocess.Popen(argv, cwd=smoke.repository, env=smoke.commands.environment,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    error = None
    try:
        stdout, stderr = child.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        error = f'Public command exceeded {timeout} seconds'
        current = next((row for row in smoke.commands.observer.observe(child.pid)
                        if row['pid'] == child.pid), None)
        require(current and current['birth'] and current['command']
                and str(smoke.binary) in current['command']
                and str(smoke.state) in current['command'], 'Timed-out command identity differs')
        child.kill()
        stdout, stderr = child.communicate(timeout=5)
    elapsed = (time.perf_counter_ns() - started) / 1e6
    return dict(ms=elapsed, pid=child.pid, exit=child.returncode, error=error, argv=argv,
                stdout=stdout.decode('utf-8'), stderr=stderr.decode('utf-8'))


def timed(smoke, arguments):
    argv = list(map(str, [smoke.binary, *arguments, '--home', smoke.state,
                          '--project', smoke.project, '--json']))
    return execute(smoke, argv, 30)

def prepare(directory, image, provider, dirty, smokes, side, count):
    directory.mkdir(mode=0o700)
    smoke = Fixture(directory, None, {'id': provider, 'driver': 'native'},
                    {'provider': provider}, dict(os.environ))
    smokes[side] = smoke
    smoke.commands.observer = NativeObserver(smoke.home, directory)
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
            'command = ' + json.dumps(sys.executable) + '\narguments = ["-c", "pass"]\n'
            '[harnesses.probe.permissions.default]\narguments = []\nmode = ""\n'
            '[harnesses.probe.permissions.default.environment]\n')
        (smoke.state / 'config.toml').chmod(0o600)
    smoke.initialization_attempted = True
    profile = smoke.call(['--key', str(uuid.uuid4()), 'init', '--repo', smoke.repository,
                          '--agent', 'reader-00', *selection], 'init', project=False)['profile']
    smoke.project, smoke.agent, smoke.owner = (profile[key] for key in ('project', 'agent_id', 'human_id'))
    smoke.startup = PublicReady(smoke, [str(smoke.binary), '--home', str(smoke.state),
                                       '--json', 'up'], smoke.commands.environment)
    started = json.loads(smoke.startup.wait()['stdout'])
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
                if smoke.startup is not None:
                    smoke.startup.join()
        except Exception as error:
            record['cleanup'][side] = dict(error=str(error))
            record['exit'] = 1
        try:
            if sys.platform == 'linux':
                # Detached runtime children belong to this subreaper. Join
                # retained exact children before requiring live command lines.
                joined = []
                deadline = time.monotonic() + 10
                for pid, birth in smoke.commands.observer.known:
                    while time.monotonic() < deadline:
                        try:
                            fields = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
                            if fields[19] != birth:
                                break
                            if os.waitpid(pid, os.WNOHANG)[0] == pid:
                                joined.append(dict(pid=pid, birth=birth))
                                break
                        except (FileNotFoundError, ProcessLookupError, ChildProcessError):
                            break
                        time.sleep(.02)
                record.setdefault('joined_runtime_children', {})[side] = joined
            remaining = smoke.commands.observer.observe()
            record['process_closure'][side] = remaining
            require(remaining == [], 'Owned process remains after shutdown')
        except Exception as error:
            record['process_closure'][side] = dict(error=str(error))
            record['exit'] = 1
