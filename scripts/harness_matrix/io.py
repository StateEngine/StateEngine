"""Private command evidence and native process observations for smoke runs."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')


class InterruptedRun(BaseException):
    """Stop starting work while allowing the active fixture to close."""


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def runner_files():
    scripts = Path(__file__).resolve().parents[1]
    paths = ['harness-matrix.py', 'harness-matrix-report.py', 'ci/installation_account.py',
             *['harness_matrix/' + name for name in
               ('flow.py', 'inputs.py', 'io.py', 'report.py', 'native_processes.ps1')]]
    return {name: digest(scripts / name) for name in paths}


def save(path, value):
    temporary = path.with_suffix(path.suffix + '.partial')
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def census():
    if sys.platform == 'linux':
        rows = []
        for path in Path('/proc').iterdir():
            if not path.name.isdecimal():
                continue
            try:
                fields = (path / 'stat').read_text().rsplit(') ', 1)[1].split()
                rows.append(dict(pid=int(path.name), parent=int(fields[1]), birth=fields[19],
                                 state=fields[0], command=(path / 'cmdline').read_bytes()
                                 .replace(b'\0', b' ').decode(errors='replace')))
            except (FileNotFoundError, ProcessLookupError):
                continue
            except PermissionError:
                if path.stat().st_uid == os.getuid():
                    raise RuntimeError('A current-user process is unreadable; closure is unknown')
        return rows
    if sys.platform == 'darwin':
        text = subprocess.check_output(['ps', '-Aww', '-o', 'pid=,ppid=,lstart=,stat=,command='],
                                       text=True, timeout=20)
        rows = []
        for line in text.splitlines():
            fields = line.split(None, 8)
            require(len(fields) == 9, 'Native process inventory is incomplete')
            rows.append(dict(pid=int(fields[0]), parent=int(fields[1]),
                             birth=' '.join(fields[2:7]), state=fields[7], command=fields[8]))
        return rows
    require(sys.platform == 'win32', 'No native process observer for this platform')
    script = Path(__file__).with_name('native_processes.ps1')
    text = subprocess.check_output(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script)],
                                   text=True, encoding='utf-8', timeout=30)
    values = json.loads(text)
    require(isinstance(values, list), 'Native process inventory is not a list')
    if not os.environ.get('GITHUB_ACTIONS'):
        # On a hosted runner the runner user owns infrastructure processes whose
        # command lines CIM leaves unreadable, so the machine-wide assertion
        # cannot hold there; the closure proof below still binds the harness's
        # own tree (known descendants, trial home in the command line).
        require(not any(row.get('owner_state') in ('current-user', 'unreadable') for row in values),
                'A current-user or unattributed native process has unreadable command identity')
    return values


class Observer:
    def __init__(self, home):
        self.home = str(home)
        self.known = set()

    def observe(self, pid=None):
        rows = census()
        if pid is not None:
            row = next((row for row in rows if row['pid'] == pid), None)
            require(row and row['birth'] and row['command'], 'Owned process identity is unreadable')
            self.known.add((pid, row['birth']))
        while True:
            parents = {row['pid'] for row in rows if (row['pid'], row['birth']) in self.known}
            added = {(row['pid'], row['birth']) for row in rows
                     if row['parent'] in parents and row['birth'] and row['command']}
            if added.issubset(self.known):
                break
            self.known.update(added)
        for row in rows:
            if (row['pid'], row['birth']) in self.known:
                require(row['command'] is not None, 'Known process command became unreadable')
        return [row for row in rows if not row['state'].startswith(('Z', 'X', 'x'))
                and ((row['pid'], row['birth']) in self.known
                     or self.home in (row['command'] or ''))]


class Commands:
    def __init__(self, output, home, repository, environment, terminal_prefix=()):
        self.output, self.home, self.repository = output, home, repository
        self.environment = environment
        self.terminal_prefix = terminal_prefix
        self.sequence = 0
        self.observer = Observer(home)

    def run(self, argv, label, terminal=False, timeout=180):
        argv = list(map(str, argv))
        actual = argv
        if terminal:
            if sys.platform == 'linux':
                actual = ['script', '-q', '-e', '-c', shlex.join(argv), '/dev/null']
            elif sys.platform == 'darwin':
                actual = ['script', '-q', '/dev/null', *argv]
            else:
                require(self.terminal_prefix, 'A native terminal driver is required on Windows')
                actual = [*self.terminal_prefix, *argv]
        self.sequence += 1
        prefix = self.output / f'{self.sequence:04d}-{label}'
        started = time.monotonic()
        code, failure = None, None
        with prefix.with_suffix('.stdout').open('xb') as out, prefix.with_suffix('.stderr').open('xb') as err:
            child = subprocess.Popen(actual, cwd=self.repository, env=self.environment,
                                     stdin=subprocess.DEVNULL, stdout=out, stderr=err)
            identity = None
            if child.poll() is None:
                identity = next((row for row in census() if row['pid'] == child.pid), None)
                if identity and identity['birth'] and identity['command']:
                    self.observer.known.add((child.pid, identity['birth']))
            interrupted = None
            next_observation = started
            try:
                while child.poll() is None:
                    now = time.monotonic()
                    if now >= next_observation:
                        self.observer.observe()
                        next_observation = now + .5
                    total = os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size
                    if total > 8 * 1024**2:
                        failure = 'command output bound exceeded'
                        break
                    if now - started >= timeout:
                        failure = 'command deadline expired'
                        break
                    time.sleep(.05)
            except BaseException as error:
                interrupted = error
                failure = 'command interrupted: ' + (str(error) or type(error).__name__)
            if failure:
                for action in (child.terminate, child.kill):
                    if child.poll() is not None:
                        break
                    current = next((row for row in census() if row['pid'] == child.pid), None)
                    require(identity and identity['command'] and current
                            and (current['birth'], current['command']) ==
                            (identity['birth'], identity['command']), 'Timed-out command identity changed')
                    action()
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        continue
            code = child.poll()
        save(prefix.with_suffix('.json'), dict(argv=argv, exit=code, failure=failure,
                                               elapsed_seconds=time.monotonic() - started))
        if interrupted is not None:
            raise interrupted
        sizes = [prefix.with_suffix(suffix).stat().st_size for suffix in ('.stdout', '.stderr')]
        require(sum(sizes) <= 8 * 1024**2, label + ' exceeded the output bound')
        require(code == 0 and failure is None, label + ' failed; see retained command evidence')
        stdout = prefix.with_suffix('.stdout').read_bytes()
        return ANSI.sub('', stdout.decode('utf-8')).replace('\r', '')
