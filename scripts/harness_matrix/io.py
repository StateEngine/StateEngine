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

ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)')


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
    paths = ['../crates/se-harness-registry/src/registry.json', 'harness-matrix.py',
             'harness-matrix-report.py', 'ci/installation_account.py',
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


def raw_census():
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
    require(isinstance(values, list) and values and all(
        isinstance(row, dict) and type(row.get('pid')) is int and row['pid'] >= 0
        and type(row.get('parent')) is int and row['parent'] >= 0
        and isinstance(row.get('state'), str) and bool(row['state'])
        and row.get('owner_state') in ('not-required', 'foreign', 'current-user', 'unreadable', 'exited')
        and (row.get('birth') is None or isinstance(row['birth'], str))
        and (row.get('command') is None or isinstance(row['command'], str)) for row in values)
        and len({row['pid'] for row in values}) == len(values), 'Native process inventory is incomplete')
    return values


def census(baseline=frozenset()):
    rows = raw_census()
    if sys.platform == 'win32':
        require(not any(row.get('owner_state') in ('current-user', 'unreadable')
                        and (not row.get('birth') or (row.get('pid'), row['birth']) not in baseline)
                        for row in rows),
                'A current-user or unattributed native process has unreadable command identity')
    return rows


def birth_order(value):
    if sys.platform == 'linux':
        return int(value)
    if sys.platform == 'win32':
        return value  # Native UTC timestamps have the same fixed format.
    return time.strptime(value, '%a %b %d %H:%M:%S %Y')


class Observer:
    def __init__(self, home, output, baseline_rows=None):
        self.home = str(home)
        self.known = set()
        self.baseline = frozenset()
        self.baseline_evidence = None
        if sys.platform == 'win32':
            rows = raw_census() if baseline_rows is None else baseline_rows
            require(rows and all(type(row.get('pid')) is int and row['pid'] >= 0
                                 and row.get('state') and row.get('owner_state')
                                 and (row.get('birth') is None or isinstance(row['birth'], str)) for row in rows),
                    'Native process baseline is incomplete')
            self.baseline = frozenset((row['pid'], row['birth']) for row in rows if row.get('birth'))
            self.baseline_evidence = dict(
                complete=True, processes=[{key: row.get(key) for key in ('pid', 'birth', 'state', 'owner_state')}
                                          for row in rows])
            save(output / 'process-baseline.json', self.baseline_evidence)

    def observe(self, pid=None):
        rows = census(self.baseline)
        if pid is not None:
            row = next((row for row in rows if row['pid'] == pid), None)
            require(row and row['birth'] and row['command'], 'Owned process identity is unreadable')
            self.known.add((pid, row['birth']))
        while True:
            parents = {row['pid']: row['birth'] for row in rows
                       if (row['pid'], row['birth']) in self.known}
            added = {(row['pid'], row['birth']) for row in rows
                     if row['parent'] in parents and row['birth'] and row['command']
                     # An old orphan can retain a parent PID reused by this run.
                     and birth_order(row['birth']) >= birth_order(parents[row['parent']])}
            if added.issubset(self.known):
                break
            self.known.update(added)
        for row in rows:
            if ((row['pid'], row['birth']) in self.known
                    and not row['state'].startswith(('Z', 'X', 'x'))):
                require(row['command'] is not None, 'Known process command became unreadable')
        return [row for row in rows if not row['state'].startswith(('Z', 'X', 'x'))
                and ((row['pid'], row['birth']) in self.known
                     or self.home in (row['command'] or ''))]


class Commands:
    def __init__(self, output, home, repository, environment, terminal_prefix=(), baseline_rows=None):
        self.output, self.home, self.repository = output, home, repository
        self.environment = environment
        self.terminal_prefix = terminal_prefix
        self.sequence = 0
        self.first_failure = None
        self.observer = Observer(home, output, baseline_rows=baseline_rows)

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
                identity = next((row for row in census(self.observer.baseline) if row['pid'] == child.pid), None)
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
                    current = next((row for row in census(self.observer.baseline) if row['pid'] == child.pid), None)
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
        sizes = [prefix.with_suffix(suffix).stat().st_size for suffix in ('.stdout', '.stderr')]
        if self.first_failure is None and (code != 0 or failure is not None or sum(sizes) > 8 * 1024**2):
            self.first_failure = prefix.name
            save(self.output / 'first-failed-command.json', dict(
                label=label, argv=argv, exit=code, failure=failure, stderr_file=prefix.name + '.stderr'))
        if interrupted is not None:
            raise interrupted
        require(sum(sizes) <= 8 * 1024**2, label + ' exceeded the output bound')
        require(code == 0 and failure is None, label + ' failed; see retained command evidence')
        stdout = prefix.with_suffix('.stdout').read_bytes()
        return ANSI.sub('', stdout.decode('utf-8')).replace('\r', '')
