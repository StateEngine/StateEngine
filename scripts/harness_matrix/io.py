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


PROVIDER_HOME_FILES = {
    'HOME': ('.claude.json',),
    'USERPROFILE': ('.claude.json',),
    'APPDATA': (),
    'LOCALAPPDATA': (),
    'CODEX_HOME': ('config.toml', 'auth.json'),
    'CLAUDE_CONFIG_DIR': ('.claude.json', 'settings.json', '.credentials.json'),
}


def provider_home_environment(home, *, codex=None, claude=None):
    home = Path(home)
    return {
        'HOME': str(home),
        'USERPROFILE': str(home),
        'APPDATA': str(home / 'AppData/Roaming'),
        'LOCALAPPDATA': str(home / 'AppData/Local'),
        'CODEX_HOME': str(codex or home / '.codex'),
        'CLAUDE_CONFIG_DIR': str(claude or home / '.claude'),
    }


def prepare_provider_home(environment, home):
    verify_provider_home(environment, home)
    for key in PROVIDER_HOME_FILES:
        Path(environment[key]).mkdir(mode=0o700, parents=True, exist_ok=True)


def verify_provider_home(environment, home):
    root = Path(home).resolve(strict=True)
    require(root.is_dir(), 'The provider fixture must have a private account home')
    homes = {Path.home(), *(Path(os.environ[key]) for key in ('HOME', 'USERPROFILE')
                            if os.environ.get(key))}
    for home in homes:
        account = home.resolve()
        require(not account.is_relative_to(root), 'The fixture contains the account home')
        for name in ('.codex', '.claude'):
            default = (account / name).resolve()
            require(not root.is_relative_to(default) and not default.is_relative_to(root),
                    'The fixture overlaps an account provider directory')
        for name in ('AppData/Roaming', 'AppData/Local'):
            require(not (account / name).resolve().is_relative_to(root),
                    'The fixture contains the account application data')
    for key, names in PROVIDER_HOME_FILES.items():
        value = environment.get(key)
        path = Path(value) if value else None
        require(path is not None and path.is_absolute() and '..' not in path.parts,
                key + ' must be set to a private fixture path')
        resolved = path.resolve()
        inherited = os.environ.get(key)
        real = Path(inherited).resolve() if inherited else None
        require(resolved.is_relative_to(root),
                key + ' escapes the provider fixture')
        require(real is None or not real.is_relative_to(root),
                key + ' points into the real account')
        if real is not None and key in ('CODEX_HOME', 'CLAUDE_CONFIG_DIR'):
            require(not root.is_relative_to(real), key + ' uses the real configuration directory')
        for name in names:
            require((path / name).resolve().is_relative_to(root),
                    key + ' contains a settings file outside the provider fixture')


def run_provider_command(spawn, argv, environment, fixture, **options):
    verify_provider_home(environment, fixture)
    return spawn(argv, env=environment, **options)


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


def canonical_image(path):
    if not isinstance(path, str) or not path:
        return None
    candidate = Path(path)
    if not candidate.is_absolute():
        return None
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None
    return os.path.normcase(str(resolved))


def raw_census():
    if sys.platform == 'linux':
        rows = []
        for path in Path('/proc').iterdir():
            if not path.name.isdecimal():
                continue
            try:
                fields = (path / 'stat').read_text().rsplit(') ', 1)[1].split()
                try:
                    exe = os.readlink(path / 'exe')
                except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
                    exe = None
                rows.append(dict(pid=int(path.name), parent=int(fields[1]), birth=fields[19],
                                 state=fields[0], command=(path / 'cmdline').read_bytes()
                                 .replace(b'\0', b' ').decode(errors='replace'), exe=exe))
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
        and (row.get('command') is None or isinstance(row['command'], str))
        and (row.get('exe') is None or isinstance(row['exe'], str)) for row in values)
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
        self.last_observation = None
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

    def _record_observation(self, facts):
        self.last_observation = facts
        return facts

    def _verify_pid(self, rows, pid, expected_exe=None):
        expected = None if expected_exe is None else str(expected_exe)
        row = next((item for item in rows if item['pid'] == pid), None)
        if row is None or row['state'].startswith(('Z', 'X', 'x')):
            facts = self._record_observation(dict(
                state='absent', pid=pid, expected_exe=expected,
                observed_state=None if row is None else row.get('state'),
            ))
            raise RuntimeError('Observed process is absent: ' + json.dumps(facts, sort_keys=True))
        birth = row.get('birth')
        exe = row.get('exe')
        command = row.get('command')
        if not birth:
            facts = self._record_observation(dict(
                state='unreadable', reason='creation identity is unreadable',
                pid=pid, birth=birth, exe=exe, expected_exe=expected,
                owner_state=row.get('owner_state'),
            ))
            raise RuntimeError('Observed process identity is unreadable: ' + json.dumps(facts, sort_keys=True))
        previous = [known_birth for known_pid, known_birth in self.known if known_pid == pid]
        if previous and birth not in previous:
            facts = self._record_observation(dict(
                state='mismatched', reason='creation identity changed',
                pid=pid, birth=birth, previous_births=sorted(previous),
                exe=exe, expected_exe=expected,
            ))
            raise RuntimeError('Observed process identity changed: ' + json.dumps(facts, sort_keys=True))
        if expected_exe is not None and sys.platform in ('win32', 'linux'):
            if not exe:
                facts = self._record_observation(dict(
                    state='unreadable', reason='native executable path is unreadable',
                    pid=pid, birth=birth, exe=exe, expected_exe=expected,
                    owner_state=row.get('owner_state'),
                ))
                raise RuntimeError('Observed process image is unreadable: ' + json.dumps(facts, sort_keys=True))
            observed_image = canonical_image(exe)
            expected_image = canonical_image(expected)
            if observed_image is None or expected_image is None:
                facts = self._record_observation(dict(
                    state='unreadable', reason='native executable path could not be resolved',
                    pid=pid, birth=birth, exe=exe, expected_exe=expected,
                    owner_state=row.get('owner_state'),
                ))
                raise RuntimeError('Observed process image is unreadable: ' + json.dumps(facts, sort_keys=True))
            if observed_image != expected_image:
                facts = self._record_observation(dict(
                    state='mismatched', reason='native executable path differs from installed image',
                    pid=pid, birth=birth, exe=exe, expected_exe=expected,
                ))
                raise RuntimeError('Observed process image differs: ' + json.dumps(facts, sort_keys=True))
        elif expected_exe is None and not command:
            facts = self._record_observation(dict(
                state='unreadable', reason='command identity is unreadable',
                pid=pid, birth=birth, exe=exe, expected_exe=expected,
                owner_state=row.get('owner_state'),
            ))
            raise RuntimeError('Owned process identity is unreadable: ' + json.dumps(facts, sort_keys=True))
        self.known.add((pid, birth))
        self._record_observation(dict(
            state='matched', pid=pid, birth=birth, exe=exe, expected_exe=expected,
        ))

    def observe(self, pid=None, *, expected_exe=None):
        rows = census(self.baseline)
        if pid is not None:
            self._verify_pid(rows, pid, expected_exe=expected_exe)
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

    def evidence_prefix(self, label):
        self.sequence += 1
        return self.output / f'{self.sequence:04d}-{label}'

    def record_failure(self, prefix, label, argv, actual, code, failure):
        if self.first_failure is None:
            self.first_failure = prefix.name
            save(self.output / 'first-failed-command.json', dict(
                label=label, argv=argv, actual_argv=actual, exit=code, failure=failure,
                stderr_file=prefix.name + '.stderr'))

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
        prefix = self.evidence_prefix(label)
        started = time.monotonic()
        code, failure = None, None
        with prefix.with_suffix('.stdout').open('xb') as out, prefix.with_suffix('.stderr').open('xb') as err:
            child = run_provider_command(subprocess.Popen, actual, self.environment, self.home,
                                         cwd=self.repository, stdin=subprocess.DEVNULL,
                                         stdout=out, stderr=err)
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
        if code != 0 or failure is not None or sum(sizes) > 8 * 1024**2:
            self.record_failure(prefix, label, argv, actual, code, failure)
        if interrupted is not None:
            raise interrupted
        require(sum(sizes) <= 8 * 1024**2, label + ' exceeded the output bound')
        require(code == 0 and failure is None, label + ' failed; see retained command evidence')
        stdout = prefix.with_suffix('.stdout').read_bytes()
        return ANSI.sub('', stdout.decode('utf-8')).replace('\r', '')
