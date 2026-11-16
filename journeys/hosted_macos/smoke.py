"""Account-free public install/terminal/runtime/removal checks on native macOS."""
import json
import os
import fcntl
from pathlib import Path
import re
import subprocess
import sys
import time
from common import digest, require, save
from native import Observer, observe
from package import verify


class Smoke:
    def __init__(self, package, checksum, output, account_registration):
        require(sys.platform == 'darwin', 'This smoke adapter requires native macOS')
        require(Path(account_registration).is_file(), 'The pinned native installation-account guard is required')
        subprocess.run([sys.executable, '-B', str(account_registration), 'check'], check=True, timeout=20)
        self.output = Path(output).resolve()
        self.output.mkdir(mode=0o700)
        self.home = self.output / 'fixture-home'
        self.home.mkdir(mode=0o700)
        (self.home / 'tmp').mkdir()
        self.state, self.repo = self.home / 'state', self.home / 'repository'
        self.repo.mkdir()
        self.bundle, metadata = verify(package, checksum, self.output / 'extracted')
        self.binary = self.home / '.local/bin/se'
        self.project = self.host = None
        self.saved_profile = None
        self.attempted_install = self.attempted_init = False
        self.calls, self.probes, self.errors = [], [], []
        self.environment = dict(HOME=str(self.home), SHELL='/bin/zsh', PATH='/usr/bin:/bin:/usr/sbin:/sbin',
                                USER=os.environ.get('USER', ''), LOGNAME=os.environ.get('LOGNAME', ''),
                                TMPDIR=str(self.home / 'tmp'), LANG='en_US.UTF-8', LC_ALL='en_US.UTF-8',
                                SE_HOME=str(self.state), GIT_CONFIG_GLOBAL=str(self.home / '.gitconfig'), GIT_CONFIG_NOSYSTEM='1')
        self.observer = Observer(self.home)
        self.record = dict(schema='se.macos-account-free/v1', result='running', source=metadata['nightly'],
                           package_metadata_sha256=checksum, archive_sha256=metadata['archive_sha256'],
                           probes=self.probes, calls=self.calls, cleanup=None,
                           qualification='Account-free native smoke only; real-provider journeys and desktop windows unmeasured')
        self.profile = {name: b'# preserved user shell configuration\n' for name in ('.zprofile', '.profile')}
        for name, content in self.profile.items():
            (self.home / name).write_bytes(content)
        self.flush()

    def flush(self):
        save(self.output / 'smoke.json', self.record)

    def command(self, argv, label, json_output=False):
        started = time.monotonic()
        row = dict(label=label, argv=[str(v) for v in argv], state='running')
        self.calls.append(row)
        self.flush()
        stdout = self.output / f'{len(self.calls):03}-{label}.stdout'
        stderr = self.output / f'{len(self.calls):03}-{label}.stderr'
        try:
            with stdout.open('xb') as out, stderr.open('xb') as err:
                value = subprocess.run(argv, cwd=self.repo, env=self.environment,
                                       stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=90)
            row.update(exit=value.returncode, seconds=time.monotonic() - started)
            require(stdout.stat().st_size + stderr.stat().st_size <= 2 * 1024**2, 'Command evidence exceeds finite limit; raw files retained')
            require(value.returncode == 0, f'{label} failed: exit {value.returncode}; retained stdout/stderr')
            row['state'] = 'complete'
            text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', stdout.read_text()).replace('\r', '')
            return json.loads(text) if json_output else text
        except Exception as error:
            row.update(state='failed', reason=str(error), seconds=time.monotonic() - started)
            raise
        finally:
            self.flush()

    def call(self, args, label, project=True, terminal=False):
        argv = [self.binary, *args, '--home', self.state, '--json', '--no-color']
        if project and self.project:
            argv += ['--project', self.project]
        if terminal:
            argv = ['/usr/bin/script', '-q', '/dev/null', *argv]
        return self.command(argv, label, True)

    def shell(self, label):
        text = self.command(['/bin/zsh', '-lc', 'printf "HOME=%s\\nPATH=%s\\nSE=%s\\n" "$HOME" "$PATH" "$(command -v se || :)"'], label)
        values = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
        require(values.get('HOME') == str(self.home), 'Fresh login shell replaced the private home')
        require('PATH' in values and 'SE' in values, 'Fresh terminal discovery is unreadable')
        return values

    def probe(self, name, action):
        row = dict(name=name, result='running')
        self.probes.append(row)
        self.flush()
        try:
            row['observation'] = action()
            row['result'] = 'PASS'
        except Exception as error:
            row.update(result='FAIL', reason=str(error))
            raise
        finally:
            self.flush()

    def install(self):
        before = self.shell('terminal-before')
        require(before['SE'] == '', 'Runner already discovers an installation; a clean runner is required')
        self.attempted_install = True
        self.command(['/bin/sh', self.bundle / 'install.sh'], 'install')
        after = self.shell('terminal-installed')
        require(Path(after['SE']).resolve(strict=True) == self.binary.resolve(strict=True), 'Fresh zsh does not discover the installed binary')
        require(digest(self.binary) == digest(self.bundle / 'se'), 'Installed binary differs from the exact native package')
        build = json.loads((self.bundle / 'build.json').read_text())
        version = self.command([self.binary, '--version'], 'version').strip()
        require(version == build['version_stdout'], 'Installed version differs from the native build')
        return dict(before=before, after=after, binary_sha256=digest(self.binary), version=version)

    def initialize(self):
        git = lambda args: self.command(['/usr/bin/git', '-c', 'user.name=Journey', '-c', 'user.email=journey@example.invalid', *args], 'git')
        git(['init', '--initial-branch=feature/user-work', self.repo])
        (self.repo / 'user.txt').write_text('Preserve committed work.\n')
        git(['add', '--', 'user.txt']); git(['commit', '-m', 'Preserve user work.'])
        (self.repo / 'untracked.txt').write_text('Preserve untracked work.\n')
        self.user_files = self.repository_files()
        self.git_head = git(['rev-parse', 'HEAD']).strip()
        self.attempted_init = True
        init = self.call(['init', '--repo', self.repo, '--name', 'native-smoke', '--agent', 'main', '--provider', 'codex'], 'init', False)
        self.saved_profile = init['profile']
        self.project = init['profile']['project']
        require(init['outcome'] == 'created' and init['launch'] is None, 'Init did not create an unlaunched saved setup')
        status = self.call(['status'], 'initialized-status')
        require(status['runtime']['state'] == 'stopped' and status['runtime']['process'] is None, 'Init started a runtime unexpectedly')
        require(status['project']['state'] == 'present' and status['project']['value']['id'] == self.project, 'Independent project identity differs')
        require(git(['rev-parse', 'HEAD']).strip() == self.git_head, 'Repository adoption changed Git history')
        after = self.repository_files()
        require(all(after.get(name) == checksum for name, checksum in self.user_files.items()), 'Init changed user work or Git state')
        require(isinstance(self.project, str) and self.project and '/' not in self.project and '\\' not in self.project, 'Project identity is not a safe marker selector')
        marker = '.git/stateengine/project-' + self.project
        require(set(after) - set(self.user_files) == {marker}, 'Init added files beyond the owned Git identity marker')
        identity = json.loads((self.repo / marker).read_text())
        require(identity['v'] == 1 and identity['project'] == self.project and identity['head'] == self.git_head
                and identity['branch'] == 'feature/user-work', 'Repository identity differs from existing user work')
        return dict(init=init, status=status, native_session_adoption='NOT RUN: real provider account required')

    def repository_files(self):
        files = {}
        for path in self.repo.rglob('*'):
            require(not path.is_symlink(), 'Repository preservation cannot follow a symbolic link')
            if path.is_file():
                files[path.relative_to(self.repo).as_posix()] = digest(path)
            else:
                require(path.is_dir(), 'Repository contains an unreadable or special object')
        return files

    def runtime(self):
        self.call(['up'], 'up', False)
        status = self.call(['status'], 'running-status', terminal=True)
        runtime = status['runtime']
        require(runtime['state'] == 'running' and runtime['host'] == 'daemon', 'Public runtime is not the standalone daemon')
        pid = runtime['process']['pid']
        self.observer.scan(pid)
        self.host = observe(pid)
        require(self.host['state'] == 'running' and self.host['uid'] == os.getuid()
                and Path(self.host['image']).resolve() == self.binary.resolve(), 'Outside native host identity or image differs')
        require(Path(runtime['process']['exe']).resolve() == self.binary.resolve(), 'Public runtime executable differs')
        page = self.call(['agent', 'list'], 'agent-list')
        require(page['window']['complete'] is True and page['next'] is None and page['window']['omitted']['count'] == 0, 'Agent page is incomplete')
        require(len(page['items']) == 1 and page['items'][0]['provider'] == 'codex'
                and page['items'][0]['session']['state'] == 'never-launched'
                and page['items'][0]['session']['process'] is None, 'Account-free run launched a provider or lost the saved agent')
        agent = self.call(['agent', 'show', page['items'][0]['id']], 'agent-show')
        require(agent['agent']['state'] == 'present' and agent['agent']['value']['id'] == page['items'][0]['id'], 'Agent show/list disagree')
        self.call(['down'], 'down', False)
        closed = self.observer.closed()
        same = observe(pid)
        require(same['state'] in ('absent', 'exited-awaiting-reap') or
                (same['state'] in ('running', 'stopped') and same['birth'] != self.host['birth']),
                'Original host remains live or its shutdown is unreadable')
        return dict(public=status, native=self.host, closure=closed, after=same)

    def removed_resources(self):
        require(self.saved_profile is not None, 'Initialized resource inventory is unavailable')
        root = Path(self.saved_profile['registry_root']).resolve()
        require(root.is_relative_to(self.home), 'Resource inventory escapes the private home')
        paths = []
        for name in ('endpoint.json', 'run/endpoint.json'):
            path = root / name
            require(not os.path.lexists(path), 'Runtime endpoint remains after removal: ' + name)
            paths.append(dict(path=str(path), state='absent'))
        locks = []
        for name in ('runtime.lock', 'run/runtime.lock'):
            path = root / name
            if not os.path.lexists(path):
                locks.append(dict(path=str(path), state='absent'))
                continue
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locks.append(dict(path=str(path), state='free'))
            finally:
                os.close(descriptor)
        return dict(endpoints=paths, runtime_locks=locks)

    def cleanup(self):
        errors, resources = [], None
        if self.binary.exists():
            for args, label in [(['down'], 'cleanup-down'), (['remove', '--all'], 'remove')]:
                if not self.attempted_init:
                    break
                try:
                    value = self.call(args, label, False)
                    if label == 'remove':
                        require(value['outcome'] == 'removed' and value['machine_credential']['state'] == 'removed'
                                and value['machine_credential']['witness']['state'] == 'witnessed', 'Public removal credential witness incomplete')
                        require(all(not row['remaining'] and row['outcome'] == 'removed' for row in value['projects']), 'Removal retains project obligations')
                        resources = self.removed_resources()
                except Exception as error:
                    errors.append(str(error))
            try:
                value = self.call(['uninstall'], 'uninstall', False)
                require(value['schema'] == 'se.uninstall/v1' and value['complete'] is True
                        and not value.get('issues'), 'Public uninstall did not complete all obligations')
                require(not self.binary.exists(), 'Public command remains after uninstall')
                require(self.shell('terminal-removed')['SE'] == '', 'Fresh zsh still discovers se after uninstall')
                require(all((self.home / name).read_bytes() == content for name, content in self.profile.items()), 'Uninstall changed original shell configuration')
                if hasattr(self, 'user_files'):
                    require(self.repository_files() == self.user_files, 'Removal changed user work, Git state or repository inventory')
            except Exception as error:
                errors.append(str(error))
        elif self.attempted_install:
            errors.append('Installation exposure absent after an attempted install; partial installation requires inspection')
        try:
            closure = self.observer.closed()
        except Exception as error:
            errors.append(str(error)); closure = dict(state='unreadable', reason=str(error))
        self.record['cleanup'] = dict(result='FAIL' if errors else 'PASS', errors=errors, process_closure=closure,
                                      resources=resources, home='Private fixture retained on disposable runner; excluded from uploads', native_home=str(self.home))
        self.errors.extend(errors)
        self.flush()

    def run(self):
        try:
            self.probe('Install and fresh terminal', self.install)
            self.probe('Initialize and preserve an existing repository', self.initialize)
            self.probe('Native runtime identity, PTY status and shutdown', self.runtime)
        except Exception as error:
            self.errors.append(str(error))
        finally:
            self.cleanup()
            self.record.update(result='FAIL' if self.errors else 'PASS', errors=self.errors)
            self.flush()
        return self.record
