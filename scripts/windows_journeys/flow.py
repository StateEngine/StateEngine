"""The same five public journeys for every admitted native harness row."""
import json
from pathlib import Path
import sys
import time
import uuid

from harness_matrix.flow import Smoke
from harness_matrix.io import digest, require
from .credentials import Credentials, Prerequisite, protect
from .usage import snapshot, difference
from .release import download
from .files import plain_files
from .foreground import DETACHED_HOST_COVERAGE, ForegroundRuntime

JOURNEYS = ('J1', 'J2', 'J3', 'J4', 'J5')


def repository_bytes(root):
    rows = {}
    for path, _ in plain_files(root):
        rows[str(path.relative_to(root))] = digest(path)
    return rows


class Journeys(Smoke):
    def __init__(self, *args, release, foreground_runtime=False, **kwargs):
        super().__init__(*args, **kwargs)
        protect(self.home)
        self.credentials = Credentials(self.settings['credential_seed'], self.settings['provider'])
        self.commands.environment['CODEX_HOME'] = str(self.home / '.codex')
        self.commands.environment['GIT_OPTIONAL_LOCKS'] = '0'
        if sys.platform == 'win32':
            self.commands.terminal_prefix = [sys.executable, '-B', str(Path(__file__).with_name('terminal.py'))]
        self.record.update(qualification='five user journeys; performance and clean-image provenance are separate',
                           release=release, phases={key: dict(result='NOT RUN') for key in JOURNEYS},
                           credential_closure=None)
        self.foreground = ForegroundRuntime(self.commands, self.binary, self.state) if foreground_runtime else None
        if self.foreground:
            self.record.update(detached_host_start=DETACHED_HOST_COVERAGE,
                               foreground_hosts=self.foreground.receipts)
        self.record['credential_expiry'] = dict(state='unknown' if self.credentials.expires is None
                                               else 'token-declared', value=self.credentials.expires)
        self.saved_events, self.user_work = {}, {}
        self.initial = None
        self.removed = False
        self.save()

    def start_runtime(self, phase):
        if self.foreground:
            self.foreground.start(phase)
        else:
            super().start_runtime()

    def observe_runtime_exit(self):
        if self.foreground:
            self.foreground.observe_exit()

    def launch(self, args, label, *, reopen=None):
        expected = self.settings.get('launch_image')
        if reopen is None:
            launched = self.call(args, label, terminal=True)
        else:
            argv = [*reopen, *args]
            if expected is None:
                self.commands.run(argv, label, terminal=True)
                return
            output = self.commands.run([*argv, '--json', '--no-color'], label, terminal=True)
            launched = self.decode_reply(output, True)
        process = launched['process']
        if reopen is None:
            self.commands.observer.observe(process['pid'])
        if expected is not None:
            process_image = Path(process['exe'])
            require(process_image.is_absolute(), 'Launched provider image must have an absolute path')
            observed = process_image.resolve(strict=True)
            require(observed == Path(expected).resolve(strict=True),
                    'Provider launched a different native image than the pinned version probe')
            observed_digest = digest(observed)
            require(any(Path(row['path']).resolve() == observed and row['sha256'] == observed_digest
                        for row in self.settings['images']), 'Launched provider image does not match its pin')
        return launched

    def phase(self, name, operation):
        before, usage_error = None, None
        try:
            before = snapshot(self.home, self.settings['provider'])
        except Exception as error:
            usage_error = str(error)
        self.credentials.ready()
        try:
            return super().phase(name, operation)
        except BaseException as error:
            if self.credentials.expires is not None and time.time() >= self.credentials.expires:
                self.record['phases'][name].update(result='INCOMPLETE', prerequisite='EXPIRED')
                raise Prerequisite('EXPIRED', 'Access token expired during the journey; observed error: '
                                   + str(error)) from error
            raise
        finally:
            try:
                require(before is not None, 'Initial usage observation is unavailable: ' + str(usage_error))
                after = snapshot(self.home, self.settings['provider'])
                self.record['phases'][name]['tokens'] = difference(before, after, name in ('J2', 'J3', 'J4'))
            except Exception as error:
                self.record['phases'][name]['tokens'] = dict(state='unavailable', reason=str(error))
            self.save()

    def user_path(self):
        value = self.commands.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                                  "ConvertTo-Json -InputObject ([Environment]::GetEnvironmentVariable('Path','User'))"],
                                 'user-path')
        return json.loads(value)

    def install(self):
        self.commands.run([sys.executable, '-B', Path(__file__).resolve().parents[1] / 'ci/installation_account.py',
                           'check'], 'installation-account')
        self.package, downloaded = download(self.record['release'], self.output)
        self.record['release'] = downloaded
        self.original_path = self.user_path()
        self.commands.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File',
                           self.package / 'install.ps1'], 'install')
        manifest = json.loads((self.package / 'manifest.json').read_text())
        build = json.loads((self.package / 'build.json').read_text())
        require(digest(self.binary) == manifest['files']['se.exe']['sha256'] == build['files']['se.exe'],
                'Installed executable differs from the downloaded release')
        code = ("$ErrorActionPreference='Stop';$env:Path=[Environment]::GetEnvironmentVariable('Path','Machine')"
                "+';'+[Environment]::GetEnvironmentVariable('Path','User');"
                "$image=(Get-Command se -CommandType Application -ErrorAction Stop).Source;"
                "$version=(& $image --version);if($LASTEXITCODE){exit $LASTEXITCODE};"
                "@{image=$image;version=$version}|ConvertTo-Json -Compress")
        fresh = json.loads(self.commands.run(['powershell.exe', '-NoProfile', '-Command', code],
                                             'fresh-terminal-discovery', terminal=True))
        require(Path(fresh['image']).resolve() == self.binary.resolve()
                and fresh['version'].strip() == build['version_stdout'],
                'Fresh terminal did not discover the installed release version')
        return dict(download=self.record['release'], installed_sha256=digest(self.binary), discovery=fresh)

    def git(self, *args, label='git'):
        return self.commands.run(['git', '-C', self.repository, *args], label)

    def preserve_work(self):
        after = repository_bytes(self.repository)
        require(all(after.get(name) == value for name, value in self.user_work.items()),
                'User files or Git history changed')

    def remember(self, result, filename):
        self.user_work[filename] = digest(self.repository / filename)
        for event in result['capture']['events']:
            value = self.call(['history', '--event', event], 'save-history')
            require(value.get('event_id') == event and value.get('kind') == 'session.turn',
                    'Canonical conversation event is unreadable')
            self.saved_events[event] = value['payload']

    def adopt_and_work(self):
        self.git('init')
        (self.repository / 'committed.txt').write_text('original committed work\n')
        self.git('add', '--', 'committed.txt')
        # Fixture authorship is synthetic, local to this new repository.
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                 'commit', '-m', 'Initial fixture work.', '--', 'committed.txt')
        (self.repository / 'committed.txt').write_text('unstaged user edit\n')
        (self.repository / 'staged.txt').write_text('staged user work\n')
        self.git('add', '--', 'staged.txt')
        (self.repository / 'untracked.txt').write_text('untracked user work\n')
        self.user_work = repository_bytes(self.repository)
        config = Path(self.settings['configuration']['path'])
        require(digest(config) == self.settings['configuration']['sha256'], 'Native configuration changed')
        self.state.mkdir(exist_ok=True)
        (self.state / 'config.toml').write_bytes(config.read_bytes())
        # Supply only the provisioned credential for this private home.
        self.commands.environment.update(self.credentials.environment())
        version = self.commands.run(self.settings['version_command'], 'native-provider-version')
        require(version.strip() == self.settings['version_stdout'], 'Native provider version differs')
        self.initialization_attempted = True
        initialized = self.call(['init', '--repo', self.repository, '--agent', 'main',
                                 '--provider', self.settings['provider']], 'adopt', terminal=True, project=False)
        self.project, self.agent, self.owner = (initialized['profile'][key]
                                               for key in ('project', 'agent_id', 'human_id'))
        self.preserve_work()
        self.credentials.install(self.home)
        self.start_runtime('J2')
        self.secret, work = str(uuid.uuid4()), str(uuid.uuid4())
        task = f'Remember {self.secret}. Write {work} plus newline to work.txt. Reply {work}.'
        launched = self.launch(['launch', self.agent, '--detach', '--task', task], 'real-work')
        require(launched['permission_profile'] == self.settings['permission_profile'],
                'Actual native permission profile differs')
        self.initial = dict(conversation=launched['conversation_id'], session=launched['session_id'])
        observed = self.file_turn(work, 'work.txt', (work + '\n').encode())
        self.remember(observed, 'work.txt')
        self.preserve_work()
        return observed

    def stop_everything(self):
        stopped = self.call(['stop', '--all'], 'close-all', terminal=True)
        require(stopped.get('complete') is True and isinstance(stopped.get('stops'), list)
                and all(row.get('remaining') == [] for row in stopped['stops']), 'Agent stop is incomplete')
        down = self.call(['down'], 'close-runtime', project=False)
        require(down.get('complete') is True and down.get('witness', {}).get('state') == 'witnessed',
                'Runtime closure is not independently witnessed')
        self.observe_runtime_exit()
        require(self.commands.observer.observe() == [], 'Owned processes remain after closing everything')
        return dict(stop=stopped, down=down)

    def come_back(self):
        closed = self.stop_everything()
        shown = self.call(['agent', 'show', self.agent], 'saved-conversation')['agent']['value']
        require(shown['conversation']['id'] == self.initial['conversation'] and shown['resume']['ready'],
                'Saved conversation is not discoverable after closing everything')
        reply = str(uuid.uuid4())
        prompt = f'Write our remembered phrase plus newline to recalled.txt. Reply {reply}.'
        require(self.secret not in prompt, 'Recall prompt disclosed its expected answer')
        self.start_runtime('J3')
        self.launch(['--task', prompt], 'public-reopen', reopen=shown['resume']['argv'])
        value = self.file_turn(reply, 'recalled.txt', (self.secret + '\n').encode(), self.initial)
        self.remember(value, 'recalled.txt')
        require(value['capture']['session'] != self.initial['session'], 'Reopen retained the old runtime session')
        self.preserve_work()
        return dict(closure=closed, recall=value)

    def handoff(self):
        peer = self.call(['agent', 'add', 'relay', '--provider', self.settings['provider']], 'create-peer')['agent']['id']
        instruction = 'Read your next StateEngine mail; write its body plus newline to handoff.txt; reply with its body.'
        launched = self.launch(['launch', peer, '--detach', '--task', instruction], 'launch-peer')
        require(launched['permission_profile'] == self.settings['permission_profile'],
                'Peer launch used a different native permission profile')
        token, key = str(uuid.uuid4()), str(uuid.uuid4())
        request = f'Send StateEngine mail to {peer}: body exactly {token}, idempotency_key {key}. Reply SENT.'
        self.call(['msg', 'send', self.agent, request, '--kind', 'question'], 'request-real-handoff')
        deadline = time.monotonic() + self.settings.get('task_seconds', 240)
        mail = None
        while time.monotonic() < deadline:
            self.credentials.ready()
            rows = self.pages(['msg', 'list', '--all', '--full', '--limit', '100'], 'observe-handoff')
            found = [row for row in rows if row.get('from', {}).get('id') == self.agent
                     and row.get('to', {}).get('id') == peer and row.get('body', {}).get('complete') is True
                     and row['body']['text'] == token and row.get('disposition', {}).get('state') == 'read']
            if found:
                require(len(found) == 1, 'Handoff created more than one matching durable message')
                mail = found[0]
                break
            time.sleep(.5)
        require(mail is not None, 'Recipient-authenticated read of the agent-to-agent handoff was not observed')
        original = self.agent
        try:
            self.agent = peer
            work = self.file_turn(token, 'handoff.txt', (token + '\n').encode())
            self.remember(work, 'handoff.txt')
        finally:
            self.agent = original
        self.preserve_work()
        return dict(message=mail, requested_key=key, peer_work=work)

    def remove(self):
        self.stop_everything()
        # Removing active registrations needs a host even after all sessions stop.
        self.start_runtime('J5')
        removed = self.call(['remove', '--all'], 'remove-project', terminal=True, project=False)
        require(removed.get('outcome') == 'removed' and removed.get('projects')
                and all(row.get('outcome') == 'removed' and row.get('remaining') == []
                        and row.get('processes_may_remain') == [] for row in removed['projects']),
                'Project removal is incomplete')
        self.observe_runtime_exit()
        self.preserve_work()
        for event, payload in self.saved_events.items():
            value = self.call(['history', '--event', event], 'retained-history')
            require(value.get('event_id') == event and value.get('payload') == payload,
                    'Saved conversation event changed or is unavailable after removal')
        self.uninstall()
        require(not self.binary.exists(), 'Uninstall retained the installed command')
        require(self.user_path() == self.original_path, 'Uninstall did not restore the original USER Path')
        require(self.commands.observer.observe() == [], 'Owned processes remain after uninstall')
        self.preserve_work()
        self.record['credential_closure'] = self.credentials.close()
        self.record.update(cleanup=[], process_closure=[], fixture_retained=True)
        self.removed = True
        return dict(remove=removed, user_work_unchanged=True, saved_events=sorted(self.saved_events),
                    installed_command_absent=True, original_user_path_restored=True)

    def run(self):
        interrupted = None
        try:
            for name, operation in zip(JOURNEYS, [self.install, self.adopt_and_work, self.come_back,
                                                 self.handoff, self.remove], strict=True):
                self.phase(name, operation)
        except Prerequisite as error:
            self.record['prerequisite'] = dict(state=error.state, reason=str(error))
        except BaseException as error:
            self.record['failure'] = str(error) or type(error).__name__
            if not isinstance(error, Exception):
                interrupted = error
            try:
                self.diagnostics()
            except Exception as diagnostic:
                self.record['diagnostic_error'] = str(diagnostic)
        finally:
            try:
                if not self.removed:
                    self.cleanup(retain_home=True)
                    self.observe_runtime_exit()
                if self.record.get('process_closure') == [] or self.removed:
                    self.record['credential_closure'] = self.credentials.close()
                    self.commands.environment.pop('CLAUDE_CODE_OAUTH_TOKEN', None)
                    self.commands.environment.pop('ANTHROPIC_API_KEY', None)
            except Exception as error:
                self.record['cleanup_error'] = str(error)
            passed = all(row['result'] == 'PASS' and row.get('tokens', {}).get('state') != 'unavailable'
                         for row in self.record['phases'].values()) and not self.record.get('cleanup_error')
            passed = passed and (self.foreground is None or self.foreground.complete())
            missing_usage = any(row.get('tokens', {}).get('state') == 'unavailable'
                                for row in self.record['phases'].values())
            self.record.update(state='finished', result='PASS' if passed and self.removed else
                               'INCOMPLETE' if (self.record.get('prerequisite') or interrupted or
                                                (missing_usage and not self.record.get('failure')))
                               else 'FAIL')
            self.save()
        if interrupted:
            raise interrupted
        return self.record
