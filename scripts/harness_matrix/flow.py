"""One public-command smoke flow shared by the native harness adapters."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
import uuid

from .io import Commands, digest, require, save
from .inputs import home_path

PHASES = ('Launch', 'Work', 'Mail', 'Resume')


class Smoke:
    def __init__(self, output, package, entry, settings, inherited):
        self.output, self.package, self.entry, self.settings = output, package, entry, settings
        self.home = output / 'home'
        self.home.mkdir(mode=0o700)
        self.state = self.home / 'state'
        self.repository = self.home / 'repository'
        self.repository.mkdir()
        self.project = self.agent = self.owner = None
        self.initialization_attempted = False
        binary = self.home / ('AppData/Local/StateEngine/bin/se.exe' if sys.platform == 'win32'
                              else '.local/bin/se')
        self.binary = binary
        # Native names are matched case-insensitively: hosted runners do not
        # guarantee the classic mixed case, and Winsock refuses to initialize
        # a child environment that lost its system root.
        system = {'path', 'systemroot', 'windir', 'comspec', 'pathext', 'lang', 'lc_all'}
        taken = set()
        environment = {}
        for key, value in inherited.items():
            lowered = key.lower()
            if lowered in system:
                if lowered not in taken:
                    taken.add(lowered)
                    environment[key] = value
            elif key in settings.get('environment', []):
                environment[key] = value
        environment.update(HOME=str(self.home), USERPROFILE=str(self.home), SE_HOME=str(self.state),
                           PATH=str(binary.parent) + os.pathsep + inherited.get('PATH', ''),
                           XDG_CONFIG_HOME=str(self.home / '.config'),
                           XDG_STATE_HOME=str(self.home / '.local/state'),
                           XDG_DATA_HOME=str(self.home / '.local/share'),
                           XDG_CACHE_HOME=str(self.home / '.cache'),
                           APPDATA=str(self.home / 'AppData/Roaming'),
                           LOCALAPPDATA=str(self.home / 'AppData/Local'),
                           TMPDIR=str(self.home / 'tmp'), TMP=str(self.home / 'tmp'),
                           TEMP=str(self.home / 'tmp'), LANG='C.UTF-8', LC_ALL='C.UTF-8',
                           GIT_CONFIG_GLOBAL=str(self.home / '.gitconfig'), GIT_CONFIG_NOSYSTEM='1')
        (self.home / 'tmp').mkdir()
        for name, relative in settings.get('home_environment', {}).items():
            environment[name] = str(self.home / home_path(relative))
        self.commands = Commands(output, self.home, self.repository, environment,
                                 settings.get('terminal_prefix', []))
        self.record = dict(harness=entry['id'], driver=entry['driver'], platform=sys.platform, state='running', result='NOT RUN',
                           qualification='smoke-only; clean-machine and performance qualification unassessed',
                           home=str(self.home), phases={name: dict(result='NOT RUN') for name in PHASES},
                           cleanup=None, process_closure=None, steps=[])
        self.save()

    def save(self):
        save(self.output / 'receipt.json', self.record)

    def call(self, args, label, terminal=False, project=True):
        argv = [self.binary, *args, '--home', self.state, '--json', '--no-color']
        if project and self.project:
            argv += ['--project', self.project]
        return json.loads(self.commands.run(argv, label, terminal=terminal))

    def pages(self, args, label):
        rows, cursor, seen = [], None, set()
        for _ in range(100):
            page = self.call([*args, *(['--cursor', cursor] if cursor else [])], label)
            require(isinstance(page.get('items'), list), label + ': unreadable rows')
            rows.extend(page['items'])
            window = page.get('window', {})
            if window.get('complete') is True:
                require(window.get('omitted', {}).get('count') == 0, label + ': omitted rows')
                return rows
            cursor = page.get('next')
            require(isinstance(cursor, str) and cursor and cursor not in seen,
                    label + ': incomplete page has no advancing cursor')
            seen.add(cursor)
        raise RuntimeError(label + ': paging bound reached')

    def reply(self, token, deadline):
        while time.monotonic() < deadline:
            rows = self.pages(['msg', 'list', '--all', '--full', '--limit', '100'], 'messages')
            found = [row for row in rows if row.get('from', {}).get('id') == self.agent
                     and row.get('to', {}).get('id') == self.owner and row.get('kind') == 'done'
                     and row.get('body', {}).get('complete') is True
                     and token in row['body'].get('text', '')]
            if found:
                return [row['id'] for row in found]
            self.commands.observer.observe()
            time.sleep(.5)
        raise RuntimeError('Authenticated owner reply was not observed before the task deadline')

    def captured(self, token, previous=None, deadline=None):
        shown = self.call(['agent', 'show', self.agent], 'agent-show')
        row = shown.get('agent', {}).get('value')
        require(shown.get('agent', {}).get('state') == 'present' and row
                and row.get('provider') == self.settings['provider']
                and row.get('harness') == self.settings.get('harness'),
                'Saved descriptor-bound agent is unavailable or changed')
        conversation = row.get('conversation', {}).get('id')
        session = row.get('session', {}).get('session_id')
        require(isinstance(conversation, str) and conversation and isinstance(session, str) and session,
                'Provider conversation or managed session identity is absent')
        if previous:
            require(conversation == previous['conversation'] and session != previous['session'],
                    'Resume changed the provider conversation or reused the managed session')
        self.commands.observer.observe(row['session']['process']['pid'])
        if deadline is None:
            deadline = time.monotonic() + self.settings.get('task_seconds', 240)
        while time.monotonic() < deadline:
            rows = self.pages(['history', '--agent', self.agent, '--kind', 'session.turn',
                               '--limit', '100'], 'history')
            matching = [event for event in rows if event.get('payload', {}).get('role') == 'assistant'
                        and event['payload'].get('provider_session') == conversation
                        and event['payload'].get('session_id') == session
                        and token in self.assistant_text(event['payload'].get('body', {}).get('text', ''))]
            if matching and self.settings['provider'] == 'secode':
                native = self.call(['agent', 'show', self.agent], 'completion-status')['agent']['value'].get('secode_runtime', {})
                require(native.get('state') == 'present' and type(native.get('value', {}).get('active')) is bool,
                        'Native execution completion is unreadable')
                if native['value']['active']:
                    matching = []
            if matching:
                for event in matching:
                    body = event['payload']['body']
                    require(body.get('complete') is True and body.get('bytes') == len(body['text'].encode())
                            and body.get('sha256') == hashlib.sha256(body['text'].encode()).hexdigest(),
                            'Captured assistant body is incomplete or inconsistent')
                return dict(conversation=conversation, session=session,
                            events=[event['event_id'] for event in matching])
            time.sleep(.5)
        raise RuntimeError('Complete canonical assistant capture was not observed')

    def assistant_text(self, text):
        if self.settings['provider'] != 'secode':
            return text
        parts = json.loads(text)
        require(isinstance(parts, list) and all(isinstance(part, dict) for part in parts),
                'Native assistant parts are unreadable')
        return '\n'.join(part['text'] for part in parts
                         if part.get('type') == 'text' and isinstance(part.get('text'), str))

    def file_turn(self, token, filename, expected, previous=None):
        deadline = time.monotonic() + self.settings.get('task_seconds', 240)
        observation = dict(state='absent')
        while time.monotonic() < deadline:
            try:
                with (self.repository / filename).open('rb') as stream:
                    observed = stream.read(len(expected) + 1)
                observation = dict(state='present', prefix_bytes=len(observed))
                if observed == expected:
                    break
            except FileNotFoundError:
                observation = dict(state='absent')
            time.sleep(.5)
        else:
            raise RuntimeError(filename + ' did not match before deadline: ' + json.dumps(observation))
        capture = self.captured(token, previous, deadline)
        return dict(capture=capture, expected_sha256=hashlib.sha256(expected).hexdigest(),
                    file_sha256=hashlib.sha256(observed).hexdigest())

    def phase(self, name, operation):
        started = time.monotonic()
        self.record['phases'][name] = dict(state='running', result='NOT RUN')
        self.save()
        try:
            value = operation()
            self.record['phases'][name] = dict(state='finished', result='PASS', evidence=value,
                                               elapsed_seconds=time.monotonic() - started)
            return value
        except BaseException as error:
            self.record['phases'][name].update(state='finished', result='FAIL', reason=str(error),
                                               elapsed_seconds=time.monotonic() - started)
            raise
        finally:
            self.save()

    def prepare(self):
        account_check = Path(__file__).resolve().parents[1] / 'ci/installation_account.py'
        self.commands.run([sys.executable, '-B', account_check, 'check'], 'installation-account')
        installer = (['powershell.exe', '-NoProfile', '-NonInteractive', '-File',
                      self.package / 'install.ps1'] if sys.platform == 'win32'
                     else ['sh', self.package / 'install.sh'])
        self.commands.run(installer, 'install')
        manifest = json.loads((self.package / 'manifest.json').read_text())
        build = json.loads((self.package / 'build.json').read_text())
        source_binary = 'se.exe' if sys.platform == 'win32' else 'se'
        require(digest(self.binary) == manifest['files'][source_binary]['sha256']
                == build['files'][source_binary],
                'Installed CLI differs from the selected package')
        configuration = Path(self.settings['configuration']['path'])
        require(digest(configuration) == self.settings['configuration']['sha256'],
                'Selected configuration changed before use')
        self.state.mkdir(mode=0o700, exist_ok=True)
        target = self.state / 'config.toml'
        target.write_bytes(configuration.read_bytes())
        target.chmod(0o600)
        output = self.commands.run(self.settings['version_command'], 'native-version')
        require(output.strip() == self.settings['version_stdout'], 'Installed harness version differs')
        selection = (['--harness', self.settings['harness']] if self.settings['provider'] == 'acp'
                     else ['--provider', self.settings['provider']])
        self.initialization_attempted = True
        initialized = self.call(['init', '--repo', self.repository, '--agent', 'main', *selection],
                                'init', terminal=True, project=False)
        self.project, self.agent, self.owner = (initialized['profile'][name]
                                               for name in ('project', 'agent_id', 'human_id'))
        self.call(['up'], 'up', project=False)
        status = self.call(['status'], 'status')
        self.commands.observer.observe(status['runtime']['process']['pid'])

    def exercise(self):
        secret, work, mail, recall = [str(uuid.uuid4()) for _ in range(4)]
        task = (f'Remember {secret} for our next conversation. Create work.txt containing exactly '
                f'{work} followed by a newline, read it back, and reply containing {work}.')
        def launch():
            launched = self.call(['launch', self.agent, '--detach', '--task', task],
                                 'launch', terminal=True)
            require(launched['permission_profile'] == self.settings['permission_profile'],
                    'Launch permission profile differs from the explicit selection')
            self.commands.observer.observe(launched['process']['pid'])
            return launched
        launched = self.phase('Launch', launch)

        first = dict(conversation=launched['conversation_id'], session=launched['session_id'])
        try:
            self.phase('Work', lambda: self.file_turn(work, 'work.txt', (work + '\n').encode()))
        except Exception as error:
            self.record['failure'] = 'Work: ' + str(error)
            self.diagnostics()

        def mail_turn():
            deadline = time.monotonic() + self.settings.get('task_seconds', 240)
            sent = self.call(['msg', 'send', self.agent, 'Send a StateEngine done reply to owner '
                              f'containing exactly {mail}.', '--kind', 'question'], 'send')
            require(sent.get('state') == 'committed' and sent.get('message_id'),
                    'Mail has no witnessed committed identity')
            return dict(sent=sent['message_id'], replies=self.reply(mail, deadline),
                        capture=self.captured(mail, deadline=deadline))
        try:
            self.phase('Mail', mail_turn)
        except Exception as error:
            self.record['failure'] = 'Mail: ' + str(error)
            self.diagnostics()

        def resume_turn():
            stopped = self.call(['stop', self.agent], 'stop', terminal=True)
            require(stopped.get('complete') is True and stopped.get('remaining') == []
                    and stopped.get('witness', {}).get('state') == 'witnessed'
                    and stopped.get('capture', {}).get('flushed') is True, 'Stop proof is incomplete')
            shown = self.call(['agent', 'show', self.agent], 'stopped-show')['agent']['value']
            status = self.call(['status'], 'stopped-status')
            row, = [value for value in status['agents']['items'] if value['id'] == self.agent]
            for view in (shown, row):
                require(view['session']['state'] == 'stopped' and view['resume']['ready'] is True
                        and view['conversation']['id'] == first['conversation'],
                        'Public discovery lost the saved conversation')
            # Execute the public argv verbatim; the prompt does not contain the answer.
            argv = row['resume']['argv']
            require(isinstance(argv, list) and argv and all(isinstance(v, str) for v in argv),
                    'Public resume argv is unavailable')
            prompt = ('Recall the phrase I asked you to remember. Write exactly that phrase '
                      'followed by a newline to resumed.txt, read it back, and reply '
                      f'containing {recall}.')
            self.commands.run([*argv, '--task', prompt], 'public-resume', terminal=True)
            return self.file_turn(recall, 'resumed.txt', (secret + '\n').encode(), first)
        self.phase('Resume', resume_turn)

    def diagnostics(self):
        # Capture through public readers before stop/remove can change discovery.
        self.record['diagnostics'] = {}
        if self.project and self.agent:
            for label, args in [('agent', ['agent', 'show', self.agent]),
                                ('history', ['history', '--agent', self.agent, '--kind',
                                             'session.turn', '--limit', '100'])]:
                try:
                    self.record['diagnostics'][label] = self.call(args, 'failure-' + label)
                except Exception as error:
                    self.record['diagnostics'][label] = dict(state='unreadable', reason=str(error))
        self.save()

    def cleanup(self):
        errors = []
        try:
            self.commands.observer.observe()
        except Exception as error:
            errors.append('pre-cleanup process census: ' + str(error))
        if self.binary.exists():
            for name, args in ([('stop', ['stop', '--all']), ('remove', ['remove', '--all']),
                                ('down', ['down'])] if self.initialization_attempted else []):
                try:
                    result = self.call(args, 'cleanup-' + name, terminal=name != 'down', project=name == 'stop')
                    if name == 'stop':
                        require(result.get('complete') is True and isinstance(result.get('stops'), list)
                                and all(row.get('remaining') == [] and row.get('enumeration') == 'complete'
                                        for row in result['stops']), 'Stop closure is incomplete')
                    if name == 'down':
                        require(result.get('complete') is True and result.get('witness', {}).get('state') == 'witnessed'
                                and isinstance(result.get('stops'), list)
                                and all(row.get('complete') is True for row in result['stops']),
                                'Runtime closure is incomplete')
                except Exception as error:
                    errors.append(name + ': ' + str(error))
            try:
                self.commands.run([self.binary, 'uninstall', '--home', self.state, '--json'],
                                  'uninstall', terminal=True)
            except Exception as error:
                errors.append('uninstall: ' + str(error))
        try:
            remaining = self.commands.observer.observe()
        except Exception as error:
            remaining = None
            errors.append('process census: ' + str(error))
        self.record.update(cleanup=errors, process_closure=remaining)
        if not errors and remaining == [] and not self.record.get('failure'):
            shutil.rmtree(self.home)
            require(not self.home.exists(), 'Finished fixture home remains')
        self.record['fixture_retained'] = self.home.exists()

    def run(self):
        interrupted = None
        try:
            self.prepare()
            self.exercise()
        except BaseException as error:
            self.record['failure'] = str(error) or type(error).__name__
            if not isinstance(error, Exception):
                interrupted = error
            self.diagnostics()
        finally:
            try:
                self.cleanup()
            except Exception as error:
                if self.record.get('cleanup') is None:
                    self.record['cleanup'] = []
                self.record['cleanup'].append(str(error))
            passed = all(row['result'] == 'PASS' for row in self.record['phases'].values())
            self.record.update(state='finished', result='PASS' if passed and not self.record.get('failure')
                               and self.record['cleanup'] == [] and self.record['process_closure'] == [] else 'FAIL')
            self.save()
        if interrupted is not None:
            raise interrupted
        return self.record
