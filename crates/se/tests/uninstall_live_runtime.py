"""Public Linux installed uninstall: real Codex work, shutdown, retained data and JSON fd separation.
Run with --bundle EXTRACTED_NATIVE_ARCHIVE --codex STOCK_CODEX --output NEW_DIRECTORY.
"""
from pathlib import Path
import argparse, datetime, fcntl, hashlib, json, os, shlex, socket, sqlite3, subprocess, tempfile, time, uuid
from codex_first_launch import Model

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def write(p, v):
    p.write_text(json.dumps(v, indent=2, default=str) + '\n')

def birth(pid):
    try:
        p = Path('/proc') / str(pid)
        f = (p / 'stat').read_text().rsplit(') ', 1)[1].split()
        return {'pid': pid, 'start': f[19], 'state': f[0], 'parent': int(f[1]), 'command': (p / 'cmdline').read_bytes().replace(b'\x00', b' ').decode(errors='replace'), 'exe': str((p / 'exe').resolve())}
    except (FileNotFoundError, ProcessLookupError):
        return None

class Fixture:

    def __init__(self, root, port):
        self.root = root
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.home = root / 'owner'
        self.home.mkdir(mode=0o700)
        self.state = self.home / '.local/state/stateengine'
        self.repo = root / 'repo'
        self.repo.mkdir()
        self.logs = root / 'calls'
        self.logs.mkdir()
        self.n = 0
        self.units = []
        self.pins = []
        self.port = port
        self.short = Path(tempfile.mkdtemp(prefix='se-uninstall-test-', dir='/tmp'))
        self.bin = self.home / '.local/bin/se'
        self.env = {'HOME': str(self.home), 'USERPROFILE': str(self.home), 'CODEX_HOME': str(self.home / '.codex'), 'XDG_CONFIG_HOME': str(self.home / '.config'), 'XDG_CACHE_HOME': str(self.home / '.cache'), 'XDG_STATE_HOME': str(self.home / '.local/state'), 'XDG_DATA_HOME': str(self.home / '.local/share'), 'XDG_RUNTIME_DIR': str(self.short), 'PATH': str(self.home / '.local/bin') + ':/usr/bin:/bin', 'SHELL': '/bin/sh', 'LANG': 'C.UTF-8', 'NO_COLOR': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
        (self.home / '.profile').write_text('# owned profile: retain me\n')
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        (self.repo / 'existing.txt').write_text('preserve-' + uuid.uuid4().hex + '\n')
        subprocess.run(['git', '-C', str(self.repo), 'add', '--', 'existing.txt'], check=True)
        subprocess.run(['git', '-C', str(self.repo), '-c', 'user.name=Uninstall consumer', '-c', 'user.email=uninstall@example.invalid', 'commit', '-qm', 'Seed user work', '--', 'existing.txt'], check=True)

    def run(self, label, args, terminal=False, timeout=100, input=b''):
        self.n += 1
        prefix = self.logs / (str(self.n).zfill(3) + '-' + label)
        args = list(map(str, args))
        unit = None
        if terminal:
            unit = 'se-uninstall-test-' + uuid.uuid4().hex[:12]
            argv = ['systemd-run', '--user', '--quiet', '--wait', '--collect', '--pipe', '--unit', unit, '--property=Type=exec', '--property=KillMode=process', '--working-directory', str(self.repo), '--', '/usr/bin/env', '-i', *[k + '=' + v for k, v in self.env.items()], '/usr/bin/script', '-q', '-e', '-c', shlex.join(args) + ' 2>' + shlex.quote(str(prefix.with_suffix('.child-stderr'))), '/dev/null']
        else:
            argv = args
        meta = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'argv': args, 'scheduler': unit}
        start = time.monotonic()
        try:
            r = subprocess.run(argv, env=None if terminal else self.env, cwd=self.repo, input=input, capture_output=True, timeout=timeout)
            prefix.with_suffix('.stdout').write_bytes(r.stdout)
            prefix.with_suffix('.stderr').write_bytes(r.stderr)
            meta.update(exit=r.returncode, elapsed=time.monotonic() - start)
            child = prefix.with_suffix('.child-stderr')
            r.stderr += child.read_bytes() if child.exists() else b''
            prefix.with_suffix('.stderr').write_bytes(r.stderr)
            return r
        except subprocess.TimeoutExpired as e:
            meta.update(timeout=True, elapsed=time.monotonic() - start)
            prefix.with_suffix('.stdout').write_bytes(e.stdout or b'')
            prefix.with_suffix('.stderr').write_bytes(e.stderr or b'')
            raise
        finally:
            write(prefix.with_suffix('.json'), meta)

    def call(self, label, args, terminal=False, binary=None):
        return self.run(label, [binary or self.bin, '--home', self.state, '--json', *args], terminal)

    def ok(self, label, args, **kw):
        r = self.call(label, args, **kw)
        until = time.monotonic() + 30
        while r.returncode and 'init' in args and (b'installation object is in use' in r.stdout + r.stderr) and (time.monotonic() < until):
            time.sleep(0.3)
            r = self.call(label + '-claim-retry', args, **kw)
        assert r.returncode == 0, (label, r.stdout.decode(), r.stderr.decode())
        return json.loads(r.stdout)

    def install(self, bundle, label):
        return self.run(label, ['/bin/sh', bundle / 'install.sh'], True)

    def up(self, label):
        unit = 'se-uninstall-test-live-' + uuid.uuid4().hex[:12]
        command = shlex.join([str(self.bin), '--home', str(self.state), '--json', 'up']) + ' && sleep 3600'
        argv = ['systemd-run', '--user', '--quiet', '--collect', '--unit', unit, '--property=Type=exec', '--property=KillMode=process', '--working-directory', str(self.repo), '--', '/usr/bin/env', '-i', *[k + '=' + v for k, v in self.env.items()], '/usr/bin/script', '-q', '-e', '-c', command, str(self.logs / (label + '-terminal.log'))]
        r = subprocess.run(argv, capture_output=True)
        assert r.returncode == 0, r.stderr
        self.units.append(unit)
        write(self.root / 'units.json', self.units)
        until = time.monotonic() + 45
        while time.monotonic() < until and (not (self.state / 'endpoint.json').exists()):
            time.sleep(0.1)
        while time.monotonic() < until:
            r = self.call(label + '-probe', ['status'])
            if r.returncode == 0 and json.loads(r.stdout)['runtime']['state'] == 'running':
                self.capture()
                return
            time.sleep(0.3)
        raise AssertionError('up timed out')

    def capture(self):
        r = self.ok('pins', ['status'])
        pins = [r['runtime'].get('process')] + [a.get('session', {}).get('process') for a in r.get('agents', {}).get('items', [])]
        roots = set()
        for p in pins:
            if p:
                b = birth(p['pid'])
                assert b and b['exe'] == p['exe']
                roots.add(p['pid'])
        census = {}
        for p in Path('/proc').iterdir():
            if p.name.isdigit():
                b = birth(int(p.name))
                if b:
                    census[int(p.name)] = b
        while True:
            new = {pid for pid, b in census.items() if b['parent'] in roots}
            if new <= roots:
                break
            roots |= new
        self.pins += [census[p] for p in roots if census[p] not in self.pins]
        write(self.root / 'births.json', self.pins)

    def closed(self, label):
        assert not (self.state / 'endpoint.json').exists(), 'endpoint live'
        until = time.monotonic() + 10
        while True:
            now = [birth(p['pid']) for p in self.pins]
            closed = all(b is None or b['start'] != p['start'] or b['state'] == 'Z' for p, b in zip(self.pins, now))
            if closed or time.monotonic() >= until:
                break
            time.sleep(.1)
        assert closed, [(pin['pid'], row['state']) for pin, row in zip(self.pins, now) if row is not None]
        with (self.state / 'runtime.lock').open('r+b') as f:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(f, fcntl.LOCK_UN)
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('127.0.0.1', self.port))
        write(self.root / (label + '-outside.json'), {'pins': self.pins, 'fresh': now, 'endpoint_absent': True, 'runtime_lock_free': True, 'port_reusable': True})

    def db(self, label):
        with sqlite3.connect('file:' + str(self.state / 'state.db') + '?mode=ro', uri=True) as db:
            v = db.execute('pragma user_version').fetchone()[0]
            tables = {}
            for table, in db.execute("select name from sqlite_master where type='table' and name not like 'sqlite_%' order by name").fetchall():
                rows = db.execute('select * from "' + table + '"').fetchall()
                tables[table] = sorted([[{'blob': x.hex()} if isinstance(x, bytes) else x for x in row] for row in rows], key=lambda r: json.dumps(r, sort_keys=True))
        out = {'schema': v, 'tables': tables}
        write(self.root / (label + '-db.json'), out)
        return out

    def close(self):
        if self.bin.exists() and (self.state / 'state.db').exists():
            r = self.call('finally-down', ['down'], True)
            assert r.returncode == 0, (r.stdout, r.stderr)
        for u in self.units:
            subprocess.run(['systemctl', '--user', 'stop', u + '.service'], check=True, capture_output=True)
        self.closed('final') if (self.state / 'runtime.lock').exists() else None

def main(options):
    os.umask(0o077)
    options.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    checks = []

    def check(message):
        checks.append(message)
        print('ok', len(checks), '-', message, flush=True)
        write(options.output / 'result.json', {'passed': len(checks), 'checks': checks, 'complete': False})
    for case in options.case or ['live-json', 'live-plain', 'idle-json', 'refused-json']:
        for offset in range(10000):
            port = 20000 + (uuid.uuid4().int + offset) % 10000
            with socket.socket() as listener:
                try:
                    listener.bind(('127.0.0.1', port))
                    break
                except OSError:
                    continue
        else:
            raise AssertionError('no free port in the configured runtime range')
        f = Fixture(options.output / case, port)
        model = None
        held = None
        try:
            installed = f.install(options.bundle, 'install')
            assert installed.returncode == 0, (installed.stdout, installed.stderr)
            init = f.ok('init', ['init', '--repo', f.repo, '--name', 'Retained work', '--agent', 'Builder', '--provider', 'codex', '--model', 'gpt-6.1-sol'], terminal=True)
            project, agent = (init['project']['id'], init['agent']['id'])
            conf = f.state / 'config.toml'
            text = conf.read_text()
            anchor = 'listen_port = ' + str(init['profile']['native_server_port'])
            assert text.count(anchor) == 1
            conf.write_text(text.replace(anchor, 'listen_port = ' + str(port), 1).replace('[providers.codex]', '[providers.codex]\ncommand = ' + json.dumps(str(options.codex)), 1))
            model = Model(f.root, f.repo)
            code = Path(f.env['CODEX_HOME'])
            code.mkdir(mode=0o700)
            (code / 'config.toml').write_text('model_provider="owned-model"\n[model_providers.owned-model]\nname="Owned loopback"\nbase_url=' + json.dumps('http://127.0.0.1:' + str(model.server.server_port) + '/v1') + '\nwire_api="responses"\nrequires_openai_auth=false\n')
            f.env['OPENAI_API_KEY'] = 'sk-owned-loopback-no-account'
            login = f.run('login', [options.codex, 'login', '--with-api-key'], input=f.env['OPENAI_API_KEY'].encode())
            assert login.returncode == 0, login.stderr
            f.up('runtime')
            launch = f.ok('launch', ['--project', project, 'launch', agent, '--detach', '--task', 'Write sum.txt with 5 followed by a newline, read it back, then reply SUM_DONE.'], terminal=True)
            f.capture()
            until = time.monotonic() + 90
            while time.monotonic() < until:
                history = f.ok('history', ['--project', project, 'history', '--agent', agent, '--limit', '100'])
                if (f.repo / 'sum.txt').exists() and 'SUM_DONE' in json.dumps(history):
                    break
                time.sleep(0.3)
            assert (f.repo / 'sum.txt').read_text() == '5\n' and 'SUM_DONE' in json.dumps(history)
            check(case + ': installed stock Codex completes real file work before uninstall')
            status = f.ok('before-status', ['status'])
            conversation = status['agents']['items'][0]['conversation']['id']
            f.ok('retained-mail', ['--project', project, 'msg', 'send', agent, 'Retain this message across automatic shutdown and uninstall.'])
            protected = {name: sha(f.state / name) for name in ['config.toml', 'credential', 'machine.json']}
            protected_login = {path: sha(path) for path in code.iterdir() if path.is_file() and path.name in ['auth.json', 'config.toml']}
            user_file = (f.repo / 'existing.txt').read_bytes()
            before = f.db('before')
            if case == 'idle-json':
                stopped = f.ok('idle-down', ['down'], terminal=True)
                assert stopped['complete']
                f.closed('idle')
            if case == 'refused-json':
                endpoint = f.state / 'endpoint.json'
                held = f.state / 'endpoint-test-held.json'
                endpoint.rename(held)
                record = json.loads((f.state / 'standalone-install.json').read_text())
                assets = {row['path']: sha(Path(row['path'])) for row in record['files']}
                assets[str(f.state / 'standalone-install.json')] = sha(f.state / 'standalone-install.json')
                profile = (f.home / '.profile').read_bytes()
                refused = f.call('uninstall-refused', ['uninstall'], terminal=True)
                assert refused.returncode != 0, (refused.stdout, refused.stderr)
                assert b'Installation files, its record and PATH were retained' in refused.stderr, refused.stderr
                assert all((sha(Path(path)) == digest for path, digest in assets.items()))
                assert (f.home / '.profile').read_bytes() == profile
                provider = birth(launch['process']['pid'])
                assert provider and provider['state'] != 'Z'
                check(case + ': unproved ordinary shutdown names its failure and preserves every installation asset and PATH')
                held.rename(endpoint)
                held = None
            if case == 'live-plain':
                removed = f.run('uninstall-plain', [f.bin, '--home', f.state, 'uninstall'], True)
                assert removed.returncode == 0, (removed.stdout, removed.stderr)
                assert b'Uninstall' in removed.stdout and b'ordinary se down' in removed.stderr
            else:
                removed = f.call('uninstall-json', ['uninstall'], terminal=True)
                assert removed.returncode == 0, (removed.stdout, removed.stderr)
                result = json.loads(removed.stdout)
                assert result['schema'] == 'se.uninstall/v1' and result['complete'], result
                assert b'Uninstall:' in removed.stderr and b'Remove exact owned file' in removed.stderr
                if case != 'idle-json':
                    assert result['stops'] and all((row['complete'] for row in result['stops']))
            f.closed('uninstalled')
            assert not f.bin.exists() and (not (f.state / 'standalone-install.json').exists())
            check(case + ': one public uninstall verifies shutdown then removes the installation; stdout/stderr remain separate')
            after = f.db('after')
            for table in ['events', 'message_data', 'payloads']:
                assert all((row in after['tables'][table] for row in before['tables'][table])), table
            assert all((sha(f.state / name) == digest for name, digest in protected.items()))
            assert (f.repo / 'existing.txt').read_bytes() == user_file and (f.repo / 'sum.txt').read_text() == '5\n'
            assert all(sha(path) == digest for path, digest in protected_login.items())
            check(case + ': committed history/mail/payload bytes, identity, configuration, credentials and user work survive')
            installed = f.install(options.bundle, 'reinstall')
            assert installed.returncode == 0, (installed.stdout, installed.stderr)
            f.ok('reinit', ['init', '--repo', f.repo, '--agent', 'Builder', '--provider', 'codex'], terminal=True)
            after_status = f.ok('returned-status', ['status'])
            assert after_status['project']['value']['id'] == project
            assert len(after_status['agents']['items']) == 1 and after_status['agents']['items'][0]['id'] == agent
            assert after_status['agents']['items'][0]['conversation']['id'] == conversation
            check(case + ': reinstall/init preserves the same project, agent and provider conversation')
        finally:
            if held is not None and held.exists():
                held.rename(f.state / 'endpoint.json')
            f.close()
            if model is not None:
                model.close()
    write(options.output / 'result.json', {'passed': len(checks), 'checks': checks, 'complete': True})
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--codex', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', action='append', choices=['live-json', 'live-plain', 'idle-json', 'refused-json'])
    options = parser.parse_args()
    options.bundle = options.bundle.resolve()
    options.codex = options.codex.resolve()
    options.output = options.output.resolve()
    main(options)
