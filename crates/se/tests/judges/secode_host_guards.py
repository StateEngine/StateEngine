"""Public CLI refusal checks for the pinned external-host contract.

These checks qualify admission guards only. They perform no model turn and
make no managed-service recovery, mail or native Windows claim.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

from secode_external import PIN, capabilities, environment, image_hash, package


def native_probe(root, value):
    """A finite native probe with an observable refusal for every launch verb."""
    root.mkdir()
    (root / 'capabilities.json').write_text(json.dumps(value))
    source = root / 'probe.rs'
    source.write_text(r'''use std::{env,fs,io::Write};
fn main() {
    let directory=env::current_exe().unwrap().parent().unwrap().to_path_buf();
    let args:Vec<String>=env::args().skip(1).collect();
    let mut log=fs::OpenOptions::new().create(true).append(true)
        .open(directory.join("calls")).unwrap();
    writeln!(log,"{}",args.join(" ")).unwrap();
    match args.as_slice() {
        [arg] if arg=="--version" => println!("secode refusal-fixture"),
        [arg] if arg=="--external-host-capabilities" =>
            print!("{}",fs::read_to_string(directory.join("capabilities.json")).unwrap()),
        _ => std::process::exit(81),
    }
}''')
    suffix = '.exe' if os.name == 'nt' else ''
    cli = root / ('secode' + suffix)
    subprocess.run(['rustc', '--edition=2024', str(source), '-o', str(cli)],
                   stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=60)
    (root / ('secode-server' + suffix)).write_bytes(cli.read_bytes())
    (root / ('secode-server' + suffix)).chmod(0o700)
    return cli


class Fixture:
    def __init__(self, se, root, provider, sandbox, approval):
        self.se, self.root = se.resolve(), root.resolve()
        root.mkdir()
        self.env = environment(root)
        self.home, self.repo = root / 'state', root / 'repo'
        self.home.mkdir(mode=0o700)
        self.repo.mkdir()
        self.calls = 0
        self.runtime = None
        config = self.home / 'config.toml'
        config.write_text('version = 1\n[providers.secode]\ncommand = ' +
                          json.dumps(str(provider.resolve())) +
                          '\n[profiles.default]\nsandbox = ' + json.dumps(sandbox) +
                          '\napproval = ' + json.dumps(approval) + '\n')
        config.chmod(0o600)
        value = self.ok('--key', str(uuid.uuid4()), 'init', '--repo', str(self.repo),
                        '--name', 'Headless Guards', '--agent', 'Guarded',
                        '--provider', 'secode', '--model', 'fixture/model')
        self.project, self.agent = value['project']['id'], value['agent']['id']
        text = config.read_text()
        port = value['profile']['native_server_port']
        assert text.count(f'listen_port = {port}') == 1, text
        config.write_text(text.replace(f'listen_port = {port}', '', 1))
        self.ok('up')

    def call(self, *args):
        self.calls += 1
        result = subprocess.run([str(self.se), '--json', '--home', str(self.home), *args],
                                cwd=self.repo, env=self.env, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=90)
        base = self.root / f'call-{self.calls:02}'
        base.with_suffix('.stdout').write_bytes(result.stdout)
        base.with_suffix('.stderr').write_bytes(result.stderr)
        base.with_suffix('.exit').write_text(str(result.returncode))
        return result

    def ok(self, *args):
        result = self.call(*args)
        until = time.monotonic() + 40
        while (result.returncode and 'init' in args and
               b'installation record is busy' in result.stderr and time.monotonic() < until):
            time.sleep(1)
            result = self.call(*args)
        assert result.returncode == 0, (args, result.stdout, result.stderr)
        return json.loads(result.stdout)

    def snapshot(self):
        agent = self.ok('--project', self.project, 'agent', 'show', self.agent)['agent']['value']
        history = self.ok('--project', self.project, 'history', '--limit', '100')
        assert history['window']['complete'] and history['next'] is None, history
        assert agent['session']['state'] == 'never-launched', agent
        if sys.platform == 'linux':
            owner = json.loads((self.home / 'endpoint.json').read_text())['epoch']['owner']
            pid = owner['pid']
            process = Path('/proc') / str(pid)
            fields = (process / 'stat').read_text().rsplit(') ', 1)[1].split()
            argv = [os.fsdecode(x) for x in (process / 'cmdline').read_bytes().split(b'\0') if x]
            identity = {'pid': pid, 'birth': fields[19],
                        'image': str((process / 'exe').resolve(strict=True)), 'argv': argv}
            assert identity['birth'] == str(owner['started']['start_ticks']), identity
            assert identity['image'] == str(self.se), identity
            assert argv == [str(self.se), '--stateengine-private-runtime-bootstrap'], identity
            assert self.runtime is None or self.runtime == identity, 'runtime identity changed'
            self.runtime = identity
            (self.root / 'runtime-identity.json').write_text(json.dumps(identity, indent=2))
        return agent, history['items']

    def absent_service(self):
        for name in ('secode', 'secode-profiles'):
            path = self.home / name
            assert not path.exists() or not list(path.iterdir()), (name, list(path.iterdir()))

    def refuse(self, reason, detach=True):
        before = self.snapshot()
        self.absent_service()
        argv = ['--project', self.project, 'launch', self.agent, '--task',
                'This original input must not be admitted']
        if detach:
            argv.append('--detach')
        result = self.call(*argv)
        assert result.returncode != 0, (result.stdout, result.stderr)
        error = result.stdout + result.stderr
        code = b'provider-incompatible' if detach else b'usage-invalid-value'
        assert code in error and reason.encode() in error, error
        assert self.snapshot() == before, 'refusal changed public agent or event history'
        self.absent_service()

    def close(self):
        value = self.ok('down')
        assert value['complete'] and value['witness']['state'] == 'witnessed', value
        assert not (self.home / 'endpoint.json').exists(), 'runtime registration retained'
        if self.runtime:
            path = Path('/proc') / str(self.runtime['pid']) / 'stat'
            try:
                fields = path.read_text().rsplit(') ', 1)[1].split()
                assert fields[19] != self.runtime['birth'] or fields[0] == 'Z', 'runtime still live'
            except FileNotFoundError:
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--secode', type=Path, required=True)
    parser.add_argument('--pin', default=PIN)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(mode=0o700)
    hashes = package(args.secode.resolve(), args.pin)
    env = environment(root)
    server = args.secode.with_name('secode-server.exe' if os.name == 'nt' else 'secode-server')
    probe = subprocess.run([str(server), '--external-host-capabilities'], env=env,
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=True)
    (root / 'pinned-capabilities.json').write_bytes(probe.stdout)
    value = json.loads(probe.stdout)
    capabilities(value)
    (root / 'images.json').write_text(json.dumps({'pin': args.pin, 'provider': hashes,
                                                 'host': image_hash(args.se)}, indent=2))
    cases = [
        ('workspace', 'workspace-write', 'never', 'repository-metadata policy', True, None),
        ('attended', 'read-only', 'never', 'headless launch with --detach', False, None),
        ('approval', 'read-only', 'on-request', 'interactive approval transport', True, None),
        ('capability', 'read-only', 'never', '/initial_input/uncertain_write', True, 'pending-no-replay'),
    ]
    print('1..5', flush=True)
    for number, (name, sandbox, approval, reason, detach, mutation) in enumerate(cases, 1):
        altered = copy.deepcopy(value)
        if mutation:
            assert altered['initial_input']['uncertain_write'] == mutation
            altered['initial_input']['uncertain_write'] = 'unsupported-fixture'
        directory = root / (name + '-probe')
        provider = native_probe(directory, altered)
        fixture = Fixture(args.se, root / name, provider, sandbox, approval)
        try:
            fixture.refuse(reason, detach)
            calls = (directory / 'calls').read_text().splitlines() if (directory / 'calls').exists() else []
            expected = ['--external-host-capabilities'] if mutation else []
            assert calls == expected, (name, calls, expected)
        finally:
            fixture.close()
        print(f'ok {number} - {name} refuses before service, session and input admission', flush=True)
    provider = native_probe(root / 'fresh-status-probe', value)
    fixture = Fixture(args.se, root / 'fresh-status', provider, 'read-only', 'never')
    try:
        row, _ = fixture.snapshot()
        fixture.absent_service()
        assert row['secode_binding']['state'] == 'absent', row
        if row['secode_runtime']['state'] != 'absent':
            print('not ok 5 - never-launched service absence is reported honestly', flush=True)
            raise AssertionError(row['secode_runtime'])
        print('ok 5 - never-launched service absence is reported honestly', flush=True)
    finally:
        fixture.close()
    assert package(args.secode.resolve(), args.pin) == hashes, 'pinned package changed'


if __name__ == '__main__':
    main()
