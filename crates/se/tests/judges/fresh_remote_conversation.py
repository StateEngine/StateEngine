"""Independent remote launch through real OpenSSH, native CLI/MCP and hosts.

The provider alone is a protocol double; SSH, pairing, Owner consent, wire
attribution, durable state, mail, conversation selection and shutdown are real.
Run only on a disposable Linux runner with openssh-server and passwordless sudo.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import termios
import time
import uuid

from fixture_paths import private_runtime_directory
from fresh_conversation import private_bytes
from mail_cli import Fixture
from private_ssh_fixture import PrivateSsh, identity


def configure(fixture, runtime):
    source = fixture.root / 'provider.rs'
    source.write_text(source.read_text().replace('2.1.287', '2.1.318'))
    subprocess.run(['rustc', '--edition=2024', str(source), '-o', str(fixture.root / 'provider')],
                   capture_output=True, check=True, timeout=60)
    fixture.env = {'PATH': os.environ['PATH'], 'HOME': str(fixture.root / 'owner'),
                   'USERPROFILE': str(fixture.root / 'owner'), 'LANG': 'C.UTF-8',
                   'XDG_RUNTIME_DIR': str(runtime)}
    for name in ('XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME'):
        path = fixture.root / name.lower()
        path.mkdir()
        fixture.env[name] = str(path)


def consent(fixture):
    master, slave = pty.openpty()
    def terminal():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    command = [str(fixture.se), '--home', str(fixture.home),
               'remote', 'permissions', '--name', 'peer', '--launch']
    process = subprocess.Popen(command, cwd=fixture.repo, env=fixture.env,
                               stdin=slave, stdout=slave, stderr=slave, preexec_fn=terminal)
    launched = identity(process.pid)
    os.close(slave)
    output = bytearray()
    choices = [(b'Choose an agent number', b'1\n'),
               (b'[allow/revoke/Enter to cancel]', b'allow\n'),
               (b'Launch consent saved.', b'\n')]
    try:
        until = time.monotonic() + 45
        while time.monotonic() < until:
            if select.select([master], [], [], .1)[0]:
                try:
                    block = os.read(master, 65536)
                except OSError:
                    break
                if not block:
                    break
                output.extend(block)
                if choices and choices[0][0] in output:
                    _, answer = choices.pop(0)
                    os.write(master, answer)
            elif process.poll() is not None:
                break
        # A PTY can report its final EOF before waitpid observes process exit.
        # Join the owned command rather than treating that scheduling gap as a hang.
        process.wait(timeout=5)
        assert process.returncode == 0 and not choices, output.decode()
    finally:
        os.close(master)
        (fixture.root / 'launch-consent.terminal').write_bytes(output)
        if process.poll() is None:
            current = identity(process.pid)
            assert launched and current and current['birth'] == launched['birth'], current
            assert current['command'] == launched['command'], current
            process.terminate()
            process.wait(timeout=10)
    assert b'allowed' in output and b'Launch consent saved.' in output, output.decode()


def observation(fixture, session):
    until = time.monotonic() + 25
    while True:
        path = fixture.repo / 'launch-observed.jsonl'
        text = path.read_text() if path.exists() else ''
        for line in text[:text.rfind('\n') + 1].splitlines():
            row = json.loads(line)
            if row['environment'].get('SE_SESSION') == session:
                for pid in (row['native_root_pid'], row['helper_pid']):
                    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
                    fixture.processes.append((pid, fields[19]))
                return row
        assert time.monotonic() < until, 'destination provider did not observe the exact remote session'
        time.sleep(.025)


def run(args):
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    source = destination = ssh = None
    runtimes = []
    result = {'checks': [], 'launches': [], 'closure': {}, 'failures': []}
    try:
        helper = Path(__file__).with_name('fresh_conversation_provider.py')
        source = Fixture(args.se, args.output / 'source', provider_helper=helper)
        destination = Fixture(args.se, args.output / 'destination', provider_helper=helper)
        for fixture in (source, destination):
            runtime = private_runtime_directory()
            runtimes.append(runtime)
            configure(fixture, runtime)
        destination.ok('up')
        remote_environment = {**destination.env, 'SE_HOME': str(destination.home)}
        ssh = PrivateSsh.__new__(PrivateSsh)
        ssh.__init__(args.output / 'ssh', destination.root / 'owner', remote_environment)
        source.env['PATH'] = str(ssh.bin) + os.pathsep + source.env['PATH']
        source.ok('up')
        parent = source.ok('--project', source.project, 'launch', source.agent,
                           '--detach', '--task', 'Independent remote launch caller')
        source.session = parent['session_id']
        observation(source, source.session)
        source.ok('remote', 'add', 'isolated-peer', '--name', 'peer')
        ssh.census()
        consent(source)
        ssh.census()
        result['checks'].append('real SSH pairing and native Owner launch consent')
        marker = 'durable-remote-' + uuid.uuid4().hex
        destination.ok('--project', destination.project, 'working-state', 'set', marker,
                       '--agent', destination.agent, '--expect', 'absent')
        mail = destination.mail('send', destination.agent, 'unread-' + marker, '--no-wake')
        target = {'project': destination.project, 'agent': destination.agent}
        selector = destination.project + '/' + destination.agent

        def invoke(door, resume=None, key=None):
            key = key or str(uuid.uuid4())
            if door == 'cli':
                argv = ['--key', key, 'remote', 'launch', '--host', 'peer', '--target', selector]
                if resume is True:
                    argv.append('--resume')
                elif isinstance(resume, str):
                    argv.append('--resume=' + resume)
                response = source.ok(*argv)
            else:
                request = {'target': target, 'idempotency_key': key}
                if resume is not None:
                    request['resume'] = resume
                reply = source.rpc('stateengine_remote_launch', {'host': 'peer', 'request': request})
                assert not reply.get('isError'), reply
                response = reply['structuredContent']
            outcome = response['outcome']
            assert outcome['state'] == 'started', response
            receipt = outcome['receipt']
            assert receipt['state'] in ('committed', 'replayed'), receipt
            return key, receipt['value'], response

        def launch(door, resume=None):
            start = time.monotonic_ns()
            key, value, response = invoke(door, resume)
            elapsed = time.monotonic_ns() - start
            ssh.census()
            row = observation(destination, value['session'])
            details = value['details']
            assert details['provider'] == 'claude' and details['resumed'] is (resume is not None), details
            assert details['conversation'] == {'state': 'present', 'value': row['conversation']}, details
            assert details['mail_notifications'] == {'state': 'present', 'value': True}, details
            assert marker in json.dumps(row['working_state']), row
            assert mail['message_id'] in json.dumps(row['unread_mail']), row
            assert row['flag'] == ('--resume' if resume is not None else '--session-id'), row
            result['launches'].append({'door': door, 'selection': resume, 'receipt': response,
                'elapsed_ns': elapsed, 'provider_private_memory': private_bytes(row['native_root_pid']),
                'provider_observation': row})
            return key, value, response

        def stop():
            stopped = destination.ok('--project', destination.project, 'stop', destination.agent)
            assert stopped['complete'] and stopped['population'] == 'empty', stopped

        for door in ('cli', 'mcp'):
            first_key, first, first_response = launch(door)
            stop()
            _, second, _ = launch(door)
            assert second['details']['conversation'] != first['details']['conversation'], 'remote plain launches reused a conversation'
            result['checks'].append(door + ': remote default launches are fresh and retain working state/unread mail')
            _, replay, _ = invoke(door, key=first_key)
            assert replay == first, 'remote receipt replay changed the original conversation or launch settings'
            result['checks'].append(door + ': original remote launch receipt remains exact after a later launch')
            stop()
            _, latest, _ = launch(door, True)
            assert latest['details']['conversation'] == second['details']['conversation']
            stop()
            _, named, _ = launch(door, first['session'])
            assert named['details']['conversation'] == first['details']['conversation']
            result['checks'].append(door + ': remote latest and named resume select the requested conversations')
            stop()
        assert len(result['checks']) == 7, result
    except Exception as error:
        result['failures'].append(type(error).__name__ + ': ' + str(error))
    finally:
        if source is not None:
            try:
                disconnected = source.call('remote', 'disconnect', '--name', 'peer')
                result['closure']['disconnect_exit'] = disconnected.returncode
            except Exception as error:
                result['closure']['disconnect_error'] = str(error)
        for name, fixture in (('source', source), ('destination', destination)):
            if fixture is not None:
                try:
                    fixture.close()
                    result['closure'][name] = {'witnessed': True, 'provider_identities': fixture.processes}
                except Exception as error:
                    result['failures'].append(name + ' closure: ' + str(error))
        if ssh is not None:
            try:
                result['closure']['ssh'] = ssh.close()
            except Exception as error:
                result['failures'].append('SSH closure: ' + str(error))
        for runtime in runtimes:
            if runtime.exists():
                for path in runtime.iterdir():
                    if path.is_dir() and not path.is_symlink() and not any(path.iterdir()):
                        path.rmdir()
                if not any(runtime.iterdir()):
                    runtime.rmdir()
        (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    assert not result['failures'], result['failures']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    run(parser.parse_args())
