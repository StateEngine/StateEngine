"""Public cold pairing on one hosted runner, with fresh source and destination accounts."""
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import socket
import statistics
import subprocess
import sys
import time

root = Path(sys.argv[1]).resolve()
base, head = map(lambda value: Path(value).resolve(), sys.argv[2:4])
root.mkdir()
private = root / 'private'
private.mkdir(mode=0o700)
receipt = dict(samples=[], failures=[], source_images={}, qualified=False, scope='Hosted Linux loopback SSH; pretrusted host key, fresh OS accounts and repositories, cached file pages; sudo/env spawn included; 200 ms native process sampler active; providers not launched')
for side, binary in (('base', base), ('head', head)):
    receipt['source_images'][side] = dict(path=str(binary), bytes=binary.stat().st_size, sha256=hashlib.file_digest(binary.open('rb'), 'sha256').hexdigest())


def command(argv, destination=None, **kwargs):
    owned_uid = kwargs.pop('owned_uid', None)
    started = time.perf_counter_ns()
    child = subprocess.Popen(list(map(str, argv)), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    timed_out = False
    timeout_cleanup = None
    try:
        stdout, stderr = child.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        timed_out = True
        if owned_uid is None:
            raise
        cleanup = subprocess.run(['sudo', '-n', sys.executable, Path(__file__).with_name('native_owners.py'), str(owned_uid)],
            capture_output=True, timeout=20)
        timeout_cleanup = dict(exit=cleanup.returncode, stdout=cleanup.stdout.decode(), stderr=cleanup.stderr.decode())
        stdout, stderr = child.communicate(timeout=10)
    elapsed = (time.perf_counter_ns() - started) / 1e6
    row = dict(argv=list(map(str, argv)), exit=child.returncode, elapsed_ms=elapsed,
        stdout=stdout.decode(), stderr=stderr.decode(), timed_out=timed_out, timeout_cleanup=timeout_cleanup)
    if destination:
        destination.write_text(json.dumps(row, indent=2) + '\n')
    return row


def must(argv, **kwargs):
    row = command(argv, **kwargs)
    assert row['exit'] == 0, row
    return row


def sudo(*argv):
    return must(['sudo', '-n', *argv])


def install(source, target, user, mode):
    sudo('install', '-m', mode, '-o', user, '-g', user, source, target)


def invocation(user, home, argv, explicit_state=False):
    env = ['env', '-i', 'HOME=' + str(home), 'USER=' + user, 'LOGNAME=' + user,
           'PATH=/usr/local/bin:/usr/bin:/bin', 'SHELL=/bin/bash']
    if explicit_state:
        env += ['XDG_CONFIG_HOME=' + str(home / '.config'), 'XDG_STATE_HOME=' + str(home / '.local/state'),
                'XDG_DATA_HOME=' + str(home / '.local/share'), 'XDG_CACHE_HOME=' + str(home / '.cache')]
    env += ['XDG_RUNTIME_DIR=' + str(home / 'runtime')]
    return ['sudo', '-n', '-u', user, *env, *map(str, argv)]


def close(user, uid, folder):
    row = command(['sudo', '-n', sys.executable, Path(__file__).with_name('native_owners.py'), uid], folder / (user + '-outside.json'))
    native = json.loads(row['stdout'])
    assert row['exit'] == 0 and native['complete'] and native['remaining'] == []
    sudo('userdel', '-r', user)
    try:
        pwd.getpwnam(user)
    except KeyError:
        return dict(user=user, uid=uid, native=native, account_absent=True)
    raise AssertionError('Owned test account survived removal')


def down(user, home, image, folder, explicit):
    argv = [image, '--json']
    if explicit:
        argv += ['--home', home / 'state']
    row = command(invocation(user, home, [*argv, 'down'], explicit), folder / (user + '-public-down.json'), owned_uid=pwd.getpwnam(user).pw_uid)
    body = json.loads(row['stdout'])
    assert row['exit'] == 0 and body['complete'] and body['witness']['state'] == 'witnessed'
    assert isinstance(body['stops'], list) and all(stop['complete'] for stop in body['stops'])
    return body


must(['ssh-keygen', '-t', 'ed25519', '-N', '', '-f', private / 'host-key'])
must(['ssh-keygen', '-t', 'ed25519', '-N', '', '-f', private / 'client-key'])
with socket.socket() as probe:
    probe.bind(('127.0.0.1', 0))
    port = probe.getsockname()[1]
config = private / 'sshd_config'
pidfile = private / 'sshd.pid'
config.write_text(f'Port {port}\nListenAddress 127.0.0.1\nHostKey {private / "host-key"}\nPidFile {pidfile}\nPasswordAuthentication no\nPubkeyAuthentication yes\nUsePAM yes\nPermitRootLogin no\nPermitUserEnvironment yes\nAllowTcpForwarding yes\nAllowUsers se418*\n')
sudo('mkdir', '-p', '/run/sshd')
sudo('env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', '/usr/sbin/sshd', '-f', config)
daemon = int(pidfile.read_text())
daemon_cmd = sudo('cat', f'/proc/{daemon}/cmdline')['stdout']
assert str(config) in daemon_cmd
daemon_stat = sudo('cat', f'/proc/{daemon}/stat')['stdout'].rsplit(') ', 1)[1].split()
daemon_birth = daemon_stat[19]
host_public = (private / 'host-key.pub').read_text().split()
count = int(os.environ.get('PAIRING_ROUNDS', '20'))
try:
    for index in range(count):
        for side, binary in ((('base', base), ('head', head)) if index % 2 == 0 else (('head', head), ('base', base))):
            folder = root / f'{index:02d}-{side}'
            folder.mkdir()
            tag = f'{os.getpid() % 100000}{index:02d}{side[0]}'
            users = [('se418s' + tag), ('se418d' + tag)]
            owned = []
            row = dict(index=index, side=side, exit=None, wall_ms=None, closures=[], failures=[])
            receipt['samples'].append(row)
            try:
                for user in users:
                    try:
                        pwd.getpwnam(user)
                        raise RuntimeError('Fresh test account already exists')
                    except KeyError:
                        pass
                    sudo('useradd', '-m', '-s', '/bin/bash', user)
                    entry = pwd.getpwnam(user)
                    owned.append((user, entry.pw_uid, Path(entry.pw_dir)))
                source_user, source_uid, source_home = owned[0]
                dest_user, dest_uid, dest_home = owned[1]
                for user, uid, home in owned:
                    sudo('install', '-d', '-m', '700', '-o', user, '-g', user, home / '.ssh')
                    sudo('install', '-d', '-m', '700', '-o', user, '-g', user, home / 'runtime')
                install(private / 'client-key', source_home / '.ssh/id_pair', source_user, '600')
                authorized = folder / 'authorized_keys'
                authorized.write_text('environment="XDG_RUNTIME_DIR=' + str(dest_home / 'runtime') + '" ' + (private / 'client-key.pub').read_text())
                install(authorized, dest_home / '.ssh/authorized_keys', dest_user, '600')
                known = folder / 'known_hosts'
                known.write_text(f'[{"127.0.0.1"}]:{port} {host_public[0]} {host_public[1]}\n')
                install(known, source_home / '.ssh/known_hosts', source_user, '600')
                alias = folder / 'ssh-config'
                alias.write_text(f'Host pairdest\n HostName 127.0.0.1\n Port {port}\n User {dest_user}\n IdentityFile {source_home / ".ssh/id_pair"}\n IdentitiesOnly yes\n StrictHostKeyChecking yes\n BatchMode yes\n')
                install(alias, source_home / '.ssh/config', source_user, '600')
                checked_environment = must(invocation(source_user, source_home, ['ssh', 'pairdest', 'env']), destination=folder / 'destination-environment.json', owned_uid=source_uid)
                remote_environment = dict(line.split('=', 1) for line in checked_environment['stdout'].splitlines() if '=' in line)
                assert remote_environment['HOME'] == str(dest_home) and remote_environment['XDG_RUNTIME_DIR'] == str(dest_home / 'runtime')
                image = source_home / 'se'
                install(binary, image, source_user, '700')
                repo = source_home / 'repository'
                must(invocation(source_user, source_home, ['git', 'init', '--initial-branch=measurement', repo], True))
                text = folder / 'work.txt'
                text.write_text('Unchanged test repository content\n')
                install(text, repo / 'work.txt', source_user, '600')
                must(invocation(source_user, source_home, ['git', '-C', repo, 'add', '--', 'work.txt'], True))
                must(invocation(source_user, source_home, ['git', '-C', repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'Initial test repository.', '--', 'work.txt'], True))
                init = must(invocation(source_user, source_home, [image, '--home', source_home / 'state', '--json', 'init', '--repo', repo, '--agent', 'main', '--provider', 'claude'], True), destination=folder / 'public-init.json', owned_uid=source_uid)
                stop_sample = folder / 'sample-stop'
                with (folder / 'sampler.stderr').open('w') as sampler_errors:
                    sampler = subprocess.Popen(['sudo', '-n', sys.executable, str(Path(__file__).with_name('profile_sample.py')),
                        str(folder / 'profile.jsonl'), str(stop_sample), str(source_uid), str(dest_uid)],
                        stdout=subprocess.DEVNULL, stderr=sampler_errors)
                    try:
                        paired = command(invocation(source_user, source_home, [image, '--home', source_home / 'state', '--json', 'remote', 'add', 'pairdest', '--name', 'loop'], True), folder / 'public-pair.json', owned_uid=source_uid)
                    finally:
                        stop_sample.touch()
                        assert sampler.wait(timeout=10) == 0, 'Native profile sampler did not join successfully'
                row['sampler_joined'] = True
                row['wall_ms'] = paired['elapsed_ms']
                row['exit'] = paired['exit']
                body = json.loads(paired['stdout'])
                assert not paired['timed_out'] and paired['exit'] == 0 and body['schema'] == 'stateengine.remote-control/v1' and body['value']['state'] == 'connected'
                remote = dest_home / '.stateengine-runtime' / receipt['source_images'][side]['sha256'] / 'se'
                native_hash = sudo('sha256sum', remote)['stdout'].split()[0]
                assert native_hash == receipt['source_images'][side]['sha256']
                row['published_sha256'] = native_hash
                row['source_down'] = down(source_user, source_home, image, folder, True)
                row['destination_down'] = down(dest_user, dest_home, remote, folder, False)
                row['connected'] = True
            except BaseException as error:
                row['failures'].append(repr(error))
            finally:
                for user, uid, home in owned:
                    try:
                        row['closures'].append(close(user, uid, folder))
                    except BaseException as error:
                        row['failures'].append(repr(error))
                (folder / 'sample.json').write_text(json.dumps(row, indent=2) + '\n')
                (root / 'summary.json').write_text(json.dumps(receipt, indent=2) + '\n')
            if row['failures']:
                receipt['failures'].append(dict(index=index, side=side, failures=row['failures']))
                raise RuntimeError('Hosted first consumer or closure failed; later attempts not started')
    receipt['arms'] = {}
    for side in ('base', 'head'):
        values = sorted(row['wall_ms'] for row in receipt['samples'] if row['side'] == side)
        assert len(values) == count
        receipt['arms'][side] = dict(count=count, p50_ms=statistics.median(values), p95_ms=values[math.ceil(.95 * count) - 1], max_ms=max(values))
    receipt['head_tail_bound_ms'] = 6500
    receipt['head_within_bound'] = receipt['arms']['head']['max_ms'] <= 6500
    receipt['qualified'] = True
finally:
    stop = command(['sudo', '-n', sys.executable, Path(__file__).with_name('stop_daemon.py'), daemon,
        daemon_birth, daemon_cmd.encode().hex()], root / 'sshd-closure.json')
    receipt['sshd_closure'] = json.loads(stop['stdout'])
    assert stop['exit'] == 0 and receipt['sshd_closure']['complete']
    (root / 'summary.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps({key: value for key, value in receipt.items() if key != 'samples'}))
