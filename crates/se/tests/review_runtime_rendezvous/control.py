"""Independent real endpoint/authentication window and held-lease consumers."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


def stat(pid):
    try:
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
    except FileNotFoundError:
        return None
    return {'pid': pid, 'birth': fields[19], 'state': fields[0],
            'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def pin(pid):
    for _ in range(3):
        result = stat(pid)
        if result is None or result['state'] == 'Z':
            return result
        try:
            result['image'] = os.readlink(f'/proc/{pid}/exe')
            result['argv'] = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')[:-1]
            result['argv'] = [os.fsdecode(x) for x in result['argv']]
        except FileNotFoundError:
            after = stat(pid)
            if after is None or after['state'] == 'Z':
                return after
            continue
        after = stat(pid)
        if same(result, after) and after['state'] != 'Z':
            return result
        if after is None or after['state'] == 'Z':
            return after
    raise RuntimeError(f'native process image remained unreadable or unstable: {pid}')


def same(a, b):
    return b is not None and all(a[k] == b[k] for k in ['pid', 'birth', 'boot'])


def alive(receipt):
    current = pin(receipt['pid'])
    return same(receipt, current) and current['state'] != 'Z'


def send(receipt, number, events):
    current = pin(receipt['pid'])
    if not same(receipt, current) or current['state'] == 'Z':
        return
    assert current['image'] == receipt['image'] and current['argv'] == receipt['argv'], current
    final = pin(receipt['pid'])
    if not same(receipt, final) or final['state'] == 'Z':
        return
    assert final['image'] == receipt['image'] and final['argv'] == receipt['argv'], final
    events.append({'signal': number, 'receipt': current})
    try:
        os.kill(receipt['pid'], number)
    except ProcessLookupError:
        assert not alive(receipt), 'signal failed while original process remains live'


def lease_held(home):
    with (home / 'runtime.lock').open('rb') as file:
        try:
            fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        else:
            fcntl.flock(file, fcntl.LOCK_UN)
            return False


def lease(home, expected_held):
    actual = lease_held(home)
    assert actual == expected_held, {'expected_held': expected_held, 'held': actual}
    return actual


def wait(predicate, seconds=10):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        result = predicate()
        if result:
            return result
        time.sleep(.005)
    raise TimeoutError('bounded reviewer condition was not witnessed')


def trial(args, name, held, Fixture):
    root = args.out / name
    f = Fixture(args.se, root)
    report = {'case': name, 'held': held, 'qualified': False, 'signals': []}
    host, caller, caller_pin = None, None, None
    try:
        f.env.update(args.private)
        f.launch()
        ready = json.loads((f.repo / 'provider-ready.json').read_text())
        providers = [pin(ready[key]) for key in ['native_root_pid', 'helper_pid']]
        assert all(p and p['state'] != 'Z' for p in providers), providers
        before = f.ok('up')
        host = pin(before['process']['pid'])
        assert host and host['image'] == str(args.se.resolve()), host
        record_bytes = (f.home / 'endpoint.json').read_bytes()
        record = json.loads(record_bytes)
        address = record['address']
        assert address['kind'] == 'unix_socket' and address['path']['encoding'] == 'unix_bytes', address
        endpoint = os.fsdecode(bytes(address['path']['units']))
        events = root / 'connections.jsonl'
        environment = dict(f.env, LD_PRELOAD=str(args.hook.resolve()),
                           REVIEW_CONNECT_TARGET=endpoint, REVIEW_CONNECT_LOG=str(events))
        # A stopped real owner retains its actual lease and listening socket.
        send(host, signal.SIGSTOP, report['signals'])
        wait(lambda: same(host, p := pin(host['pid'])) and p['state'] in ('T', 't'))
        assert lease(f.home, True)
        with (root / 'up.stdout').open('wb') as out, (root / 'up.stderr').open('wb') as err:
            caller = subprocess.Popen([str(f.se), '--json', '--home', str(f.home), 'up'],
                                      env=environment, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
        caller_pin = wait(lambda: pin(caller.pid))
        wait(lambda: events.exists() and same(caller_pin, p := pin(caller.pid)) and p['state'] in ('T', 't'))
        connections = [json.loads(x) for x in events.read_text().splitlines()]
        assert len(connections) == 1 and connections[0]['pid'] == caller.pid, connections
        assert connections[0]['result'] == 0 or connections[0]['errno'] == 115, connections
        report['route_then_connect_before_auth'] = connections
        assert (f.home / 'endpoint.json').read_bytes() == record_bytes
        if not held:
            # The call has routed and connected to this exact old owner, but has
            # not yet authenticated. Kill only that recorded native birth.
            send(host, signal.SIGKILL, report['signals'])
            wait(lambda: not alive(host))
            # Native process exit and release of the kernel-held file lease are
            # separate observations. Do not interpret one as the other.
            wait(lambda: not lease_held(f.home))
            assert not lease(f.home, False)
        send(caller_pin, signal.SIGCONT, report['signals'])
        caller.wait(timeout=45)
        report['up_exit'] = caller.returncode
        output = (root / 'up.stdout').read_text()
        report['up_reply'] = json.loads(output)
        report['all_connections'] = [json.loads(x) for x in events.read_text().splitlines()]
        report['provider_survival'] = [alive(p) for p in providers]
        assert all(report['provider_survival']), 'up/crash stopped a preserved provider'
        if held:
            assert caller.returncode != 0, report
            assert 'state-conflict' in output, output
            assert len(report['all_connections']) == 1, 'held lease was retried'
            assert alive(host) and lease(f.home, True)
            assert (f.home / 'endpoint.json').read_bytes() == record_bytes
            send(host, signal.SIGCONT, report['signals'])
        elif args.expect == 'recovered':
            assert caller.returncode == 0, report
            replacement = pin(report['up_reply']['process']['pid'])
            assert replacement and not same(host, replacement), replacement
            assert replacement['image'] == host['image'], replacement
            report['replacement'] = replacement
            recovery = report['up_reply'].get('endpoint_recovery')
            assert recovery is not None, 'retry discarded its stale-endpoint recovery receipt'
            retained = recovery['retained']
            assert retained['encoding'] == 'unix_bytes', retained
            retained_path = Path(os.fsdecode(bytes(retained['units'])))
            assert retained_path.is_relative_to(f.home), retained_path
            assert retained_path.read_bytes() == record_bytes, 'retained endpoint bytes changed'
            report['retained_endpoint_bytes_verified'] = True
        else:
            assert caller.returncode != 0 and 'state-conflict' in output, report
        # Ordinary recovery after the expected base refusal permits ordinary
        # shutdown. Provider survival was already read back before this command.
        recovered = f.ok('up')
        report['ordinary_recovery_after_observation'] = recovered['process']['pid']
        assert all(alive(p) for p in providers)
        report['qualified'] = True
    except Exception as error:
        report['failure'] = repr(error)
    finally:
        try:
            if host and alive(host):
                send(host, signal.SIGCONT, report['signals'])
            if caller and caller.poll() is None:
                if caller_pin:
                    send(caller_pin, signal.SIGCONT, report['signals'])
                try:
                    caller.wait(timeout=40)
                except subprocess.TimeoutExpired:
                    send(caller_pin, signal.SIGKILL, report['signals'])
                    caller.wait(timeout=5)
        except Exception as error:
            report['qualified'] = False
            report['resume_join_failure'] = repr(error)
        try:
            f.close()
            assert not (f.home / 'endpoint.json').exists()
            assert not lease(f.home, False)
            report['witnessed_shutdown_and_free_lease'] = True
        except Exception as error:
            report['qualified'] = False
            report['closure_failure'] = repr(error)
        (root / 'outside-report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--hook', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--expect', choices=['refused', 'recovered'], required=True)
    args = parser.parse_args()
    assert sys.platform == 'linux'
    os.umask(0o077)
    args.out.mkdir(mode=0o700)
    runtime = Path(tempfile.mkdtemp(prefix='se-rendezvous-', dir='/tmp'))
    args.private = {'XDG_RUNTIME_DIR': str(runtime)}
    for key in ['XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'CODEX_HOME']:
        path = args.out / key.lower()
        path.mkdir(mode=0o700)
        args.private[key] = str(path)
    sys.path.insert(0, str(args.source / 'crates/se/tests/judges'))
    from mail_cli import Fixture as PublicFixture

    class Fixture(PublicFixture):
        def call(self, *arguments, **options):
            self.env.update(args.private)
            return super().call(*arguments, **options)

    reports = []
    for i in range(3):
        reports.append(trial(args, f'window-{i}', False, Fixture))
    reports.append(trial(args, 'held-lease', True, Fixture))
    from failures import trial as failure_trial
    for mode in ['first-startup-failure', 'retry-startup-failure', 'deadline-after-retention']:
        reports.append(failure_trial(args, mode, Fixture))
    (args.out / 'summary.json').write_text(json.dumps(reports, indent=2) + '\n')
    assert all(r['qualified'] for r in reports), 'one or more independent controls failed'


if __name__ == '__main__':
    main()
