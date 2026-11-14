"""Real startup refusals after independently witnessed endpoint retention."""
import json
import os
import signal
import subprocess
import time

from control import alive, lease, lease_held, pin, same, send, wait


def trial(args, mode, Fixture):
    root = args.out / mode
    f = Fixture(args.se, root)
    report = {'case': mode, 'qualified': False, 'signals': []}
    host, caller, caller_pin = None, None, None
    try:
        f.env.update(args.private)
        f.launch()
        ready = json.loads((f.repo / 'provider-ready.json').read_text())
        providers = [pin(ready[key]) for key in ['native_root_pid', 'helper_pid']]
        assert all(p and p['state'] != 'Z' for p in providers)
        host = pin(f.ok('up')['process']['pid'])
        record_bytes = (f.home / 'endpoint.json').read_bytes()
        endpoint = json.loads(record_bytes)['address']['path']['units']
        connections, retention = root / 'connections.jsonl', root / 'retention.json'
        bootstraps = root / 'bootstraps.jsonl'
        environment = dict(f.env, LD_PRELOAD=str(args.hook.resolve()),
                           REVIEW_RETAIN_HOME=str(f.home), REVIEW_RETAIN_LOG=str(retention),
                           REVIEW_BOOTSTRAP_LOG=str(bootstraps))
        if mode != 'deadline-after-retention':
            environment['REVIEW_BOOTSTRAP_FAIL'] = '1'
        retry = mode == 'retry-startup-failure'
        if retry:
            environment.update(REVIEW_CONNECT_TARGET=os.fsdecode(bytes(endpoint)),
                               REVIEW_CONNECT_LOG=str(connections))
            send(host, signal.SIGSTOP, report['signals'])
            wait(lambda: same(host, p := pin(host['pid'])) and p['state'] in ('T', 't'))
            assert lease(f.home, True)
        else:
            send(host, signal.SIGKILL, report['signals'])
            wait(lambda: not alive(host))
            wait(lambda: not lease_held(f.home))
        started = time.monotonic()
        with (root / 'up.stdout').open('wb') as out, (root / 'up.stderr').open('wb') as err:
            caller = subprocess.Popen([str(f.se), '--json', '--home', str(f.home), 'up'],
                                      env=environment, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
        caller_pin = wait(lambda: pin(caller.pid))
        if retry:
            wait(lambda: connections.exists() and same(caller_pin, p := pin(caller.pid))
                 and p['state'] in ('T', 't'))
            observed = [json.loads(x) for x in connections.read_text().splitlines()]
            assert len(observed) == 1 and observed[0]['pid'] == caller.pid, observed
            assert (f.home / 'endpoint.json').read_bytes() == record_bytes
            send(host, signal.SIGKILL, report['signals'])
            wait(lambda: not alive(host))
            wait(lambda: not lease_held(f.home))
            send(caller_pin, signal.SIGCONT, report['signals'])
        wait(lambda: caller.poll() is not None or
             (retention.exists() and same(caller_pin, p := pin(caller.pid))
              and p['state'] in ('T', 't')), seconds=15)
        if retention.exists():
            report['retention_barrier'] = json.loads(retention.read_text())
            assert report['retention_barrier']['pid'] == caller.pid
            assert caller.poll() is None and not (f.home / 'endpoint.json').exists()
            retained = list(f.home.glob('endpoint.retained-*.json'))
            assert len(retained) == 1 and retained[0].read_bytes() == record_bytes
            report['retained_endpoint_bytes_verified'] = True
            report['retained_name'] = retained[0].name
            if mode == 'deadline-after-retention':
                # The production CLI's original budget is 30 seconds. Let real
                # monotonic time pass; no clock or deadline value is rewritten.
                time.sleep(max(0, 31 - (time.monotonic() - started)))
            send(caller_pin, signal.SIGCONT, report['signals'])
        else:
            assert retry and args.expect == 'refused', 'retention barrier was not reached'
        caller.wait(timeout=45)
        report['up_exit'] = caller.returncode
        report['elapsed_seconds'] = time.monotonic() - started
        output = (root / 'up.stdout').read_text()
        report['up_reply'] = json.loads(output)
        attempts = [json.loads(line) for line in bootstraps.read_text().splitlines()] if bootstraps.exists() else []
        report['bootstrap_attempts'] = attempts
        report['provider_survival'] = [alive(p) for p in providers]
        assert caller.returncode != 0 and all(report['provider_survival']), report
        if retention.exists():
            assert retained[0].read_bytes() == record_bytes
            assert str(retained[0]) in output, 'refusal omitted the actual retained record path'
            report['reported_retained_path_verified'] = True
            if mode == 'deadline-after-retention':
                assert attempts == [], 'expired request started another bootstrap'
            else:
                assert len(attempts) == 1 and attempts[0]['caller'] == caller.pid, attempts
                assert attempts[0]['result'] == 13 and attempts[0]['child'] == 0, attempts
                assert 'posix_spawn installed runtime bootstrap' in output, 'original startup failure was lost'
        else:
            assert 'state-conflict' in output
            assert (f.home / 'endpoint.json').read_bytes() == record_bytes
            assert attempts == [], 'base authentication refusal started a bootstrap'
        report['ordinary_recovery_after_observation'] = f.ok('up')['process']['pid']
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
            report['resume_join_failure'] = repr(error)
            report['qualified'] = False
        try:
            f.close()
            assert not (f.home / 'endpoint.json').exists()
            assert not lease(f.home, False)
            report['witnessed_shutdown_and_free_lease'] = True
        except Exception as error:
            report['closure_failure'] = repr(error)
            report['qualified'] = False
        (root / 'outside-report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report
