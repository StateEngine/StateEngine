"""Public startup incomplete/retry checks shared by the Linux quota judge."""
import json
from pathlib import Path
import subprocess
import time
import uuid


def release_scope_quota(unit, group, pins, control_env, exited, result):
    released = subprocess.run(['systemctl', '--user', 'set-property', unit, 'CPUQuota=100%'],
                              env=control_env, capture_output=True, timeout=5)
    result['recovery_quota_exit'] = released.returncode
    if released.returncode == 0:
        result['recovery_scope'] = 'quota released'
        return
    assert group is not None, 'owned recovery scope identity was not witnessed'
    try:
        members = (group / 'cgroup.procs').read_text().split()
    except FileNotFoundError:
        try:
            group.stat()
        except FileNotFoundError:
            members = None
        else:
            raise AssertionError('owned scope exists but its membership is unreadable')
    shown = subprocess.run(['systemctl', '--user', 'show', unit, '--property=LoadState',
                            '--property=ActiveState', '--property=ControlGroup'],
                           env=control_env, capture_output=True, text=True, timeout=5)
    state = dict(line.split('=', 1) for line in shown.stdout.splitlines() if '=' in line)
    outside = [{'pid': pin['pid'], 'birth': pin['birth'], 'not_executing': exited(pin)}
               for pin in pins]
    result['recovery_settled_scope'] = {'path': str(group), 'members': members,
                                       'unit': state, 'outside': outside}
    assert members in (None, []), 'owned scope is live and its recovery quota could not be released'
    assert all(pin['not_executing'] for pin in outside), 'owned startup birth still executes after quota failure'
    missing = state.get('LoadState') == 'not-found' and state.get('ActiveState') == 'inactive'
    inactive = (shown.returncode == 0 and state.get('LoadState') == 'loaded'
                and state.get('ActiveState') in ['inactive', 'failed']
                and state.get('ControlGroup') in ['', '/' + str(group.relative_to('/sys/fs/cgroup'))])
    assert missing or inactive, 'owned scope state is unreadable or not settled after quota failure'
    result['recovery_scope'] = 'proven absent' if members is None else 'proven empty'


def same_request(argv, f, key, task):
    assert argv and argv[0] == 'se', 'recovery is not a literal se command'
    values, positional, flags = {}, [], []
    tokens = iter(argv[1:])
    for token in tokens:
        if token in ['--home', '--project', '--key', '--task']:
            assert token not in values, 'duplicate recovery selector'
            values[token] = next(tokens)
        elif token in ['--json', '--detach']:
            assert token not in flags, 'duplicate recovery flag'
            flags.append(token)
        else:
            positional.append(token)
    assert values == {'--home': str(f.home), '--project': f.project,
                      '--key': key, '--task': task}, values
    assert positional == ['launch', f.agent] and '--detach' in flags, argv


def agent(f):
    status = f.ok('--project', f.project, 'status')
    assert status['agents']['window']['complete'], 'agent status window incomplete'
    return status, next(row for row in status['agents']['items'] if row['id'] == f.agent)


def retry(f, argv, label, control_env, track, groups):
    unit = 'se-startup-retry-' + uuid.uuid4().hex + '.scope'
    launcher = ['systemd-run', '--user', '--scope', '--quiet', '--unit=' + unit,
                '/usr/bin/env', 'XDG_RUNTIME_DIR=' + f.env['XDG_RUNTIME_DIR'],
                str(f.se), *argv[1:]]
    environment = {**f.env, 'XDG_RUNTIME_DIR': control_env['XDG_RUNTIME_DIR'],
                   'DBUS_SESSION_BUS_ADDRESS': control_env['DBUS_SESSION_BUS_ADDRESS']}
    group = None
    until = time.monotonic() + 90
    outpath, errpath = f.root / (label + '.stdout'), f.root / (label + '.stderr')
    with outpath.open('wb') as out, errpath.open('wb') as err:
        run = subprocess.Popen(launcher, env=environment, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
        while run.poll() is None:
            assert time.monotonic() < until, 'advertised retry exceeded the judge bound'
            if group is None:
                shown = subprocess.run(['systemctl', '--user', 'show', unit, '--property=ControlGroup', '--value'],
                                       env=control_env, capture_output=True, text=True, timeout=5)
                if shown.returncode == 0 and shown.stdout.strip():
                    group = Path('/sys/fs/cgroup') / shown.stdout.strip().lstrip('/')
                    assert group.resolve().is_relative_to('/sys/fs/cgroup')
                    groups.append(group)
            if group is not None and (group / 'cgroup.procs').exists():
                for pid in map(int, (group / 'cgroup.procs').read_text().split()):
                    track(pid, required=False)
            time.sleep(0.1)
    assert group is not None, 'retry CPU scope was not observed'
    return subprocess.CompletedProcess(argv, run.returncode, outpath.read_bytes(), errpath.read_bytes())


def pending_recovery(f, reply, stderr, key, task, release_quota, track, result, control_env, groups):
    assert reply['code'] == 'runtime-start-pending' and reply['class'] == 'incomplete', reply
    assert reply['exit'] == 2, reply
    assert 25_000 <= reply['detail']['waited_ms'] <= 45_000, 'incomplete startup did not consume its thirty-second budget'
    assert 25 <= result['cli_seconds'] <= 60, 'measured CLI elapsed does not match the thirty-second startup budget'
    human = (reply['message'] + '\n' + reply['remedy']['text']).lower()
    for text in [human, stderr.lower()]:
        assert 'slow' in text and 'nothing was lost' in text, text
        assert 'unreadable' not in text, text
    assert reply['retry']['kind'] != 'never', 'incomplete startup forbids its own retry'
    logs = [p for p in f.home.glob('runtime-startup-*.log')
            if str(p).lower() in human and p.is_file() and not p.is_symlink() and p.stat().st_size]
    assert len(logs) == 1, 'no single readable startup log advertised for this home'
    result['advertised_log'] = str(logs[0])
    command = reply['remedy']['command']
    assert command['kind'] == 'se', command
    argv = command['argv']
    same_request(argv, f, key, task)
    assert not (f.repo / 'provider-ready.json').exists(), 'task already reached a provider'
    assert not (f.repo / 'provider-starts.jsonl').exists(), 'provider started before incomplete response'
    status, row = agent(f)
    assert row['session']['session_id'] is None and row['conversation']['id'] is None, row
    result['unsubmitted_readback'] = row
    # Simulate the machine becoming available. No down, manual repair, new key,
    # argument rewrite or extra startup is inserted before the advertised retry.
    release_quota()
    result['recovery_argv'] = argv
    replies = []
    for label in ['retry', 'replay']:
        run = retry(f, argv, label, control_env, track, groups)
        assert run.returncode == 0, (label, run.stdout, run.stderr)
        status, row = agent(f)
        assert status['runtime']['state'] == 'running', status['runtime']
        track(status['runtime']['process']['pid'])
        ready = json.loads((f.repo / 'provider-ready.json').read_text())
        assert ready['session_discovery'] and ready['http_discovery'], ready
        assert row['conversation']['id'] == ready['conversation'], (row, ready)
        assert row['session']['session_id'] is not None, row
        for pid in [ready['native_root_pid'], ready['helper_pid']]:
            track(pid)
        starts = [json.loads(line) for line in (f.repo / 'provider-starts.jsonl').read_text().splitlines()]
        assert len(starts) == 1 and starts[0]['conversation'] == ready['conversation'], starts
        replies.append({'session': row['session']['session_id'], 'conversation': ready['conversation']})
    assert replies[0] == replies[1], 'same-key replay created another session or conversation'
    result['recovery_readbacks'] = replies


def native_refusal(f, reply, stderr):
    assert reply['exit'] != 0 and reply['class'] != 'incomplete', reply
    assert reply['code'] != 'runtime-start-pending', reply
    logs = '\n'.join(p.read_text() for p in f.home.glob('runtime-startup-*.log'))
    text = (json.dumps(reply) + stderr + logs).lower()
    assert any(cause in text for cause in ['address already in use', 'address in use', 'os error 98']), text
    assert not (f.repo / 'provider-starts.jsonl').exists(), 'native bind refusal still submitted the task'
