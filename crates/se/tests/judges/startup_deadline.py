"""Observe public CLI startup under an owned Linux CPU quota.

python3 startup_deadline.py --se SHIPPED_SE --output NEW_DIRECTORY --quota 25
For the ratified incomplete/recovery case, use --quota 1 --expect pending.
For a real native listener-bind failure, use --quota 100 --expect refusal.
Retains readiness, typed refusals, live progress and
outside cleanup separately; a progressing child is never labeled a clean refusal.
Uses a native provider double, without a provider account or deadline changes.
"""
import argparse
import fcntl
import hashlib
import json
import os
import socket
import tomllib
from pathlib import Path
import subprocess
import tempfile
import time
import traceback
import uuid

from judge_records import wait_json
from mail_cli import Fixture
from startup_contract import pending_recovery, native_refusal, release_scope_quota
from directory_owner import DirectoryOwner


def native(pid):
    try:
        root = Path('/proc') / str(pid)
        fields = (root / 'stat').read_text().rsplit(')', 1)[1].split()
        return {'pid': pid, 'birth': fields[19], 'state': fields[0],
                'argv': (root / 'cmdline').read_bytes().replace(b'\0', b' ').decode()}
    except (FileNotFoundError, ProcessLookupError):
        return None


def exited(pin):
    now = native(pin['pid'])
    return now is None or now['birth'] != pin['birth'] or now['state'] in ('Z', 'X')


def provider(path):
    source = Path(__file__).with_name('mail_provider.py').read_text()
    anchor = '    flag = "--resume"'
    assert source.count(anchor) == 1, 'native provider argument anchor missing'
    source = source.replace(anchor, '''    if "--safe-mode" in arguments:
        request = json.loads(sys.stdin.readline())
        assert request["request"]["subtype"] == "get_settings"
        print(json.dumps({"type":"control_response", "response":{
            "request_id":"settings", "subtype":"success", "response":{
            "effective":{}, "sources":[], "errors":[]}}}), flush=True)
        return
''' + anchor, 1)
    anchor = '    conversation = arguments[arguments.index(flag) + 1]'
    assert source.count(anchor) == 1, 'provider conversation anchor missing'
    source = source.replace(anchor, anchor + '\n' + """    with (cwd / "provider-starts.jsonl").open("a") as starts:
        starts.write(json.dumps({"pid":os.getpid(), "conversation":conversation}) + "\\n")
""", 1)
    path.write_text(source)


def run_case(image, directory, control_env, quota, expect):
    directory.mkdir(mode=0o700)
    runtime = Path(tempfile.mkdtemp(prefix='startup-runtime-', dir=os.environ.get('TMPDIR')))
    print("fixture root (retained on failed or interrupted closure):", runtime, flush=True)
    root_owner = DirectoryOwner(runtime)
    isolated = {'XDG_RUNTIME_DIR': str(runtime)}
    for name in ['XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME']:
        path = directory / name.lower()
        path.mkdir(mode=0o700)
        isolated[name] = str(path)

    class PrivateFixture(Fixture):
        def call(self, *arguments, **options):
            self.env.update(isolated)
            return super().call(*arguments, **options)

    helper = directory / 'provider.py'
    provider(helper)
    f = PrivateFixture(image, directory / 'home', provider_helper=helper)
    subprocess.run(['git', 'init', '--quiet', str(f.repo)], env=f.env, check=True)
    occupied = None
    if expect == 'refusal':
        config = tomllib.loads((f.home / 'config.toml').read_text())
        occupied = socket.socket()
        occupied.bind(('127.0.0.1', config['runtime']['listen_port']))
        occupied.listen()
    key, task = 'startup-' + uuid.uuid4().hex, 'Startup regression'
    unit = 'se-startup-judge-' + uuid.uuid4().hex + '.scope'
    command = [str(f.se), '--json', '--home', str(f.home), '--project', f.project,
               '--key', key, 'launch', f.agent, '--detach', '--task', task]
    launcher = ['systemd-run', '--user', '--scope', '--quiet', '--unit=' + unit,
                '--property=CPUQuota=' + str(quota) + '%', '/usr/bin/env',
                'XDG_RUNTIME_DIR=' + str(runtime), *command]
    pins, samples = {}, []
    retry_groups = []
    endpoint_seen = None
    cgroup = None
    run = None
    result = {'home_bytes': len(os.fsencode(f.home)), 'unit': unit, 'quota_percent': quota, 'passed': False}
    result.update(expected=expect, request_key=key)

    def track(pid, required=True):
        pin = native(pid)
        if required:
            assert pin is not None, 'native process exited before its outside identity read'
        if pin is not None:
            pins[(pid, pin['birth'])] = pin
        return pin

    def release_quota():
        release_scope_quota(unit, cgroup, list(pins.values()), control_env, exited, result)

    started = time.monotonic()
    try:
        with (directory / 'launch.stdout').open('wb') as out, (directory / 'launch.stderr').open('wb') as err:
            launcher_env = {**f.env, 'XDG_RUNTIME_DIR': control_env['XDG_RUNTIME_DIR'],
                            'DBUS_SESSION_BUS_ADDRESS': control_env['DBUS_SESSION_BUS_ADDRESS']}
            run = subprocess.Popen(launcher, env=launcher_env, stdout=out, stderr=err)
            exited_at = None
            while True:
                elapsed = time.monotonic() - started
                assert elapsed < 90, 'CLI launch exceeded the judge bound'
                if run.poll() is not None and exited_at is None:
                    exited_at = elapsed
                    result['cli_seconds'] = elapsed
                    result['live_at_cli_exit'] = [pin for pin in pins.values() if not exited(pin)]
                if exited_at is not None and (run.returncode == 0 or elapsed - exited_at >= 10):
                    break
                if cgroup is None:
                    shown = subprocess.run(['systemctl', '--user', 'show', unit, '--property=ControlGroup', '--value'],
                                           env=control_env, capture_output=True, text=True, timeout=5)
                    if shown.returncode == 0 and shown.stdout.strip():
                        cgroup = Path('/sys/fs/cgroup') / shown.stdout.strip().lstrip('/')
                        assert cgroup.resolve().is_relative_to('/sys/fs/cgroup')
                        quota_us, period = (cgroup / 'cpu.max').read_text().split()
                        assert quota_us != 'max' and int(quota_us) * 100 == int(period) * result['quota_percent'], 'owned CPU quota was not applied'
                        result['cpu_max'] = [int(quota_us), int(period)]
                if endpoint_seen is None and (f.home / 'endpoint.json').exists():
                    endpoint_seen = elapsed
                if cgroup is not None and (cgroup / 'cgroup.procs').exists():
                    for pid in map(int, (cgroup / 'cgroup.procs').read_text().split()):
                        pin = native(pid)
                        if pin is None or not pin['argv']:
                            continue
                        pins[(pid, pin['birth'])] = pin
                        if '--stateengine-private-runtime-bootstrap' not in pin['argv']:
                            continue
                        sample = {'seconds': time.monotonic() - started, **pin, 'image_offsets': []}
                        try:
                            fields = (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
                            sample['cpu_ticks'] = int(fields[11]) + int(fields[12])
                        except (FileNotFoundError, ProcessLookupError):
                            sample['cpu_ticks'] = None
                        try:
                            descriptors = list((Path('/proc') / str(pid) / 'fd').iterdir())
                        except (FileNotFoundError, ProcessLookupError):
                            descriptors = []
                        for fd in descriptors:
                            try:
                                if fd.readlink() == image:
                                    info = (fd.parent.parent / 'fdinfo' / fd.name).read_text()
                                    position = next(line[4:].strip() for line in info.splitlines() if line.startswith('pos:'))
                                    sample['image_offsets'].append(int(position))
                            except (FileNotFoundError, ProcessLookupError):
                                pass
                        samples.append(sample)
                time.sleep(0.1)
            result['exit'] = run.returncode
        result['seconds'] = time.monotonic() - started
        assert cgroup is not None and result.get('cpu_max'), 'owned CPU scope was not witnessed'
        result['native_samples'] = len(samples)
        result['endpoint_first_seen_seconds'] = endpoint_seen
        hashing = [sample for sample in samples if sample['image_offsets']]
        result['self_hash_observation'] = {
            'sample_interval_seconds': 0.1,
            'first_seconds': hashing[0]['seconds'] if hashing else None,
            'last_seconds': hashing[-1]['seconds'] if hashing else None,
            'max_offset_bytes': max((offset for sample in hashing for offset in sample['image_offsets']), default=None),
            'image_size_bytes': image.stat().st_size,
            'note': 'Observed file positions bound the sampled phase; they are not an exact hash duration.'}
        stdout = (directory / 'launch.stdout').read_text()
        stderr = (directory / 'launch.stderr').read_text()
        launched = json.loads(stdout)
        result['reply'] = launched
        if run.returncode == 0:
            assert expect == 'ready', 'required pending/refusal control was not reached'
            assert launched['state'] == 'running', launched
            ready = wait_json(f.repo / 'provider-ready.json')
            assert ready['session_discovery'] and ready['http_discovery'], ready
            assert ready['conversation'] == launched['conversation_id'], (ready, launched)
            for pid in [ready['native_root_pid'], ready['helper_pid']]:
                pin = native(pid)
                assert pin is not None, 'provider exited before its outside identity read'
                pins[(pid, pin['birth'])] = pin
            result['outcome'] = 'ready'
            result['passed'] = True
        else:
            assert launched['schema'] == 'se.error/v1' and launched['exit'] == run.returncode, launched
            live = [pin for pin in result['live_at_cli_exit']
                    if '--stateengine-private-runtime-bootstrap' in pin['argv']]
            after = [sample for sample in samples if sample['seconds'] >= result['cli_seconds']]
            offsets = [offset for sample in after for offset in sample['image_offsets']]
            result['progress_after_refusal'] = len(set(offsets)) > 1
            near = [sample for sample in samples
                    if result['cli_seconds'] - 2 <= sample['seconds'] <= result['cli_seconds']]
            positions = [offset for sample in near for offset in sample['image_offsets']]
            result['hash_progress_near_refusal'] = len(set(positions)) > 1
            result['outcome'] = ('refused-with-live-startup' if live else 'refused')
            result['failure'] = stderr
            if expect == 'pending':
                pending_recovery(f, launched, stderr, key, task, release_quota, track, result, control_env, retry_groups)
                result['outcome'] = 'incomplete-recovered-and-replayed'
                result['passed'] = True
            elif expect == 'refusal':
                native_refusal(f, launched, stderr)
                result['outcome'] = 'genuine-native-refusal'
                result['passed'] = True
    except Exception:
        result['failure'] = traceback.format_exc()
    finally:
        if occupied is not None:
            occupied.close()
        # Release only this exercise's quota after recording the outcome. This
        # lends cleanup CPU without changing the startup observation or clocks.
        try:
            released = subprocess.run(['systemctl', '--user', 'set-property', unit, 'CPUQuota=100%'],
                                      env=control_env, capture_output=True, timeout=5)
            result['cleanup_quota_exit'] = released.returncode
            if run is not None and run.poll() is None:
                try:
                    run.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    result['launcher_cleanup_wait_expired'] = True
            stopped = f.call('down')
            result['down_exit'] = stopped.returncode
            until = time.monotonic() + 30
            while not all(exited(pin) for pin in pins.values()) and time.monotonic() < until:
                time.sleep(0.1)
            outside = [{'pid': pin['pid'], 'birth': pin['birth'], 'not_executing': exited(pin)} for pin in pins.values()]
            remaining = (cgroup / 'cgroup.procs').read_text().split() if cgroup and (cgroup / 'cgroup.procs').exists() else []
            result['outside'] = outside
            for group in retry_groups:
                if (group / 'cgroup.procs').exists():
                    remaining.extend((group / 'cgroup.procs').read_text().split())
            result['scope_remaining_pids'] = remaining
            result['retry_scopes'] = [str(group) for group in retry_groups]
            result['endpoint_absent'] = not (f.home / 'endpoint.json').exists()
            with (f.home / 'runtime.lock').open('rb') as lease:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result['lease_free'] = True
            result['cleanup_complete'] = (stopped.returncode == 0 and result['endpoint_absent']
                                          and not remaining and all(item['not_executing'] for item in outside))
            result['passed'] = result['passed'] and result['cleanup_complete']
            if result['cleanup_complete']:
                try:
                    root_owner.remove()
                except OSError as error:
                    result['runtime_directory_cleanup'] = str(error)
                    result['cleanup_complete'] = False
                    result['passed'] = False
        except Exception:
            result['cleanup_complete'] = False
            result['passed'] = False
            result['cleanup_failure'] = traceback.format_exc()
        (directory / 'samples.json').write_text(json.dumps(samples, indent=2))
        (directory / 'result.json').write_text(json.dumps(result, indent=2))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expect', choices=['ready', 'pending', 'refusal'], default='ready')
    parser.add_argument('--quota', type=int, default=25, metavar='PERCENT')
    args = parser.parse_args()
    if not 1 <= args.quota <= 100:
        parser.error('--quota must be an integer from 1 to 100')
    assert os.name == 'posix' and Path('/proc').is_dir(), 'requires native Linux and a systemd user manager'
    os.umask(0o077)
    args.se = args.se.resolve(strict=True)
    args.output = args.output.resolve()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    with args.se.open('rb') as image:
        image_hash = hashlib.file_digest(image, 'sha256').hexdigest()
    for name in list(os.environ):
        if name.startswith(('SE_', 'STATEENGINE_', 'CODEX_', 'CLAUDE', 'OPENAI', 'ANTHROPIC')) or any(
                marker in name for marker in ['TOKEN', 'SECRET', 'API_KEY']):
            del os.environ[name]
    control_env = {**os.environ, 'XDG_RUNTIME_DIR': '/run/user/' + str(os.getuid()),
                   'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/' + str(os.getuid()) + '/bus'}
    results = []
    for label in ['short', 'long-' + 'x' * 70]:
        result = run_case(args.se, args.output / label, control_env, args.quota, args.expect)
        results.append(result)
        print(('ok' if result['passed'] else 'not ok'), len(results), '-', label.split('-')[0], flush=True)
    assert results[1]['home_bytes'] - results[0]['home_bytes'] >= 64, 'long/short home control collapsed'
    with args.se.open('rb') as image:
        assert hashlib.file_digest(image, 'sha256').hexdigest() == image_hash, 'image changed during the judge'
    report = {'image_sha256': image_hash,
              'cache_control': 'Fresh homes; no global cache eviction. Image binding reads the image before the cases.',
              'cases': results, 'passed': sum(item['passed'] for item in results),
              'failed': sum(not item['passed'] for item in results)}
    (args.output / 'result.json').write_text(json.dumps(report, indent=2))
    print('1..2', flush=True)
    assert report['failed'] == 0, 'public CLI startup contract failed; see retained outcomes and cleanup'


if __name__ == '__main__':
    main()
