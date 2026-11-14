"""Outside native observer for the finite Git process tree; no PID-only kills."""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time


class BsdInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in (
        'flags', 'status', 'xstatus', 'pid', 'ppid', 'uid', 'gid', 'ruid',
        'rgid', 'svuid', 'svgid', 'reserved')]
    _fields_ += [('comm', ctypes.c_char * 16), ('name', ctypes.c_char * 32)]
    _fields_ += [(name, ctypes.c_uint32) for name in (
        'nfiles', 'pgid', 'pjobc', 'e_tdev', 'e_tpgid', 'nice')]
    _fields_ += [('seconds', ctypes.c_uint64), ('micros', ctypes.c_uint64)]


NATIVE = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
NATIVE.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                               ctypes.c_void_p, ctypes.c_int]
NATIVE.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
NATIVE.proc_listchildpids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
BOOT = subprocess.check_output(['sysctl', '-n', 'kern.bootsessionuuid'], text=True).strip()


def observe(pid):
    value = BsdInfo()
    ctypes.set_errno(0)
    count = NATIVE.proc_pidinfo(pid, 3, 1, ctypes.byref(value), ctypes.sizeof(value))
    cause = ctypes.get_errno()
    if count == 0 and cause == errno.ESRCH:
        return None
    if count != ctypes.sizeof(value):
        raise RuntimeError(f'unreadable native process {pid}: {count}/{cause}')
    if value.pid != pid or value.micros >= 1_000_000:
        raise RuntimeError('invalid native process receipt')
    result = {name: getattr(value, name) for name in (
        'pid', 'ppid', 'uid', 'status', 'seconds', 'micros')}
    if value.status != 5:
        path = ctypes.create_string_buffer(4096)
        length = NATIVE.proc_pidpath(pid, path, len(path))
        if length <= 0:
            raise RuntimeError(f'unreadable native image {pid}: {ctypes.get_errno()}')
        result['image'] = os.fsdecode(path.value)
    return result


def same(receipt, current):
    return current is not None and all(receipt[k] == current[k] for k in (
        'pid', 'uid', 'seconds', 'micros'))


def children(pid):
    values = (ctypes.c_int * 64)()
    ctypes.set_errno(0)
    count = NATIVE.proc_listchildpids(pid, values, ctypes.sizeof(values))
    cause = ctypes.get_errno()
    if count < 0 or count >= len(values) or (count == 0 and cause not in (0, errno.ESRCH)):
        raise RuntimeError('unreadable or over-bound child inventory')
    return list(values)[:count]


def atomic_json(path, data):
    temporary = path.with_suffix('.pending')
    temporary.write_text(json.dumps(data, indent=2) + '\n')
    temporary.replace(path)


class Trial:
    def __init__(self, parent, name, config, driver, probe, clean, meter):
        self.root = parent / name
        self.root.mkdir(mode=0o700)
        self.helper = self.root / 'driver'
        shutil.copyfile(driver, self.helper)
        self.helper.chmod(0o700)
        atomic_json(self.root / 'config.json', config)
        self.probe = self.root / 'probe-first'
        shutil.copyfile(probe, self.probe)
        self.probe.chmod(0o700)
        self.config, self.clean_probe, self.clean, self.meter = config, probe, clean, meter
        self.pins = {}
        self.max_bytes = 0
        self.samples = 0
        self.git_executed = False
        self.events = []
        self.host = None
        self.report = {'case': name, 'qualified': False, 'config': config}

    def remember(self, value):
        key = f"{value['pid']}:{value['seconds']}:{value['micros']}"
        self.pins[key] = value

    def tick(self):
        if self.host is None:
            return
        pending = [self.host.pid]
        for _ in range(3):
            following = []
            for pid in pending:
                value = observe(pid)
                if value is None:
                    continue
                if value.get('image') not in self.images():
                    if value['status'] != 5:
                        raise RuntimeError(f'unexpected image in owned tree: {value}')
                self.remember(value)
                self.git_executed |= value.get('image') == str(self.probe)
                following.extend(children(pid))
            pending = following
        total = 0
        for pin in list(self.pins.values()):
            current = observe(pin['pid'])
            if same(pin, current) and current['status'] != 5 and current['pid'] != self.host.pid:
                amount = self.meter.review_peak(pin['pid'])
                if amount != 2**64 - 1:
                    total += amount
        self.max_bytes = max(self.max_bytes, total)
        self.samples += 1

    def wait(self, predicate, seconds=8):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.tick()
            value = predicate()
            if value:
                return value
            time.sleep(0.005)
        raise TimeoutError(f"fixture condition not reached in {self.root.name}")

    def signal(self, pin, number):
        current = observe(pin['pid'])
        if not same(pin, current) or current['status'] == 5:
            return
        command = subprocess.check_output(['ps', '-ww', '-p', str(pin['pid']), '-o', 'command='], text=True).strip()
        assert current['image'] in self.images(), current
        assert current['image'] in command, command
        assert subprocess.check_output(['sysctl', '-n', 'kern.bootsessionuuid'], text=True).strip() == BOOT
        assert same(pin, observe(pin['pid'])), 'native birth changed before signal'
        self.events.append({'signal': number, 'receipt': current, 'full_command': command})
        os.kill(pin['pid'], number)

    def images(self):
        return (str(self.helper), str(self.clean), str(self.probe), str(self.clean_probe))

    def alive(self, pin):
        current = observe(pin['pid'])
        return same(pin, current) and current['status'] != 5

    def custody(self):
        path = self.root / '.se-atlas-git-review/.git-custody.json'
        return json.loads(path.read_text()) if path.exists() else None

    def role(self, role):
        for value in list(self.pins.values()):
            current = observe(value['pid'])
            if same(value, current) and current['status'] != 5:
                command = subprocess.check_output(['ps', '-ww', '-p', str(value['pid']), '-o', 'command='], text=True)
                if role in command:
                    return current
        return None

    def reconcile(self):
        with (self.root / 'reconcile.stdout').open('w') as stdout, (self.root / 'reconcile.stderr').open('w') as stderr:
            process = subprocess.run([str(self.helper), 'reconcile'], stdout=stdout, stderr=stderr, timeout=5)
        assert process.returncode == 0, 'reconciler fixture failed before reporting'
        return json.loads((self.root / 'reconcile.json').read_text())

    def result(self):
        path = self.root / 'host-result.json'
        return json.loads(path.read_text()) if path.exists() else None

    def run(self):
        with (self.root / 'host.stdout').open('w') as stdout, (self.root / 'host.stderr').open('w') as stderr:
            self.host = subprocess.Popen([str(self.helper), 'host', str(self.probe), str(self.clean), str(self.clean_probe)], stdout=stdout, stderr=stderr)
        self.remember(self.wait(lambda: observe(self.host.pid)))
        stage = self.config.get('death_stage')
        if stage:
            self.death(stage, self.config['victim'])
        else:
            self.ordinary()

    def ordinary(self):
        result = self.wait(self.result, 15)
        self.report['consumer'] = result
        mode = self.config['mode']
        first, second = result['first'], result['second']
        fault = self.config.get('fault')
        if fault == 'kill-denied':
            assert not first['ok'] and 'cleanup unresolved' in first['reason'], first
            assert not second['ok'] and 'not been exactly reaped' in second['reason'], second
            assert self.custody() is not None, 'failed reap discarded durable custody'
            self.signal(self.pins[next(k for k, p in self.pins.items() if p['pid'] == self.host.pid)], signal.SIGKILL)
            self.host.wait(timeout=3)
            reconciled = self.reconcile()
            assert reconciled['ok'], reconciled
            self.report['failed_reap_recovery'] = reconciled
        else:
            assert second['ok'] and second['success'], second
            assert first['child_wait']['result'] == -1 and first['child_wait']['errno'] == errno.ECHILD, first
            if fault in ('first-unreadable', 'first-over-budget'):
                assert not first['ok'] and not self.git_executed, first
            elif mode == '0':
                assert first['ok'] and first['success'], first
                limits = json.loads(first['stdout'])
                self.report['inherited_limits'] = limits
                assert limits['cpu_soft'] <= self.config.get('cpu', 900)
                assert limits['cpu_hard'] <= self.config.get('cpu', 900)
                assert limits['fd_soft'] <= self.config.get('fds', 64)
                assert limits['fd_hard'] <= self.config.get('fds', 64)
            elif mode == '1':
                assert first['ok'] and not first['success'] and first['signal'] in (signal.SIGXCPU, signal.SIGKILL), first
            elif mode == '2':
                assert not first['ok'] and ('footprint budget' in first['reason'] or 'OutOfMemory' == first.get('kind')), first
            elif mode == '3':
                assert not first['ok'] and first['kind'] == 'TimedOut', first
            else:
                assert not first['ok'] and 'output overflow' in first['reason'], first
            self.host.wait(timeout=3)
            assert self.host.returncode == 0
            assert not (self.root / '.se-atlas-git-review/.git-custody.json').exists()
            assert not (self.root / '.se-atlas-git-review/.git-intent.json').exists()
            assert self.reconcile()['ok']

    def death(self, stage, victim):
        if stage == 'before-release':
            bootstrap = self.wait(lambda: self.role('--private-atlas-git-bootstrap'))
            bootstrap = self.wait(lambda: (p if (p := observe(bootstrap['pid'])) and p['status'] == 4 else None))
            supervisor = self.wait(lambda: self.role('--private-atlas-git-supervisor'))
            assert self.custody() is None, 'pre-release fixture passed the durable barrier'
        else:
            record = self.wait(self.custody)
            supervisor = self.wait(lambda: self.role('--private-atlas-git-supervisor'))
            self.wait(lambda: (p if (p := observe(record['git']['pid'])) and p.get('image') == str(self.probe) else None))
        host = self.wait(lambda: observe(self.host.pid))
        if victim == 'both':
            self.signal(supervisor, signal.SIGSTOP)
        if victim in ('host', 'both'):
            self.signal(host, signal.SIGKILL)
        if victim in ('supervisor', 'both'):
            self.signal(supervisor, signal.SIGKILL)
        if stage == 'before-release':
            self.signal(bootstrap, signal.SIGCONT)
        if victim == 'supervisor':
            result = self.wait(self.result)
            self.report['consumer'] = result
            assert not result['first']['ok'], result
            if stage == 'before-release':
                assert not result['second']['ok'] and 'not been exactly reaped' in result['second']['reason'], result
            else:
                assert result['second']['ok'] and result['second']['success'], result
            self.host.wait(timeout=3)
            assert self.host.returncode == 0
        else:
            self.host.wait(timeout=3)
            assert self.host.returncode == -signal.SIGKILL
        if stage == 'after-release' and victim == 'both':
            residual = observe(record['git']['pid'])
            assert residual is not None and residual['status'] != 5, 'residual recovery path was not exercised'
            self.report['observed_post_owner_death_residual'] = residual
            assert self.custody() is not None
            assert self.reconcile()['ok']
        else:
            self.wait(lambda: all(not self.alive(p) for p in list(self.pins.values())))
            reconciled = self.reconcile()
            self.report['reconcile'] = reconciled
            if stage == 'before-release':
                assert not self.git_executed
                assert not reconciled['ok'] and 'no complete native child receipt' in reconciled['reason'], reconciled
                assert (self.root / '.se-atlas-git-review/.git-intent.json').exists()
            else:
                assert reconciled['ok'], reconciled

    def close(self):
        errors = []
        for path in self.root.glob('fault-events-*.jsonl'):
            try:
                events = [json.loads(x) for x in path.read_text().splitlines()]
            except Exception as error:
                errors.append(str(error))
                continue
            self.report.setdefault('fault_events', []).extend(events)
            for event in events:
                if event['kind'] == 'child':
                    current = observe(event['pid'])
                    if current is not None and all(current[k] == event[k] for k in ('seconds','micros')):
                        if current['status'] != 5:
                            assert current['image'] in self.images(), current
                        self.remember(current)
        fault = self.config.get('fault')
        if fault:
            if not any(x['kind'] == fault for x in self.report.get('fault_events', [])):
                errors.append('native fault was not exercised')
        sampled = [x for x in self.report.get('fault_events', []) if x['kind'] == 'first-native-sample']
        self.report['first_native_sample_delays_ms'] = [
            (x['wall_ns'] - x['actor_birth_ns']) / 1_000_000 for x in sampled]
        self.report['sampling_measurement_limits'] = (
            'Native instrumentation includes its own bounded event-write overhead; '
            'the outside peak and overshoot are observed lower bounds, not an upper guarantee.')
        live = [pin for pin in self.pins.values() if self.alive(pin)]
        self.report['live_before_external_cleanup'] = live
        if live:
            errors.append('product left a live owned instance before judge cleanup')
        # Direct host is reaped only by its creator. Other instances are observed
        # externally and never assigned a made-up wait status.
        for pin in list(self.pins.values()):
            try:
                if self.alive(pin):
                    self.signal(pin, signal.SIGKILL)
            except Exception as error:
                errors.append(str(error))
        if self.host is not None:
            try:
                self.host.wait(timeout=3)
            except Exception as error:
                errors.append(str(error))
        end = time.monotonic() + 3
        while any(self.alive(p) for p in self.pins.values()) and time.monotonic() < end:
            time.sleep(0.005)
        self.report.update(native_receipts=list(self.pins.values()), signals=self.events,
                           outside_observed_peak_bytes=self.max_bytes,
                           observed_overshoot_lower_bound=max(0, self.max_bytes - 64_000_000),
                           outside_samples=self.samples,
                           final_states=[{'receipt':p,'current':observe(p['pid'])} for p in self.pins.values()],
                           closure_errors=errors)
        assert not errors and all(not self.alive(p) for p in self.pins.values()), self.report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--meter', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(mode=0o700)
    clean_root = args.out / 'clean'
    clean_root.mkdir(mode=0o700)
    clean = clean_root / 'driver'
    shutil.copyfile(args.driver, clean)
    clean.chmod(0o700)
    atomic_json(clean_root / 'config.json', {})
    meter = ctypes.CDLL(str(args.meter), use_errno=True)
    meter.review_peak.argtypes = [ctypes.c_int]
    meter.review_peak.restype = ctypes.c_uint64
    cases = [('success', {'mode':'0'}), ('deadline', {'mode':'3','deadline_ms':2000}),
             ('stdout-overflow', {'mode':'4'}), ('stderr-overflow', {'mode':'5'}),
             ('memory-growth', {'mode':'2'}),
             ('first-unreadable', {'mode':'0','fault':'first-unreadable'}),
             ('first-over-budget', {'mode':'0','fault':'first-over-budget'}),
             ('lowered-limits', {'mode':'0','fds':48,'cpu':32}),
             ('cpu-limit', {'mode':'1','cpu':2,'deadline_ms':10000}),
             ('failed-reap', {'mode':'3','deadline_ms':2000,'fault':'kill-denied'})]
    for stage in ['before-release','after-release']:
        for victim in ['host','supervisor','both']:
            cases.append((stage+'-'+victim, {'mode':'3','death_stage':stage,'victim':victim,
                                            'pause_bootstrap':stage=='before-release'}))
    reports = []
    for name, specific in cases:
        config = {'mode':'0','deadline_ms':5000, **specific}
        trial = Trial(args.out, name, config, args.driver, args.probe, clean, meter)
        try:
            trial.run()
            trial.report['qualified'] = True
        except Exception as error:
            trial.report['failure'] = repr(error)
        finally:
            try:
                trial.close()
            except Exception as error:
                trial.report['qualified'] = False
                trial.report['closure_failure'] = repr(error)
            atomic_json(trial.root / 'outside-report.json', trial.report)
            reports.append(trial.report)
            atomic_json(args.out / 'summary.json', reports)
    if not all(x['qualified'] for x in reports):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
