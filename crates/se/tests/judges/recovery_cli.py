"""Public recovery after a real killed init, and literal executable remedies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shlex
import sqlite3
import subprocess
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Case:
    def __init__(self, root, se):
        self.root, self.se = root, se
        root.mkdir(mode=0o700)
        self.home = root / 'state'
        self.repo, self.owner = root / 'repo', root / 'owner'
        self.repo.mkdir(mode=0o700)
        self.owner.mkdir(mode=0o700)
        self.marker = self.repo / 'user-work.txt'
        self.marker.write_bytes(b'Existing user work must remain.\n')
        self.marker_hash = digest(self.marker)
        self.env = {'HOME': str(self.owner), 'USERPROFILE': str(self.owner),
                    'PATH': str(se.parent) + ':/home/jimmy/.local/bin:/usr/bin:/bin',
                    'LANG': 'C.UTF-8'}
        self.count = 0

    def argv(self, *args):
        return [str(self.se), '--json', '--home', str(self.home), *args]

    def call(self, *args, success=True):
        self.count += 1
        result = subprocess.run(self.argv(*args), env=self.env, cwd=self.repo,
                                capture_output=True, timeout=90)
        base = self.root / f'call-{self.count:02}'
        base.with_suffix('.stdout').write_bytes(result.stdout)
        base.with_suffix('.stderr').write_bytes(result.stderr)
        assert (result.returncode == 0) == success, (args, result.returncode, result.stderr)
        return json.loads(result.stdout)

    def init(self):
        return ['--key', 'original-init-key', 'init', '--repo', str(self.repo),
                '--name', 'Recovery judge', '--agent', 'Judge', '--provider', 'claude',
                '--model', 'claude-sonnet-5-5']

    def finish(self):
        value = self.call('down')
        assert value['complete']
        assert not (self.home / 'endpoint.json').exists()
        assert digest(self.marker) == self.marker_hash


def killed_init(c):
    with (c.root / 'killed.stdout').open('wb') as out, (c.root / 'killed.stderr').open('wb') as err:
        trace = subprocess.Popen(['strace', '-ff', '-qq', '-yy', '-s', '2048',
            '-e', 'trace=pwrite64', '-e', 'inject=pwrite64:delay_enter=500ms',
            '-o', str(c.root / 'trace'), *c.argv(*c.init())], env=c.env, cwd=c.repo,
            stdout=out, stderr=err)
        deadline = time.monotonic() + 45
        native = None
        while time.monotonic() < deadline:
            traces = list(c.root.glob('trace.*'))
            if any('pwrite64(' in p.read_text(errors='replace') and
                   str(c.home) in p.read_text(errors='replace') for p in traces):
                for child in Path(f'/proc/{trace.pid}/task/{trace.pid}/children').read_text().split():
                    proc = Path('/proc') / child
                    args = (proc / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
                    if args == list(map(os.fsencode, c.argv(*c.init()))):
                        native = proc
                        break
                if native:
                    break
            assert trace.poll() is None, 'init exited before the native write observation'
            time.sleep(.002)
        assert native is not None, 'REFUSE: no exact init at its native SQLite write'
        birth = (native / 'stat').read_text().rsplit(') ', 1)[1].split()[19]
        command = (native / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        assert command == list(map(os.fsencode, c.argv(*c.init())))
        assert (native / 'exe').resolve() == c.se.resolve()
        assert (native / 'stat').read_text().rsplit(') ', 1)[1].split()[19] == birth
        os.kill(int(native.name), signal.SIGKILL)
        assert trace.wait(timeout=10) != 0
    stages = {p.name: digest(p) for p in c.home.glob('.se-stage-*') if p.is_file()}
    assert len(stages) >= 2, 'native crash did not retain both database and journal'
    (c.root / 'kill.json').write_text(json.dumps({'pid': int(native.name), 'birth': birth,
        'command': list(map(os.fsdecode, command)), 'stages': stages}, indent=2))
    configured = c.call(*c.init())
    directories = list(c.home.glob('init-quarantine-*'))
    assert len(directories) == 1
    quarantine = directories[0]
    assert str(quarantine) in json.dumps(configured['changed'])
    assert {p.name: digest(p) for p in quarantine.iterdir()} == stages
    assert not list(c.home.glob('.se-stage-*'))
    again = c.call(*c.init())
    assert again['owner']['human_id'] == configured['owner']['human_id']
    assert list(c.home.glob('init-quarantine-*')) == directories
    c.finish()


def block(text, kind):
    marker = 'COMMANDS' if kind == 'RESTORE' else 'COMMAND'
    found = re.findall(rf'(?m)^BEGIN SE {kind} {marker}\n(.*?)\nEND SE {kind} {marker}$',
                       text, flags=re.DOTALL)
    assert len(found) == 1, 'REFUSE: marked command block absent or ambiguous'
    return found[0]


def literal_restore(c):
    original = c.call(*c.init())
    c.finish()
    saved = c.root / 'closed copy'
    saved.mkdir(mode=0o700)
    (c.home / 'state.db').rename(saved / 'state.db')
    source_hash = digest(saved / 'state.db')
    old = {'state.db-wal': b'old retained WAL bytes', 'state.db-shm': b'old retained SHM bytes'}
    for name, data in old.items():
        (c.home / name).write_bytes(data)
        (c.home / name).chmod(0o600)
    refused = c.call('status', success=False)
    assert refused['code'] == 'state-conflict' and not (c.home / 'state.db').exists()
    remedy = refused['remedy']['text']
    run = subprocess.run(['/bin/sh', '-c', block(remedy, 'RESTORE')], input=(str(saved) + '\n').encode(),
        env=c.env, cwd=c.repo, capture_output=True, timeout=90)
    (c.root / 'restore.stdout').write_bytes(run.stdout)
    (c.root / 'restore.stderr').write_bytes(run.stderr)
    assert run.returncode == 0, run.stderr
    assert c.call('status')['setup']['state'] == 'configured'
    assert digest(saved / 'state.db') == source_hash
    preserved = list(c.home.glob('recovery-sidecars-*'))
    assert len(preserved) == 1
    assert {p.name: p.read_bytes() for p in preserved[0].iterdir()} == old
    fresh = subprocess.run(['/bin/sh', '-c', block(remedy, 'FRESH')], env=c.env, cwd=c.repo,
        capture_output=True, timeout=90)
    (c.root / 'fresh.stdout').write_bytes(fresh.stdout)
    (c.root / 'fresh.stderr').write_bytes(fresh.stderr)
    assert fresh.returncode == 0, fresh.stderr
    fresh_args = shlex.split(block(remedy, 'FRESH'))
    fresh_home = Path(fresh_args[fresh_args.index('--home') + 1])
    with sqlite3.connect(f'file:{fresh_home / "state.db"}?mode=ro', uri=True) as reader:
        assert reader.execute('select human_id from owners').fetchall() != [(original['owner']['human_id'],)]
    assert not (c.repo / 'INJECTED').exists(), 'printed command executed a path fragment'
    c.finish()


def linked_stage(c):
    c.call(*c.init())
    outside = c.root / 'outside.txt'
    outside.write_bytes(b'foreign retained bytes')
    link = c.home / ('.se-stage-' + 'b' * 32)
    link.symlink_to(outside)
    c.call(*c.init(), success=False)
    assert link.is_symlink() and outside.read_bytes() == b'foreign retained bytes'
    assert not list(c.home.glob('init-quarantine-*'))
    link.unlink()
    c.finish()



def setup_hint(c):
    absent = c.call('resume', success=False)
    assert absent['code'] == 'setup-required'
    text = absent['remedy']['text']
    assert text.startswith('Run se ')
    script = text.removeprefix('Run ')
    words = shlex.split(script)
    assert words[words.index('--home') + 1] == str(c.home)
    assert words[words.index('--repo') + 1] == str(c.repo)
    result = subprocess.run(['/bin/sh', '-c', script], env=c.env, cwd=c.repo,
                            capture_output=True, timeout=90)
    (c.root / 'hint.stdout').write_bytes(result.stdout)
    (c.root / 'hint.stderr').write_bytes(result.stderr)
    assert result.returncode == 0, result.stderr
    assert c.call('status')['setup']['state'] == 'configured'
    c.finish()
    c.home = c.root / 'line\nbreak'
    refused = c.call('resume', success=False)
    assert refused['code'] == 'setup-required'
    assert not refused['remedy']['text'].startswith('Run se ')
    assert not c.home.exists()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    rows = []
    for name, operation in [('native-kill', killed_init), ("O’Brien's $(touch INJECTED)", literal_restore),
                            ('linked-stage', linked_stage), ("hint O’Brien's $(touch INJECTED)", setup_hint)]:
        case = Case(args.out / name, args.se.resolve())
        try:
            operation(case)
            rows.append({'case': name, 'passed': True})
        except Exception as error:
            rows.append({'case': name, 'passed': False, 'failure': repr(error)})
            (args.out / 'results.json').write_text(json.dumps(rows, indent=2))
            raise
        (args.out / 'results.json').write_text(json.dumps(rows, indent=2))
        print('ok - ' + name, flush=True)
    print('4/4 independent recovery consumers passed', flush=True)


if __name__ == '__main__':
    main()
