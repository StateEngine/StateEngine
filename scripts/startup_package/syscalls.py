"""Follow only selected syscalls, and join the tracer after public shutdown."""
import json
from pathlib import Path
import re
import subprocess
import time

from harness_matrix.io import require, save


def capture(smoke, argv, environment):
    number = len(list(smoke.output.glob('syscalls-*.stdout')))
    prefix = smoke.output / f'syscalls-{number}'
    output, errors = prefix.with_suffix('.stdout'), prefix.with_suffix('.stderr')
    command = ['strace', '--seccomp-bpf', '-ff', '-ttt', '-T', '-yy', '-s', '1024',
               '-o', str(prefix.with_suffix('.log')), '-e',
               'trace=execve,fsync,fdatasync,futex,poll,ppoll,clock_nanosleep,recvmsg,sendmsg',
               '-e', 'raw=recvmsg,sendmsg', *argv]
    started = time.perf_counter_ns()
    with output.open('xb') as out, errors.open('xb') as err:
        child = subprocess.Popen(command, cwd=smoke.repository, env=environment,
                                 stdin=subprocess.DEVNULL, stdout=out, stderr=err)
    smoke.startup_tracer = dict(child=child, prefix=prefix, errors=errors)
    smoke.commands.observer.observe(child.pid)
    until = time.monotonic() + 30
    while time.monotonic() < until:
        require(output.stat().st_size + errors.stat().st_size <= 2 * 1024**2,
                'Startup syscall observer output exceeded its bound')
        for path in smoke.output.glob(prefix.name + '.log.*'):
            require(path.stat().st_size <= 16 * 1024**2, 'Syscall trace exceeded its bound')
            text = path.read_text()
            first = text.splitlines()[0] if text else ''
            # Each traced process has a separate file. Identify the public CLI
            # by its exact argv prefix, rather than assuming the lowest PID.
            expected = f'execve({json.dumps(argv[0])}, [{json.dumps(argv[0])}, "up",'
            if expected not in first:
                continue
            exited = re.search(r'\+\+\+ exited with ([0-9]+) \+\+\+', text)
            if exited:
                stdout, stderr = output.read_text(), errors.read_text()
                code = int(exited[1])
                require(code == 0, 'Traced public up failed: ' + stderr)
                json.loads(stdout)
                value = dict(ms=(time.perf_counter_ns()-started)/1e6, exit=code,
                             stdout=stdout, stderr=stderr, traced=True,
                             syscall_root_file=path.name,
                             timing='upper bound through outside observation of public CLI exit; syscall diagnostic only')
                save(smoke.output / 'last-up.json', value)
                return value
        if child.poll() is not None:
            raise RuntimeError('Syscall tracer exited before a successful CLI observation: '
                               + errors.read_text())
        time.sleep(.002)
    raise RuntimeError('Traced public up exceeded its 30-second observation bound')


def join(smoke):
    trace = getattr(smoke, 'startup_tracer', None)
    if trace is None:
        return
    child = trace['child']
    code = child.wait(timeout=10)
    text = trace['errors'].read_text()
    save(trace['prefix'].with_suffix('.json'), dict(tracer_exit=code, stderr=text,
         joined_after_public_down=True))
    require(code == 0, 'Startup syscall tracer failed after shutdown')
    require('seccomp-bpf is not' not in text and 'seccomp filter failed' not in text,
            'Kernel syscall filtering was unavailable; no low-overhead diagnostic is claimed')
    del smoke.startup_tracer
