"""Time the authenticated public status consumer without census polling delay."""
import json
import subprocess
import sys
import time

from harness_matrix.io import census, require, save


def observe(smoke, number):
    argv = [str(smoke.binary), 'status', '--home', str(smoke.state), '--json', '--no-color',
            '--project', smoke.project]
    started = time.perf_counter_ns()
    child = subprocess.Popen(argv, cwd=smoke.repository, env=smoke.commands.environment,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    failure = None
    try:
        stdout, stderr = child.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        rows = smoke.commands.observer.census() if sys.platform == 'win32' else census()
        current = next((row for row in rows if row['pid'] == child.pid), None)
        require(current and str(smoke.binary).casefold() in current['command'].casefold(),
                'Timed-out owned status command identity is unreadable or changed')
        # Popen retains the exact native handle; only the read-back owned
        # command is terminated, never a process found by executable name.
        child.kill()
        stdout, stderr = child.communicate(timeout=5)
        failure = 'Public status command exceeded thirty seconds'
    elapsed = (time.perf_counter_ns()-started)/1e6
    prefix = smoke.output / f'peer-status-{number}'
    prefix.with_suffix('.stdout').write_bytes(stdout)
    prefix.with_suffix('.stderr').write_bytes(stderr)
    result = dict(ms=elapsed, argv=argv,
                  exit=child.returncode, stdout=stdout.decode(), stderr=stderr.decode(),
                  failure=failure,
                  qualification='Public authenticated status command wall clock, including CLI spawn, native peer proof, reply and rendering; outside census excluded')
    save(prefix.with_suffix('.json'), result)
    require(failure is None and child.returncode == 0,
            'Public authenticated status failed; retained raw command evidence is available')
    require(len(stdout)+len(stderr) <= 8*1024**2,
            'Public authenticated status exceeded its output bound')
    return json.loads(result['stdout']), result
