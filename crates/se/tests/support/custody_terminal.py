"""Linux console consumer; all subprocesses have an explicit deadline and identity."""
import os
import pty
import select
import signal
import subprocess
import sys
import time

image, home = sys.argv[1:3]
budget = min(30, float(sys.argv[3]) / 1000 if len(sys.argv) > 3 else 30)
if budget <= 0:
    raise TimeoutError('public owner command exceeded deadline before launch')
deadline = time.monotonic() + budget
env = {key: value for key, value in os.environ.items()
       if not key.startswith(('SE_', 'STATEENGINE_', 'CODEX_')) and key != 'CLAUDECODE'}
# Optional arguments let other owner-only CLI judges reuse this native terminal.
args = [image, '--json', '--home', home, *(sys.argv[4:] or ['uninstall'])]
master, slave = pty.openpty()
child = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=slave,
                         env=env, start_new_session=True)
os.close(slave)
# An immediately completed child may already be gone; no signal is then needed.
try:
    birth = open(f'/proc/{child.pid}/stat', encoding='utf-8').read().rsplit(')', 1)[1].split()[19]
except FileNotFoundError:
    if child.poll() is None:
        raise
    birth = None
data = bytearray()
try:
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError('public owner command exceeded deadline')
        if select.select([master], [], [], .05)[0]:
            try:
                part = os.read(master, 4096)
            except OSError as error:
                if error.errno != 5:
                    raise
                break
            if not part:
                break
            data.extend(part)
            if len(data) > 262144:
                raise RuntimeError('public owner command exceeded output budget')
        if child.poll() is not None:
            # Drain the final PTY bytes before interpreting the child's exit.
            if not select.select([master], [], [], 0)[0]:
                break
    result = child.wait(timeout=3)
except BaseException:
    if child.poll() is None:
        actual = open(f'/proc/{child.pid}/cmdline', 'rb').read().split(b'\0')[:-1]
        current = open(f'/proc/{child.pid}/stat', encoding='utf-8').read().rsplit(')', 1)[1].split()[19]
        if birth is None or actual != [os.fsencode(arg) for arg in args] or current != birth:
            raise RuntimeError('owned child identity changed; refusing signal')
        os.kill(child.pid, signal.SIGKILL)
        child.wait(timeout=3)
    raise
finally:
    os.close(master)
    sys.stdout.buffer.write(data)
sys.exit(result)
