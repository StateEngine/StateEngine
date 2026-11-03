"""Linux console consumer; all subprocesses have an explicit deadline and identity."""
import os
import pty
import select
import signal
import subprocess
import sys
import time

image, home = sys.argv[1:]
env = {key: value for key, value in os.environ.items()
       if not key.startswith(('SE_', 'STATEENGINE_', 'CODEX_')) and key != 'CLAUDECODE'}
args = [image, '--json', '--home', home, 'uninstall']
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
deadline = time.monotonic() + 30
data = bytearray()
try:
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError('public uninstall exceeded deadline')
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
                raise RuntimeError('public uninstall exceeded output budget')
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
