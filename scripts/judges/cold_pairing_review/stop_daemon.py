"""Stop the exact retained fixture sshd through an instance-pinned native handle."""
import json
import os
from pathlib import Path
import select
import signal
import sys

pid, birth, command = int(sys.argv[1]), sys.argv[2], bytes.fromhex(sys.argv[3])
assert os.geteuid() == 0 and pid > 0 and b'sshd_config' in command
fd = os.pidfd_open(pid)
try:
    root = Path('/proc') / str(pid)
    current_birth = (root / 'stat').read_text().rsplit(') ', 1)[1].split()[19]
    current_command = (root / 'cmdline').read_bytes()
    assert current_birth == birth and current_command == command
    signal.pidfd_send_signal(fd, signal.SIGTERM)
    poll = select.poll()
    poll.register(fd, select.POLLIN)
    complete = bool(poll.poll(10000))
    print(json.dumps(dict(pid=pid, birth=birth, command_hex=command.hex(), complete=complete,
        witness='native pidfd exit readiness' if complete else 'no native exit witness')))
    raise SystemExit(0 if complete else 1)
finally:
    os.close(fd)
