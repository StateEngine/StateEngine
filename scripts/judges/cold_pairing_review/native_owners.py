"""Reap only exact native instances belonging to freshly created test accounts."""
import json
import os
from pathlib import Path
import pwd
import select
import signal
import sys
import time

uid = int(sys.argv[1])
assert os.geteuid() == 0 and uid >= 1000
assert pwd.getpwuid(uid).pw_name.startswith('se418')


def read(pid):
    root = Path('/proc') / str(pid)
    try:
        fields = (root / 'stat').read_text().rsplit(') ', 1)[1].split()
        owner = next(int(line.split()[1]) for line in (root / 'status').read_text().splitlines() if line.startswith('Uid:'))
        raw = (root / 'cmdline').read_bytes()
    except (FileNotFoundError, ProcessLookupError):
        return None
    assert len(raw) <= 1024 * 1024, 'Native command exceeds retained bound'
    return dict(pid=pid, uid=owner, birth=fields[19], state=fields[0], command_hex=raw.hex())


def inventory():
    rows = []
    for path in Path('/proc').iterdir():
        if path.name.isdigit():
            row = read(int(path.name))
            if row and row['uid'] == uid:
                rows.append(row)
    return rows


report = dict(uid=uid, signals=[], refused=[])
for sig, seconds in ((signal.SIGTERM, 3), (signal.SIGKILL, 10)):
    for row in inventory():
        if row['state'] in ('Z', 'X', 'x'):
            continue
        if not row['command_hex']:
            report['refused'].append(dict(before=row, reason='Unreadable live full command'))
            continue
        try:
            fd = os.pidfd_open(row['pid'])
        except ProcessLookupError:
            continue
        try:
            current = read(row['pid'])
            if current is None:
                continue
            if any(current[key] != row[key] for key in ('uid', 'birth', 'command_hex')):
                report['refused'].append(dict(before=row, after=current, reason='Native instance changed'))
                continue
            try:
                signal.pidfd_send_signal(fd, sig)
                report['signals'].append(dict(before=row, signal=int(sig)))
            except ProcessLookupError:
                pass
        finally:
            os.close(fd)
    end = time.monotonic() + seconds
    while inventory() and time.monotonic() < end:
        time.sleep(0.05)
    if not inventory():
        break
report['remaining'] = inventory()
report['complete'] = not report['remaining'] and not report['refused']
print(json.dumps(report))
raise SystemExit(0 if report['complete'] else 1)
