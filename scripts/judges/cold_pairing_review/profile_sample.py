"""Observe only the two fixture accounts; never use a sample to authorize a signal."""
import json
from pathlib import Path
import sys
import time

output, stop = map(Path, sys.argv[1:3])
uids = set(map(int, sys.argv[3:5]))
started = time.monotonic_ns()
with output.open('x') as stream:
    while not stop.exists():
        rows, omissions = [], []
        for path in Path('/proc').iterdir():
            if not path.name.isdigit():
                continue
            try:
                owner = next(int(line.split()[1]) for line in (path / 'status').read_text().splitlines() if line.startswith('Uid:'))
                if owner not in uids:
                    continue
                stat = (path / 'stat').read_text().rsplit(') ', 1)[1].split()
                command = (path / 'cmdline').read_bytes()
                assert len(command) <= 1024 * 1024
                io = {}
                for line in (path / 'io').read_text().splitlines():
                    key, value = line.split(':', 1)
                    io[key] = int(value)
                rows.append(dict(pid=int(path.name), uid=owner, birth=stat[19], state=stat[0],
                    utime=int(stat[11]), stime=int(stat[12]), command_hex=command.hex(), io=io))
            except (FileNotFoundError, ProcessLookupError):
                continue
            except (OSError, ValueError) as error:
                omissions.append(dict(pid=path.name, reason=repr(error)))
        stream.write(json.dumps(dict(elapsed_ns=time.monotonic_ns() - started, rows=rows, omissions=omissions)) + '\n')
        stream.flush()
        time.sleep(0.2)
