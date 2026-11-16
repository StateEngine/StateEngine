"""Read-only Darwin identities; neither PID nor unreadability grants signal authority."""
import ctypes
import errno
import os
from pathlib import Path
import subprocess
import sys
import time
from common import require


class BsdInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in (
        'flags', 'status', 'xstatus', 'pid', 'parent', 'uid', 'gid', 'ruid', 'rgid', 'svuid', 'svgid', 'reserved')]
    _fields_ += [('comm', ctypes.c_char * 16), ('name', ctypes.c_char * 32)]
    _fields_ += [(name, ctypes.c_uint32) for name in ('files', 'pgid', 'jobc', 'tdev', 'tpgid')]
    _fields_ += [('nice', ctypes.c_int32), ('seconds', ctypes.c_uint64), ('microseconds', ctypes.c_uint64)]


def library():
    require(sys.platform == 'darwin', 'Native macOS observer requires Darwin')
    require(ctypes.sizeof(BsdInfo) == 136, 'Unexpected Darwin BSD identity layout')
    lib = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    lib.proc_pidinfo.restype = ctypes.c_int
    lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    lib.proc_pidpath.restype = ctypes.c_int
    return lib


def info(lib, pid):
    require(type(pid) is int and 1 < pid < 2**31, 'A finite positive process selector is required')
    value = BsdInfo()
    ctypes.set_errno(0)
    count = lib.proc_pidinfo(pid, 3, 1, ctypes.byref(value), ctypes.sizeof(value))
    cause = ctypes.get_errno()
    if count == 0 and cause == errno.ESRCH:
        return None
    require(count == ctypes.sizeof(value), f'Native BSD identity unreadable for {pid}: count={count}, errno={cause}')
    require(value.pid == pid and value.microseconds < 1_000_000 and value.status in (1, 2, 3, 4, 5),
            'Invalid native PID, birth or state')
    return value


def image(lib, pid):
    value = ctypes.create_string_buffer(4096)
    ctypes.set_errno(0)
    count = lib.proc_pidpath(pid, value, len(value))
    require(0 < count < len(value) and len(value.value) == count, f'Native image unreadable for {pid}: errno={ctypes.get_errno()}')
    path = os.fsdecode(value.value)
    require(Path(path).is_absolute(), 'Native executable path is not absolute')
    return path


def observe(pid):
    lib = library()
    try:
        before = info(lib, pid)
        if before is None:
            return dict(pid=pid, state='absent', method='proc_pidinfo ESRCH')
        row = dict(pid=pid, parent=before.parent, uid=before.uid, pgid=before.pgid,
                   birth=f'{before.seconds}:{before.microseconds:06d}', method='Darwin proc_pidinfo/proc_pidpath')
        if before.status == 5:
            return dict(row, state='exited-awaiting-reap', image=None)
        first = image(lib, pid)
        after = info(lib, pid)
        require(after is not None and (after.seconds, after.microseconds, after.uid) ==
                (before.seconds, before.microseconds, before.uid), 'Native process changed during observation')
        require(image(lib, pid) == first, 'Native process image changed during observation')
        last = info(lib, pid)
        require(last is not None and (last.seconds, last.microseconds, last.uid) ==
                (before.seconds, before.microseconds, before.uid), 'Native process changed after image observation')
        if last.status == 5:
            return dict(row, state='exited-awaiting-reap', image=None)
        return dict(row, state='stopped' if last.status == 4 else 'running', image=first)
    except (OSError, RuntimeError) as error:
        return dict(pid=pid, state='unreadable', reason=str(error))


def census():
    text = subprocess.check_output(['/bin/ps', '-Aww', '-o', 'pid=,ppid=,uid=,stat=,command='], text=True, timeout=20)
    rows = []
    for line in text.splitlines():
        fields = line.split(None, 4)
        require(len(fields) == 5, 'Native process census is incomplete')
        pid, parent, uid = map(int, fields[:3])
        if uid != os.getuid():
            continue
        row = observe(pid)
        if row['state'] == 'absent':
            continue
        require(row['state'] != 'unreadable', f'Current-account process census unreadable: {pid}')
        row.update(command=fields[4])
        rows.append(row)
    return rows


class Observer:
    def __init__(self, home):
        self.home, self.known = str(home), {}

    def scan(self, pid=None):
        rows = census()
        if pid is not None:
            row = next((r for r in rows if r['pid'] == pid), None)
            require(row and row['state'] == 'running', 'Original native host identity is not live/readable')
            self.known[(row['pid'], row['birth'])] = row
        for row in rows:
            if self.home in row['command']:
                self.known[(row['pid'], row['birth'])] = row
        while True:
            owned = {p for p, birth in self.known if any(r['pid'] == p and r['birth'] == birth for r in rows)}
            added = [r for r in rows if r['parent'] in owned and (r['pid'], r['birth']) not in self.known]
            if not added:
                break
            for row in added:
                self.known[(row['pid'], row['birth'])] = row
        return [r for r in rows if (r['pid'], r['birth']) in self.known]

    def closed(self, seconds=15):
        deadline = time.monotonic() + seconds
        while True:
            self.scan()
            rows, active = [], []
            for pid, birth in self.known:
                row = observe(pid)
                require(row['state'] != 'unreadable', f'Known native shutdown identity is unreadable: {pid}')
                rows.append(dict(row, original_birth=birth))
                if row['state'] in ('running', 'stopped') and row['birth'] == birth:
                    active.append(row)
            if not active:
                return dict(state='witnessed', method='outside native PID/birth census', observed=rows,
                            known=list(self.known.values()), bounds='Observed identities and descendants only; no wholly unobserved child guarantee')
            require(time.monotonic() < deadline, 'Owned native processes remain after public shutdown: ' + ','.join(str(r['pid']) for r in active))
            time.sleep(.1)
