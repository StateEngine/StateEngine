"""Process-profile sampler for #381 cold pairings.

Samples the source se CLI process tree (CLI, native host, ssh/scp children)
and every destination-user process (sshd session, destination se) at 100 ms
resolution, plus host disk/load context. Writes one JSON line per tick to
--out and a final aggregate summary. Stops on SIGINT.
"""
import argparse
import json
import os
import pathlib
import signal
import subprocess
import sys
import time


def read_stat(pid):
    try:
        text = pathlib.Path(f'/proc/{pid}/stat').read_text()
    except OSError:
        return None
    close = text.rfind(')')
    fields = text[close + 2:].split()
    if len(fields) < 14:
        return None
    try:
        return {
            'state': fields[0],
            'utime': int(fields[11]),
            'stime': int(fields[12]),
        }
    except ValueError:
        return None


def read_io(pid):
    try:
        values = [int(part) for part in
                  pathlib.Path(f'/proc/{pid}/io').read_text().split()]
    except (OSError, ValueError):
        return None
    names = ['rchar', 'wchar', 'syscr', 'syscw', 'read_bytes', 'write_bytes',
             'cancelled_write_bytes']
    return dict(zip(names, values))


def read_wchan(pid):
    try:
        return pathlib.Path(f'/proc/{pid}/wchan').read_text().strip()
    except OSError:
        return ''


def read_ctx(pid):
    try:
        values = {}
        for line in pathlib.Path(f'/proc/{pid}/status').read_text().splitlines():
            if line.startswith(('voluntary_ctxt_switches', 'nonvoluntary_ctxt_switches')):
                key, value = line.split(':')
                values[key] = int(value.strip())
        return values
    except (OSError, ValueError):
        return {}


def read_cmdline(pid):
    try:
        return [part.decode('utf-8', 'replace') for part in
                pathlib.Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0') if part]
    except OSError:
        return []


def process_table():
    table = {}
    for entry in os.listdir('/proc'):
        if not entry.isdigit():
            continue
        pid = int(entry)
        stat = read_stat(pid)
        if stat is None:
            continue
        table[pid] = {'ppid': None, 'uid': None, **stat}
        try:
            raw = pathlib.Path(f'/proc/{pid}/stat').read_text()
            table[pid]['ppid'] = int(raw[raw.rfind(')') + 2:].split()[3])
        except (OSError, IndexError, ValueError):
            pass
        try:
            for line in pathlib.Path(f'/proc/{pid}/status').read_text().splitlines():
                if line.startswith('Uid:'):
                    table[pid]['uid'] = int(line.split()[1])
                    break
        except (OSError, IndexError, ValueError):
            pass
    return table


def tree_from(root):
    table = process_table()
    children = {}
    for pid, info in table.items():
        children.setdefault(info['ppid'], []).append(pid)
    seen, stack = set(), [root]
    while stack:
        pid = stack.pop()
        if pid in seen or pid not in table:
            continue
        seen.add(pid)
        stack.extend(children.get(pid, []))
    return seen, table


def disk_snapshot():
    try:
        lines = pathlib.Path('/proc/diskstats').read_text().splitlines()
    except OSError:
        return None
    best = None
    for line in lines:
        parts = line.split()
        if len(parts) < 17:
            continue
        name = parts[2]
        if name[:4] in ('nvme', 'sd', 'vd', 'xv') and name[-2:] != 'p0':
            if not (name.endswith('p1') or name.endswith('p2')):
                ios = int(parts[3]) + int(parts[7])
                io_ms = int(parts[12]) + int(parts[16])
                if best is None or ios > best[1]:
                    best = (name, ios, io_ms)
    if best is None:
        return None
    return {'disk': best[0], 'ios': best[1], 'io_ms': best[2]}


def destination_markers(dest_home):
    markers = {}
    try:
        found = subprocess.run(
            ['find', dest_home, '-name', 'se', '-type', 'f', '-o',
             '-name', 'remote-sessions', '-type', 'd'],
            capture_output=True, text=True, timeout=2)
        for line in found.stdout.splitlines():
            if line.strip() == f'{dest_home}':
                continue
            if os.path.basename(line) == 'remote-sessions' and os.path.isdir(line) \
                    and any(os.scandir(line)):
                markers['dest_accept_session'] = True
            elif os.path.basename(line) == 'se' and os.access(line, os.X_OK):
                markers.setdefault('dest_image', line)
    except (OSError, subprocess.SubprocessError):
        pass
    return markers


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True)
    parser.add_argument('--se', required=True)
    parser.add_argument('--dest-user', required=True)
    parser.add_argument('--dest-home', required=True)
    parser.add_argument('--interval', type=float, default=0.1)
    args = parser.parse_args()

    stopping = {'flag': False}

    def stop(_signum, _frame):
        stopping['flag'] = True
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    try:
        dest_uid = int(
            [line for line in
             pathlib.Path('/etc/passwd').read_text().splitlines()
             if line.startswith(f'{args.dest_user}:')][0].split(':')[2])
    except (OSError, IndexError, ValueError):
        dest_uid = None

    out = open(args.out, 'w')
    start = time.monotonic()
    cli_pid = None
    cli_seen_at = None
    cumulative = {}
    ticks = 0
    while not stopping['flag']:
        ticks += 1
        t = round(time.monotonic() - start, 3)
        if cli_pid is None:
            for pid, info in process_table().items():
                if info['uid'] == os.getuid():
                    cmd = read_cmdline(pid)
                    if cmd and os.path.basename(cmd[0]) == 'se' \
                            and 'remote' in cmd and 'add' in cmd and 'pairdest' in cmd:
                        cli_pid = pid
                        cli_seen_at = t
                        break
        procs = {}
        if cli_pid is not None:
            tree, _ = tree_from(cli_pid)
            for pid in sorted(tree):
                stat = read_stat(pid)
                if stat is None:
                    continue
                procs[pid] = {
                    'cmd': read_cmdline(pid)[:6],
                    'state': stat['state'],
                    'cpu_ticks': stat['utime'] + stat['stime'],
                    'io': read_io(pid),
                    'wchan': read_wchan(pid),
                    'ctx': read_ctx(pid),
                }
        dest = {}
        if dest_uid is not None:
            for pid, info in process_table().items():
                if info['uid'] == dest_uid:
                    stat = read_stat(pid)
                    if stat is None:
                        continue
                    dest[pid] = {
                        'cmd': read_cmdline(pid)[:6],
                        'state': stat['state'],
                        'cpu_ticks': stat['utime'] + stat['stime'],
                        'io': read_io(pid),
                        'wchan': read_wchan(pid),
                        'ctx': read_ctx(pid),
                    }
        host = {'loadavg': None, 'disk': disk_snapshot()}
        try:
            host['loadavg'] = [float(part) for part in
                               pathlib.Path('/proc/loadavg').read_text().split()[:3]]
        except (OSError, ValueError):
            pass
        if ticks % 5 == 1 or not cumulative:
            cumulative.update(destination_markers(args.dest_home))
        out.write(json.dumps({
            't': t,
            'cli_pid': cli_pid,
            'cli_seen_at': cli_seen_at,
            'procs': procs,
            'dest': dest,
            'host': host,
            'markers': cumulative,
        }) + '\n')
        out.flush()
        slept = 0.0
        while slept < args.interval and not stopping['flag']:
            time.sleep(0.01)
            slept += 0.01
    out.close()

    # Aggregate over the trace for the record.
    ticks_read = 0
    first = {}
    last = {}
    d_ticks = {}
    wchan = {}
    with open(args.out) as handle:
        for line in handle:
            ticks_read += 1
            row = json.loads(line)
            for group in ('procs', 'dest'):
                for pid, snap in row[group].items():
                    first.setdefault(pid, snap['cpu_ticks'])
                    last[pid] = snap['cpu_ticks']
                    if snap['state'] == 'D':
                        d_ticks[pid] = d_ticks.get(pid, 0) + 1
                    if snap['wchan'] and snap['wchan'] != '0':
                        key = f"{group}:{snap['cmd'][:2]}:{snap['wchan']}"
                        wchan[key] = wchan.get(key, 0) + 1
    summary = {
        'ticks': ticks_read,
        'cli_seen_at': None,
        'first_marker': {k: None for k in ('dest_image', 'dest_accept_session')},
        'cpu_ticks_total': {pid: last[pid] - first.get(pid, last[pid])
                            for pid in last},
        'd_state_ticks': d_ticks,
        'wchan_histogram': dict(sorted(wchan.items(),
                                       key=lambda kv: -kv[1])[:20]),
    }
    with open(args.out + '.summary.json', 'w') as handle:
        json.dump(summary, handle, indent=1)
        handle.write('\n')


if __name__ == '__main__':
    main()
