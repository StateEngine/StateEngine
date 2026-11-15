"""Profile cold first pairings for #381: per-attempt wall time, phase markers,
matched process profiles of the se CLI tree and the destination session.

Runs as an ordinary (non-root) user with passwordless sudo for user management.
Each attempt gets a fresh destination user, fresh source home and fresh XDG
directories; the image cache is absent by construction. The slowest attempt is
retained, never dropped.

Usage:
  python3 cold-pair-profile.py --se /path/to/release/se --repo REPO --output DIR \
      --attempts N [--ssh-port 2222] [--tail-bound-sec X] [--time-limit-sec 120]

Outputs (under DIR):
  attempt-<n>/trace.jsonl   one sampling tick per line
  attempt-<n>/attempt.json  phase markers, per-process aggregates, checks
  attempt-<n>/cli.stdout, attempt-<n>/cli.stderr
  attempt-<n>/dest-prepare-diagnostic.txt
                            named prepare result; failed attempts only
  summary.json              all attempts, max/median, tail-bound verdict
"""
import argparse
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time


def sudo(*args):
    proc = subprocess.run(['sudo', '-n', *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f'sudo {" ".join(args)} failed: {proc.stderr.strip()}')
    return proc.stdout


def clock():
    return time.monotonic()


def read_proc_ints(path):
    try:
        text = pathlib.Path(path).read_text()
        return [int(part) for part in text.split()]
    except (OSError, ValueError):
        return None


def proc_snapshot(pid):
    base = f'/proc/{pid}'
    try:
        stat = pathlib.Path(f'{base}/stat').read_text()
    except OSError:
        return None
    # Field 2 (comm) is parenthesized and may contain spaces.
    close = stat.rfind(')')
    fields = stat[close + 2:].split()
    # After comm: state is fields[0] (field 3), utime fields[11] (14), stime 12.
    state = fields[0]
    try:
        utime = int(fields[11])
        stime = int(fields[12])
    except (IndexError, ValueError):
        return None
    io = read_proc_ints(f'{base}/io') or []
    # /proc/pid/io order: rchar wchar syscr syscw read_bytes write_bytes
    # cancelled_write_bytes ...
    io_map = {}
    names = ['rchar', 'wchar', 'syscr', 'syscw', 'read_bytes', 'write_bytes',
             'cancelled_write_bytes']
    for name, value in zip(names, io):
        io_map[name] = value
    wchan = ''
    try:
        wchan = pathlib.Path(f'{base}/wchan').read_text().strip()
    except OSError:
        pass
    status = {}
    try:
        for line in pathlib.Path(f'{base}/status').read_text().splitlines():
            if line.startswith(('voluntary_ctxt_switches', 'nonvoluntary_ctxt_switches')):
                key, value = line.split(':')
                status[key] = int(value.strip())
    except (OSError, ValueError):
        pass
    cmdline = []
    try:
        cmdline = [part for part in
                   pathlib.Path(f'{base}/cmdline').read_bytes().split(b'\0')
                   if part]
    except OSError:
        pass
    return {
        'state': state,
        'utime': utime,
        'stime': stime,
        'io': io_map,
        'wchan': wchan,
        'ctx': status,
        'cmdline': cmdline[:8],
    }


def process_table():
    table = {}
    for entry in os.listdir('/proc'):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            stat = pathlib.Path(f'/proc/{pid}/stat').read_text()
        except OSError:
            continue
        close = stat.rfind(')')
        fields = stat[close + 2:].split()
        if len(fields) < 4:
            continue
        table[pid] = {'ppid': int(fields[3]), 'uid': None}
        try:
            for line in pathlib.Path(f'/proc/{pid}/status').read_text().splitlines():
                if line.startswith('Uid:'):
                    table[pid]['uid'] = int(line.split()[1])
                    break
        except (OSError, IndexError, ValueError):
            pass
    return table


def wait_uid_gone(dest_uid, bound_sec):
    """Wait until no process entry of dest_uid remains in any state,
    zombies included. SIGKILL is asynchronous and userdel refuses while any
    entry remains; return False when the bound expires."""
    deadline = clock() + bound_sec
    while True:
        if not any(info['uid'] == dest_uid for info in process_table().values()):
            return True
        if clock() >= deadline:
            return False
        time.sleep(0.1)


def tree_from(root_pid):
    table = process_table()
    children = {}
    for pid, info in table.items():
        children.setdefault(info['ppid'], []).append(pid)
    seen = set()
    stack = [root_pid]
    while stack:
        pid = stack.pop()
        if pid in seen or pid not in table:
            continue
        seen.add(pid)
        stack.extend(children.get(pid, []))
    return seen, table


def disk_snapshot():
    lines = pathlib.Path('/proc/diskstats').read_text().splitlines()
    best = None
    for line in lines:
        parts = line.split()
        if len(parts) < 14:
            continue
        name = parts[2]
        if name.startswith(('nvme', 'sd', 'vd', 'xvd')) and not name.endswith(('p1', 'p2')):
            reads = int(parts[3])
            writes = int(parts[7])
            read_ms = int(parts[12])
            write_ms = int(parts[16])
            if best is None or (writes + reads) >= (best[1] + best[3]):
                best = (name, reads, write_ms + read_ms, writes)
    if best is None:
        return None
    return {'disk': best[0], 'ios': best[1] + best[3], 'io_ms': best[2]}


def host_snapshot():
    snap = {'loadavg': read_proc_ints('/proc/loadavg')}
    disk = disk_snapshot()
    if disk:
        snap['disk'] = disk
    return snap


def find_destination_markers(dest_home, source_home):
    """Edge-detect product-side phase markers in the destination home tree."""
    markers = {}
    try:
        for path in pathlib.Path(dest_home).rglob('*'):
            name = path.name
            if name == 'remote-sessions' and path.is_dir():
                if any(path.iterdir()):
                    markers['dest_accept_session'] = True
            elif name == 'se' and path.is_file() and os.access(str(path), os.X_OK):
                markers.setdefault('dest_image', str(path))
    except OSError:
        pass
    return markers


# The product's runtime-cache prepare check (staging::prepare, Linux flavor),
# verbatim: the destination runs it as itself, and its refusal names nothing.
DEST_PREPARE_EXACT = (
    'uid=$(id -u) && for p in . .stateengine-runtime '
    '.stateengine-runtime/@DIGEST@; do\n'
    'if ! test -d "$p"; then (umask 077 && mkdir "$p") || test -d "$p" '
    '|| exit 1; fi\n'
    'if test -L "$p"; then exit 1; fi\n'
    'owner=$(stat -c %u "$p") && mode=$(stat -c %a "$p") || exit 1\n'
    'test "$owner" = "$uid" && test "$((0$mode & 022))" -eq 0 || exit 1\n'
    'done')

# The same predicates, one named line each, no early exit, plus the session
# CWD: a CWD that is not the destination home fails the first path at once.
DEST_PREPARE_NAMED = '''uid=$(id -u)
fail=0
for p in . .stateengine-runtime .stateengine-runtime/@DIGEST@; do
  if [ ! -d "$p" ]; then
    mkdir_detail=$( (umask 077 && mkdir "$p") 2>&1 )
    if [ -d "$p" ]; then
      printf 'created p=%s\\n' "$p"
    else
      printf 'FAIL mkdir p=%s detail=%s\\n' "$p" "$mkdir_detail"
      fail=1; continue
    fi
  fi
  if [ -L "$p" ]; then
    printf 'FAIL symlink p=%s\\n' "$p"; fail=1; continue
  fi
  if ! owner=$(stat -c %u "$p"); then
    printf 'FAIL stat p=%s\\n' "$p"; fail=1; continue
  fi
  if ! mode=$(stat -c %a "$p"); then
    printf 'FAIL stat p=%s\\n' "$p"; fail=1; continue
  fi
  if [ "$owner" != "$uid" ]; then
    printf 'FAIL owner p=%s owner=%s uid=%s mode=%s\\n' "$p" "$owner" "$uid" "$mode"
    fail=1; continue
  fi
  if [ "$((0$mode & 022))" -ne 0 ]; then
    printf 'FAIL group-or-other-writable p=%s owner=%s uid=%s mode=%s\\n' "$p" "$owner" "$uid" "$mode"
    fail=1; continue
  fi
  printf 'OK p=%s owner=%s mode=%s\\n' "$p" "$owner" "$mode"
done
printf 'cwd=%s\\n' "$(pwd)"
printf 'home=%s\\n' "$HOME"
exit "$fail"
'''


def dest_prepare_diagnostic(outdir, dest_user, args, digest):
    """A failed pairing's cache refusal names no check; run the product's
    exact prepare check as the destination user over the loopback sshd,
    then the same predicates one named line each."""
    report = {'ran': False, 'exact_exit': None, 'named_exit': None,
              'failures': [], 'cwd': None, 'home': None}

    def run_remote(script):
        return subprocess.run(
            ['ssh', '-p', str(args.ssh_port), '-i', args.identity,
             '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
             '-o', 'StrictHostKeyChecking=accept-new',
             f'{dest_user}@127.0.0.1', script],
            capture_output=True, text=True, timeout=60)

    try:
        exact = run_remote(DEST_PREPARE_EXACT.replace('@DIGEST@', digest))
        report['exact_exit'] = exact.returncode
        if exact.stderr.strip():
            report['exact_stderr'] = exact.stderr.strip()
    except (subprocess.SubprocessError, OSError) as error:
        report['exact_error'] = str(error)
    try:
        named = run_remote(DEST_PREPARE_NAMED.replace('@DIGEST@', digest))
        report['named_exit'] = named.returncode
        lines = named.stdout.splitlines()
        for line in lines:
            if line.startswith('FAIL '):
                report['failures'].append(line)
            elif line.startswith('cwd='):
                report['cwd'] = line.split('=', 1)[1]
            elif line.startswith('home='):
                report['home'] = line.split('=', 1)[1]
        (outdir / 'dest-prepare-diagnostic.txt').write_text(
            f'exact_exit={report["exact_exit"]}\nnamed_exit='
            f'{report["named_exit"]}\n' + '\n'.join(lines) + '\n')
    except (subprocess.SubprocessError, OSError) as error:
        report['named_error'] = str(error)
    report['ran'] = True
    return report


def run_attempt(index, args, ssh_port, source_pub):
    outdir = pathlib.Path(args.output) / f'attempt-{index}'
    outdir.mkdir(parents=True, exist_ok=False)
    dest_user = f'pair-{index}-{os.getuid()}'
    dest_home = f'/home/{dest_user}'
    src_home = f'{args.output}/src-home-{index}'
    xdg = {
        'XDG_CONFIG_HOME': f'{src_home}/xdg-config',
        'XDG_CACHE_HOME': f'{src_home}/xdg-cache',
        'XDG_DATA_HOME': f'{src_home}/xdg-data',
        'XDG_STATE_HOME': f'{src_home}/xdg-state',
        'HOME': src_home,
    }
    for value in xdg.values():
        pathlib.Path(value).mkdir(parents=True, exist_ok=True)
        os.chmod(value, 0o700)

    # Fresh destination account; sshd already running on the loopback port.
    sudo('useradd', '-m', '-s', '/usr/bin/bash', dest_user)
    dest_ssh = f'{dest_home}/.ssh'
    sudo('install', '-d', '-m', '700', '-o', dest_user, '-g', dest_user, dest_ssh)
    sudo('install', '-m', '600', '-o', dest_user, '-g', dest_user, source_pub,
         f'{dest_ssh}/authorized_keys')
    # ssh resolves its user config from the invoking user's passwd-entry
    # home, not from $HOME (modern OpenSSH ignores $HOME), so the alias must
    # live there; the synthetic HOME stays only for the se state home.
    import pwd
    real_ssh = pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir) / '.ssh'
    real_ssh.mkdir(mode=0o700, exist_ok=True)
    os.chmod(real_ssh, 0o700)
    real_config = real_ssh / 'config'
    saved_config = real_config.read_bytes() if real_config.exists() else None
    real_config.write_text(
        f'Host pairdest\n'
        f'  HostName 127.0.0.1\n'
        f'  Port {ssh_port}\n'
        f'  User {dest_user}\n'
        f'  IdentityFile {args.identity}\n'
        f'  IdentitiesOnly yes\n'
        f'  StrictHostKeyChecking accept-new\n'
        f'  BatchMode yes\n')
    os.chmod(real_config, 0o600)

    se_env = dict(os.environ)
    se_env.update(xdg)

    # A fresh source home must be initialized like a stranger's first run;
    # init is recorded setup, not part of the measured pairing invocation.
    init_t0 = clock()
    init_proc = subprocess.run(
        [args.se, '--home', src_home, 'init', '--repo', args.repo],
        env=se_env, capture_output=True, text=True)
    init_sec = round(clock() - init_t0, 6)
    if init_proc.returncode != 0:
        raise RuntimeError(f'se init failed (exit {init_proc.returncode}): '
                           f'{init_proc.stderr.strip()}')

    # Sampler: child of this judge, starts before the CLI spawn.
    sampler = subprocess.Popen(
        [sys.executable, str(pathlib.Path(__file__).with_name('cold-pair-sampler.py')),
         '--out', str(outdir / 'trace.jsonl'),
         '--se', args.se,
         '--dest-user', dest_user,
         '--dest-home', dest_home],
        env=se_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.2)

    t0 = clock()
    attempt = {
        'attempt': index,
        'se': args.se,
        'dest_user': dest_user,
        'started': t0,
        'checks': {},
        'init_sec': init_sec,
    }
    timed_out = False
    stdout_text = ''
    stderr_text = ''
    exit_code = None
    try:
        cli_proc = subprocess.Popen(
            [args.se, '--home', src_home, 'remote', 'add', 'pairdest', '--name', 'loop'],
            env=se_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True)
        try:
            stdout_text, stderr_text = cli_proc.communicate(
                timeout=args.time_limit_sec)
            exit_code = cli_proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            # Kill the whole session: CLI, native host and any ssh children.
            try:
                os.killpg(cli_proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                stdout_text, stderr_text = cli_proc.communicate(timeout=10)
            except subprocess.SubprocessError:
                pass
        # The alias is no longer needed once the invocation has returned.
        if saved_config is not None:
            real_config.write_bytes(saved_config)
            os.chmod(real_config, 0o600)
        else:
            try:
                real_config.unlink()
            except FileNotFoundError:
                pass
        t1 = clock()
        attempt['wall_sec'] = round(t1 - t0, 6)
        attempt['exit_code'] = exit_code
        (outdir / 'cli.stdout').write_text(stdout_text)
        (outdir / 'cli.stderr').write_text(stderr_text)
        attempt['checks']['pairing_connected'] = (
            not timed_out and exit_code == 0
            and '"state":"connected"' in stdout_text.replace(' ', ''))
        if timed_out:
            attempt['checks']['timed_out'] = True
    finally:
        sampler.send_signal(signal.SIGINT)
        try:
            sampler.wait(timeout=5)
        except subprocess.TimeoutExpired:
            sampler.kill()

    # Image publication witness: the destination must hold an executable copy
    # of the exact source binary.
    src_sha = hashlib_sha256(args.se)
    published = None
    try:
        for path in pathlib.Path(dest_home).rglob('se'):
            if path.is_file() and os.access(str(path), os.X_OK):
                if hashlib_sha256(str(path)) == src_sha:
                    published = str(path)
                    break
    except OSError:
        pass
    attempt['checks']['image_published_sha256_match'] = published is not None
    attempt['image_sha256'] = src_sha

    # A failed pairing's refusal names no check; run the product's own
    # prepare check as the destination user and name the failing predicate.
    if not attempt['checks']['pairing_connected']:
        attempt['dest_prepare'] = dest_prepare_diagnostic(
            outdir, dest_user, args, src_sha)

    # Tear down the destination session by exact pid, then remove the user.
    # The kills run through sudo: the judge's own uid cannot signal the
    # destination user's processes (EPERM, previously swallowed silently).
    # SIGKILL is asynchronous and userdel refuses while any entry of the uid
    # remains (any state, zombies included), so wait for the table to clear.
    teardown = {'dest_uid': None, 'term_errors': 0, 'kill_errors': 0,
                'uid_gone_before_userdel': None,
                'userdel_ok': None, 'userdel_error': None}
    try:
        for line in pathlib.Path('/etc/passwd').read_text().splitlines():
            if line.startswith(f'{dest_user}:'):
                teardown['dest_uid'] = int(line.split(':')[2])
                break
        dest_uid = teardown['dest_uid']
        if dest_uid is not None:
            def kill_uid(sig, field):
                for pid in [int(pid) for pid, info in process_table().items()
                            if info['uid'] == dest_uid]:
                    try:
                        sudo('kill', '-s', sig, str(pid))
                    except (RuntimeError, OSError):
                        teardown[field] += 1  # the pid is already gone
            kill_uid('TERM', 'term_errors')
            deadline = clock() + 5
            while clock() < deadline and any(
                    info['uid'] == dest_uid for info in process_table().values()):
                time.sleep(0.1)
            kill_uid('KILL', 'kill_errors')
            teardown['uid_gone_before_userdel'] = wait_uid_gone(dest_uid, 30)
    except OSError:
        pass
    if teardown['dest_uid'] is not None:
        try:
            sudo('userdel', '-r', dest_user)
            teardown['userdel_ok'] = True
        except RuntimeError as error:
            teardown['userdel_ok'] = False
            teardown['userdel_error'] = str(error)
    attempt['teardown'] = teardown
    shutil.rmtree(src_home, ignore_errors=True)
    attempt['finished'] = clock()
    (outdir / 'attempt.json').write_text(json.dumps(attempt, indent=1) + '\n')
    return attempt


def hashlib_sha256(path):
    import hashlib
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--se', required=True)
    parser.add_argument('--repo', required=True,
                        help='repo path for se init of the fresh source home')
    parser.add_argument('--output', required=True)
    parser.add_argument('--attempts', type=int, required=True)
    parser.add_argument('--identity', required=True,
                        help='source SSH private key used for the loopback destination')
    parser.add_argument('--ssh-port', type=int, default=2222)
    parser.add_argument('--tail-bound-sec', type=float, default=None)
    parser.add_argument('--time-limit-sec', type=float, default=120.0)
    args = parser.parse_args()

    output = pathlib.Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    # The destination's authorized_keys needs the public half; the CLI keeps
    # the private half via its ssh config IdentityFile.
    pub_proc = subprocess.run(
        ['ssh-keygen', '-y', '-f', args.identity],
        capture_output=True, text=True)
    if pub_proc.returncode != 0:
        raise SystemExit(f'ssh-keygen -y failed: {pub_proc.stderr.strip()}')
    source_pub = output / 'source.pub'
    source_pub.write_text(pub_proc.stdout)
    os.chmod(source_pub, 0o644)
    attempts = []
    for index in range(1, args.attempts + 1):
        attempt = run_attempt(index, args, args.ssh_port, str(source_pub))
        attempts.append(attempt)
        line = (f'attempt {index}: {attempt.get("wall_sec")}s '
                f'exit={attempt.get("exit_code")} checks={attempt["checks"]}')
        prep = attempt.get('dest_prepare') or {}
        if prep.get('failures'):
            line += f' dest_prepare={"; ".join(prep["failures"])}'
        print(line, flush=True)
    times = [a['wall_sec'] for a in attempts if a.get('wall_sec') is not None]
    times_sorted = sorted(times)
    median = times_sorted[len(times_sorted) // 2] if times_sorted else None
    summary = {
        'issue': 381,
        'se': args.se,
        'attempts': attempts,
        'wall_sec': {'max': max(times) if times else None,
                     'median': median,
                     'min': min(times) if times else None,
                     'all': times},
         'slowest_attempt': attempts[times.index(max(times))]['attempt'] if times else None,
    }
    summary['teardown_failures'] = [
        a['attempt'] for a in attempts
        if a.get('teardown', {}).get('dest_uid') is not None
        and a.get('teardown', {}).get('userdel_ok') is not True]
    if args.tail_bound_sec is not None:
        # A failed pairing or a failed teardown is a tail violation, never a
        # dropped sample.
        def violated(a):
            if a['attempt'] in summary['teardown_failures']:
                return True
            return (not a.get('checks', {}).get('pairing_connected')
                    or a.get('wall_sec') is None
                    or a['wall_sec'] > args.tail_bound_sec)
        violations = [a['attempt'] for a in attempts if violated(a)]
        summary['tail_bound_sec'] = args.tail_bound_sec
        summary['tail_bound_violations'] = violations
        summary['tail_bound_verdict'] = 'PASS' if not violations else 'FAIL'
    connected = [a['attempt'] for a in attempts
                 if a.get('checks', {}).get('pairing_connected')]
    summary['connected_attempts'] = connected
    (output / 'summary.json').write_text(json.dumps(summary, indent=1) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k != 'attempts'}, indent=1))
    if not connected:
        print('refusal: no attempt completed a connected pairing; the run '
              'measured nothing and cannot judge the tail', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
