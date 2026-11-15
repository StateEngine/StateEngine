"""Profile cold first pairings for #381: per-attempt wall time, phase markers,
matched process profiles of the se CLI tree and the destination session.

Runs as an ordinary (non-root) user with passwordless sudo for user management.
The source side runs as the disposable OS user se381check: the product's ssh
client reads its config from the invoking user's passwd home, so the pairing
alias must live in a real home, and it lives in this user's, never in the
judge's real ~/.ssh. Each attempt gets a fresh destination user, fresh source
home and fresh XDG directories; the image cache is absent by construction.
The slowest attempt is retained, never dropped.

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
import shlex
import signal
import subprocess
import sys
import time


def sudo(*args):
    proc = subprocess.run(['sudo', '-n', *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f'sudo {" ".join(args)} failed: {proc.stderr.strip()}')
    return proc.stdout


# The disposable source-side account. The product's ssh client reads its
# config from the invoking user's passwd home (OpenSSH ignores $HOME), so
# the pairing alias must live in a real home. It lives in this user's home,
# never in the judge's real ~/.ssh (the 2026-11-15 harness incident lost the
# judge's config to an in-memory save/restore that was not crash-safe). The
# account is judge-owned and disposable: every process of its uid is one
# this judge reaps.
SOURCE_USER = 'se381check'


def ensure_source_user():
    import pwd
    try:
        entry = pwd.getpwnam(SOURCE_USER)
    except KeyError:
        sudo('useradd', '-m', '-s', '/usr/bin/bash', SOURCE_USER)
        entry = pwd.getpwnam(SOURCE_USER)
    sudo('install', '-d', '-m', '700', '-o', SOURCE_USER, '-g', SOURCE_USER,
         f'{entry.pw_dir}/.ssh')
    return entry.pw_uid, pathlib.Path(entry.pw_dir)


def source_cmd(argv, xdg, home):
    """A product invocation as the disposable source user. env -i wipes the
    judge's session markers (CODEX_*, SE_*, STATEENGINE_*) that make the
    product's owner probe refuse; the XDG set pins se state under the
    attempt home. ssh reads this passwd home's .ssh/config, which the judge
    stages per attempt."""
    env = ['HOME=' + str(home),
           'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin']
    env.extend(f'{key}={value}' for key, value in xdg.items())
    return ['sudo', '-n', '-u', SOURCE_USER, 'env', '-i', *env, *argv]


def stage_repo(repo, staging):
    """--repo must be traversable and readable by the source user. The judge
    may run from a home chain the source user cannot enter (fleet host), in
    which case the repo is bind-mounted into the judge-owned staging dir.
    A worktree checkout keeps its git metadata outside the mounted path,
    which the source user still cannot reach; that would fail init with
    "not a git repository", so it falls back to a fresh minimal git repo,
    which keeps init's git observation honest. Returns
    (path, mountpoint-or-None, mode)."""
    probe = subprocess.run(['sudo', '-n', '-u', SOURCE_USER, 'test', '-d', repo],
                           capture_output=True)
    if probe.returncode == 0:
        return repo, None, 'direct'
    if os.path.isfile(pathlib.Path(repo) / '.git'):
        # A worktree: its gitdir is not inside the mounted path, so no mount
        # can make it readable.
        return _fresh_repo(staging)
    mountpoint = str(staging / 'repo')
    try:
        mounts = pathlib.Path('/proc/mounts').read_text()
    except OSError:
        mounts = ''
    if f' {mountpoint} ' in mounts:
        sudo('umount', mountpoint)  # a crashed earlier run may hold it
    sudo('install', '-d', '-m', '755', '-o', SOURCE_USER, '-g', SOURCE_USER,
         mountpoint)
    sudo('mount', '--bind', repo, mountpoint)
    return mountpoint, mountpoint, 'bind-mount'


def _fresh_repo(staging):
    fresh = str(staging / 'repo-fresh')
    sudo('rm', '-rf', fresh)
    sudo('install', '-d', '-m', '700', '-o', SOURCE_USER, '-g', SOURCE_USER,
         fresh)
    for argv in (['git', 'init', '-q', '-b', 'main', fresh],
                 ['git', '-C', fresh, '-c', 'user.name=se381-judge',
                  '-c', 'user.email=se381@judge', 'commit', '-q',
                  '--allow-empty', '-m', 'se381 judge repo']):
        proc = subprocess.run(['sudo', '-n', '-u', SOURCE_USER, *argv],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(
                f'{" ".join(argv[:3])} failed: {proc.stderr.strip()}'
            )
    return fresh, None, 'fresh-minimal'


def reap_uid(uid):
    """TERM, then KILL, every process of uid; wait for the table to clear.
    The caller owns the uid (judge-created, disposable). SIGKILL is
    asynchronous and userdel refuses while any entry of the uid remains
    (any state, zombies included)."""
    report = {'term_errors': 0, 'kill_errors': 0, 'uid_gone': None}

    def kill_uid(sig, field):
        for pid in [int(pid) for pid, info in process_table().items()
                    if info['uid'] == uid]:
            try:
                sudo('kill', '-s', sig, str(pid))
            except (RuntimeError, OSError):
                report[field] += 1  # the pid is already gone

    kill_uid('TERM', 'term_errors')
    deadline = clock() + 5
    while clock() < deadline and any(
            info['uid'] == uid for info in process_table().values()):
        time.sleep(0.1)
    kill_uid('KILL', 'kill_errors')
    report['uid_gone'] = wait_uid_gone(uid, 30)
    return report


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


def dest_probe(outdir, dest_user, args, digest, tag):
    """r11: measure the remote session itself as the destination user over
    the same loopback sshd the product uses: login/current shell, ambient
    umask, pre-existing cache state, and a same-session comparison of
    explicit-mode versus subshell-umask creation. Writes r11-probe-<tag>.txt."""
    report = {'ran': False, 'exit': None}
    probe = (pathlib.Path(__file__).with_name('r11-dest-prepare-probe.sh')
             ).read_text()
    command = ('sh -c ' + shlex.quote(probe)
               + ' r11probe ' + shlex.quote(digest))
    try:
        proc = subprocess.run(
            ['ssh', '-p', str(args.ssh_port), '-i', args.identity,
             '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
             '-o', 'StrictHostKeyChecking=accept-new',
             f'{dest_user}@127.0.0.1', command],
            capture_output=True, text=True, timeout=60)
        report['exit'] = proc.returncode
        (outdir / f'r11-probe-{tag}.txt').write_text(
            f'exit={proc.returncode}\n' + proc.stdout
            + (f'\nstderr:\n{proc.stderr}\n' if proc.stderr else ''))
    except (subprocess.SubprocessError, OSError) as error:
        report['error'] = str(error)
    report['ran'] = True
    return report


def run_attempt(index, args, ssh_port, source_pub, staging, source_home,
                source_uid, se_bin, repo_path):
    outdir = pathlib.Path(args.output) / f'attempt-{index}'
    outdir.mkdir(parents=True, exist_ok=False)
    dest_user = f'pair-{index}-{os.getuid()}'
    dest_home = f'/home/{dest_user}'
    # The source side runs as the disposable source user, in a fresh home
    # per attempt: a reused home still holds the previous attempt's live IPC
    # listener, which the product refuses with ipc-unavailable/AlreadyExists.
    # Nothing under the judge's home is written.
    src_home = f'{staging}/src-home-{index}'
    sudo('install', '-d', '-m', '700', '-o', SOURCE_USER, '-g', SOURCE_USER,
         src_home)
    xdg = {
        'XDG_CONFIG_HOME': f'{src_home}/xdg-config',
        'XDG_CACHE_HOME': f'{src_home}/xdg-cache',
        'XDG_DATA_HOME': f'{src_home}/xdg-data',
        'XDG_STATE_HOME': f'{src_home}/xdg-state',
        'HOME': src_home,
    }
    for value in xdg.values():
        sudo('install', '-d', '-m', '700', '-o', SOURCE_USER, '-g', SOURCE_USER,
             value)

    # A fresh source home must be initialized like a stranger's first run;
    # init is recorded setup, not part of the measured pairing invocation.
    # It runs before the destination account exists, so an init failure
    # leaks no destination user.
    init_t0 = clock()
    init_proc = subprocess.run(
        source_cmd([se_bin, '--home', src_home, 'init', '--repo', repo_path],
                   xdg, source_home),
        capture_output=True, text=True)
    init_sec = round(clock() - init_t0, 6)
    if init_proc.returncode != 0:
        raise RuntimeError(f'se init failed (exit {init_proc.returncode}): '
                           f'{init_proc.stderr.strip()}')

    # Fresh destination account; sshd already running on the loopback port.
    sudo('useradd', '-m', '-s', '/usr/bin/bash', dest_user)
    dest_ssh = f'{dest_home}/.ssh'
    sudo('install', '-d', '-m', '700', '-o', dest_user, '-g', dest_user, dest_ssh)
    sudo('install', '-m', '600', '-o', dest_user, '-g', dest_user, source_pub,
         f'{dest_ssh}/authorized_keys')
    # The pairing alias in the source user's own ssh config (passwd home --
    # OpenSSH ignores $HOME). The file is disposable: rewritten per attempt,
    # no save/restore.
    alias = outdir / 'source-ssh-config'
    alias.write_text(
        f'Host pairdest\n'
        f'  HostName 127.0.0.1\n'
        f'  Port {ssh_port}\n'
        f'  User {dest_user}\n'
        f'  IdentityFile {staging}/.ssh/id_pair\n'
        f'  IdentitiesOnly yes\n'
        f'  StrictHostKeyChecking accept-new\n'
        f'  BatchMode yes\n')
    sudo('install', '-m', '600', '-o', SOURCE_USER, '-g', SOURCE_USER,
         str(alias), f'{source_home}/.ssh/config')

    # r11: the remote session's own shell/umask/cache state, measured
    # through the product's ssh path before the first product call.
    src_sha = hashlib_sha256(args.se)
    pre_probe = dest_probe(outdir, dest_user, args, src_sha, 'pre')
    if args.stop_before_pairing:
        record = {
            'attempt': index,
            'se': args.se,
            'dest_user': dest_user,
            'stop_before_pairing': True,
            'checks': {},
            'init_sec': init_sec,
            'r11_probe_pre': pre_probe,
        }
        (outdir / 'attempt.json').write_text(json.dumps(record, indent=1) + '\n')
        try:
            sudo('userdel', '-r', dest_user)
        except (RuntimeError, OSError):
            pass
        sudo('rm', '-rf', src_home)
        return record

    # Sampler: child of this judge, starts before the CLI spawn.
    sampler = subprocess.Popen(
        [sys.executable, str(pathlib.Path(__file__).with_name('cold-pair-sampler.py')),
         '--out', str(outdir / 'trace.jsonl'),
         '--se', args.se,
         '--dest-user', dest_user,
         '--dest-home', dest_home,
         '--source-uid', str(source_uid)],
        env=dict(os.environ), stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    time.sleep(0.2)

    t0 = clock()
    attempt = {
        'attempt': index,
        'se': args.se,
        'dest_user': dest_user,
        'started': t0,
        'checks': {},
        'init_sec': init_sec,
        'r11_probe_pre': pre_probe,
    }
    timed_out = False
    stdout_text = ''
    stderr_text = ''
    exit_code = None
    try:
        cli_proc = subprocess.Popen(
            source_cmd([se_bin, '--home', src_home, '--json', 'remote',
                        'add', 'pairdest', '--name', 'loop'],
                       xdg, source_home),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
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

    # Source-side reap: the source user is judge-owned, so every surviving
    # process of its uid (CLI, native host, ssh children, a detached daemon)
    # is this judge's to clean.
    attempt['source_teardown'] = {'source_uid': source_uid, **reap_uid(source_uid)}

    # Image publication witness: the destination must hold an executable copy
    # of the exact source binary. The runtime cache dirs are 0700 for the
    # destination user, so the readback runs through root (the judge cannot
    # traverse them, and the destination user is removed shortly after).
    published = None
    try:
        found = sudo('find', dest_home, '-name', 'se', '-type', 'f',
                     '-perm', '-u+x').split()
        for path in found:
            digest = sudo('sha256sum', path).split()[0]
            if digest == src_sha:
                published = path
                break
    except (RuntimeError, OSError):
        pass
    attempt['checks']['image_published_sha256_match'] = published is not None
    attempt['image_sha256'] = src_sha

    # A failed pairing's refusal names no check; run the product's own
    # prepare check as the destination user and name the failing predicate.
    if not attempt['checks']['pairing_connected']:
        attempt['dest_prepare'] = dest_prepare_diagnostic(
            outdir, dest_user, args, src_sha)
        # r11: the same session measurements after the refusal, so the
        # product's prepare attempt is visible against the pre state.
        attempt['r11_probe_post'] = dest_probe(
            outdir, dest_user, args, src_sha, 'post')

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
            reaped = reap_uid(dest_uid)
            teardown['term_errors'] = reaped['term_errors']
            teardown['kill_errors'] = reaped['kill_errors']
            teardown['uid_gone_before_userdel'] = reaped['uid_gone']
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
    # src_home is source-user owned; the judge cannot unlink it without root.
    sudo('rm', '-rf', src_home)
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
    parser.add_argument('--stop-before-pairing', action='store_true',
                        help='box pre-run: do setup and the r11 pre-probe, '
                             'then stop before the pairing call')
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
    # Stage the source side under the source user's own home: the product
    # refuses a state home whose ancestor dirs belong to another user
    # (LocationUnsafe), and the judge's own home chain is exactly that.
    # The product binary and the identity may sit under a home chain the
    # source user cannot enter, so both are copied into a chowned staging
    # tree. A crashed earlier run's staging (unique pid suffix) is swept.
    source_uid, source_home = ensure_source_user()
    for name in sudo('ls', '-1', str(source_home)).split():
        if name.startswith('381-src-staging-'):
            sudo('rm', '-rf', str(source_home / name))
    staging = source_home / f'381-src-staging-{os.getpid()}'
    sudo('install', '-d', '-m', '700', '-o', SOURCE_USER, '-g', SOURCE_USER,
         str(staging / '.ssh'))
    se_bin = str(staging / 'se')
    sudo('install', '-m', '755', '-o', SOURCE_USER, '-g', SOURCE_USER,
         args.se, se_bin)
    sudo('install', '-m', '600', '-o', SOURCE_USER, '-g', SOURCE_USER,
         args.identity, str(staging / '.ssh' / 'id_pair'))
    repo_path, repo_mount, repo_mode = stage_repo(args.repo, staging)

    import atexit

    def cleanup_run():
        if repo_mount is not None:
            try:
                sudo('umount', repo_mount)
            except (RuntimeError, OSError):
                pass
        try:
            sudo('rm', '-rf', str(staging))
        except (RuntimeError, OSError):
            pass

    atexit.register(cleanup_run)
    attempts = []
    for index in range(1, args.attempts + 1):
        attempt = run_attempt(index, args, args.ssh_port, str(source_pub),
                              staging, source_home, source_uid, se_bin,
                              repo_path)
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
        'repo_mode': repo_mode,
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
