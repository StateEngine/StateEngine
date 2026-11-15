import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

export const windows = process.platform === 'win32';
export const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
export const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

export function assertRunnerEnvironment(env = process.env) {
  const names = Object.keys(env).filter(key => /^(STATEENGINE_|SECODE_|SE_SESSION$)/i.test(key));
  if (names.length) throw Error(`Run from a clean human terminal; fleet/session environment present: ${names.slice(0, 20).join(', ')}`);
}

export function restartWitness(before, after, observed) {
  const live = identity => observed.some(p => p.pid === identity.pid && p.birth === identity.birth && p.state !== 'Z');
  if (!before?.birth || !after?.birth || !before.command || !after.command) throw Error('Host restart identity unavailable');
  if (before.pid === after.pid && before.birth === after.birth) throw Error('Host did not restart: PID and birth unchanged');
  if (live(before) || !live(after)) throw Error('Host restart outside witness incomplete');
  return { before, after, old_absent: true, replacement_live: true };
}

export function prepareHome(home, surface, inherited = process.env) {
  const stock = process.platform === 'linux' ? '/etc/skel' : null;
  if (stock) for (const entry of fs.readdirSync(stock)) fs.cpSync(path.join(stock, entry), path.join(home, entry), { recursive: true, force: false, errorOnExist: true });
  // Select one prerequisite executable, never an operator's entire bin folder.
  const extensions = windows ? (inherited.PATHEXT ?? '.EXE;.CMD;.BAT;.COM').split(';') : [''];
  let source;
  for (const directory of (inherited.PATH ?? inherited.Path ?? '').split(path.delimiter)) {
    for (const extension of extensions) {
      const candidate = path.resolve(directory, surface + extension.toLowerCase());
      try { fs.accessSync(candidate, windows ? fs.constants.F_OK : fs.constants.X_OK); if (fs.statSync(candidate).isFile()) { source = candidate; break; } }
      catch (error) { if (!['ENOENT', 'EACCES', 'ENOTDIR'].includes(error.code)) throw error; }
    }
    if (source) break;
  }
  if (!source) return { stock, agent: null }; // Install/Remove do not need an agent prerequisite.
  const bin = path.join(home, 'agent-prerequisite'); fs.mkdirSync(bin);
  const target = path.join(bin, windows ? path.basename(source) : surface);
  if (windows && /\.(cmd|bat)$/i.test(source)) {
    // Keep a native CLI's existing wrapper beside its own dependencies. No
    // StateEngine/operator commands may enter through that directory.
    const directory = path.dirname(source);
    if (['se.exe', 'secode.exe', 'se.cmd', 'secode.cmd'].some(name => fs.existsSync(path.join(directory, name)))) throw Error('Agent prerequisite directory contains StateEngine commands; use a clean native CLI installation');
    return { stock, agent: source, bin: directory };
  }
  if (windows) fs.linkSync(source, target);
  else fs.symlinkSync(source, target);
  return { stock, agent: source, bin };
}

export function environment(home, inherited = process.env) {
  // Keep desktop transport and OS prerequisites, never an agent/factory identity.
  const allowed = /^(PATH|PATHEXT|SystemRoot|windir|ComSpec|OS|LANG|LC_.*|DISPLAY|WAYLAND_DISPLAY|DBUS_SESSION_BUS_ADDRESS|XAUTHORITY|XDG_RUNTIME_DIR|USER|LOGNAME|SHELL|TERM)$/i;
  const env = Object.fromEntries(Object.entries(inherited).filter(([key]) => allowed.test(key)));
  for (const key of Object.keys(env)) if (key.toUpperCase() === 'PATH') delete env[key];
  Object.assign(env, { HOME: home, USERPROFILE: home, TMPDIR: path.join(home, 'tmp'),
    TMP: path.join(home, 'tmp'), TEMP: path.join(home, 'tmp'),
    APPDATA: path.join(home, 'AppData', 'Roaming'), LOCALAPPDATA: path.join(home, 'AppData', 'Local'),
    XDG_CONFIG_HOME: path.join(home, '.config'), XDG_DATA_HOME: path.join(home, '.local', 'share'),
    XDG_STATE_HOME: path.join(home, '.local', 'state'), XDG_CACHE_HOME: path.join(home, '.cache'),
    GIT_CONFIG_GLOBAL: path.join(home, '.gitconfig'), GIT_CONFIG_NOSYSTEM: '1', TERM: 'xterm-256color',
    PATH: windows ? [path.join(inherited.SystemRoot ?? inherited.SYSTEMROOT ?? 'C:\\Windows', 'System32'),
      inherited.SystemRoot ?? inherited.SYSTEMROOT ?? 'C:\\Windows', path.join(inherited.SystemRoot ?? inherited.SYSTEMROOT ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0')].join(';')
      : process.platform === 'darwin' ? '/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin' : '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' });
  if (Object.keys(env).some(key => /^(STATEENGINE_|SECODE_)/i.test(key))) throw Error('Fleet environment leaked');
  return env;
}

export { credentials, automationCredentials } from './credentials.mjs';

// Helpers may rewrite argv (Postgres workers do). Attribute their current
// descendants from the outside parent inventory, without a process-name allowlist.
export function selectProcesses(rows, home, known) {
  const wanted = new Set(known.map(row => row.pid));
  const owned = new Set(rows.filter(row => (windows ? row.command?.toLowerCase().includes(home.toLowerCase()) : row.command?.includes(home))
    || known.some(old => old.pid === row.pid && old.birth === row.birth)).map(row => row.pid));
  let changed = true;
  while (changed) {
    changed = false;
    for (const row of rows) if (owned.has(row.parent) && !owned.has(row.pid)) { owned.add(row.pid); changed = true; }
  }
  return rows.filter(row => owned.has(row.pid) || wanted.has(row.pid))
    .map(row => ({ ...row, attributed: owned.has(row.pid) }));
}

// W5 also needs the census's unreadable rows, not just attributed processes.
export function linuxProcessCensus() {
  if (process.platform !== 'linux') throw Error('Linux process census required');
  const rows = [], unreadable = [];
  for (const entry of fs.readdirSync('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    const pid = Number(entry);
    try {
      const before = fs.readFileSync(`/proc/${pid}/stat`, 'utf8').split(') ').at(-1).split(' ');
      const command = fs.readFileSync(`/proc/${pid}/cmdline`).toString().replaceAll('\0', ' ');
      const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8').split(') ').at(-1).split(' ');
      if (before[19] !== stat[19]) throw Object.assign(Error(`PID ${pid} changed birth during census`), { code: 'IDENTITY_CHANGED' });
      rows.push({ pid, parent: Number(stat[1]), birth: stat[19], state: stat[0], command });
      if (!command.trim() && stat[0] !== 'Z') throw Object.assign(Error(`PID ${pid} has an empty command line`), { code: 'EMPTY_CMDLINE' });
    } catch (error) {
      if (['ENOENT', 'ESRCH'].includes(error.code)) continue;
      let uid;
      try { uid = Number(fs.readFileSync(`/proc/${pid}/status`, 'utf8').match(/^Uid:\s+(\d+)/m)?.[1]); }
      catch (cause) { if (['ENOENT', 'ESRCH'].includes(cause.code)) continue; }
      unreadable.push({ pid, code: error.code, reason: error.message,
        owner: Number.isSafeInteger(uid) ? uid === process.getuid() ? 'current-user' : 'foreign' : 'unreadable' });
    }
  }
  return { rows, unreadable };
}

// Outside the writer: observe exact births, without executable-name filtering.
export function processes(home, known = [], timeoutMs = 30_000) {
  const wanted = new Set(known.map(row => row.pid));
  if (process.platform === 'linux') {
    const census = linuxProcessCensus();
    const failure = census.unreadable.find(row => wanted.has(row.pid) || !['EACCES', 'EPERM', 'EMPTY_CMDLINE'].includes(row.code));
    if (failure) throw Error(failure.reason);
    return selectProcesses(census.rows, home, known);
  }
  let command, args, input;
  if (windows) {
    const script = `$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new(); $q=[Console]::In.ReadToEnd()|ConvertFrom-Json; $rows=@(Get-CimInstance Win32_Process|ForEach-Object {@{pid=[int]$_.ProcessId;parent=[int]$_.ParentProcessId;birth=$_.CreationDate.ToUniversalTime().ToString('o');state='live';command=$_.CommandLine}}); @{readable=$true;processes=$rows}|ConvertTo-Json -Depth 5 -Compress`;
    command = 'powershell.exe'; args = ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')];
    input = JSON.stringify({ home, pids: [...wanted] });
  } else {
    command = '/bin/ps'; args = ['-ww', '-axo', 'pid=,ppid=,lstart=,command='];
  }
  const r = spawnSync(command, args, { input, encoding: 'utf8', timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024, windowsHide: true });
  if (r.error || r.status !== 0) throw Error(`Process inventory unavailable: ${r.error?.message ?? r.stderr}`);
  if (windows) {
    const document = JSON.parse(r.stdout);
    if (document.readable !== true || !Array.isArray(document.processes)) throw Error('Process inventory is not an explicit readable array');
    return selectProcesses(document.processes, home, known);
  }
  const rows = r.stdout.split('\n').flatMap(line => {
    const match = /^\s*(\d+)\s+(\d+)\s+((?:\S+\s+){4}\S+)\s+(.*)$/.exec(line);
    if (line.trim() && !match) throw Error('Process inventory contains an unreadable row');
    return match ? [{ pid: Number(match[1]), parent: Number(match[2]), birth: match[3], state: 'live', command: match[4] }] : [];
  });
  return selectProcesses(rows, home, known);
}

export function defaultOutput() { return fs.mkdtempSync(path.join(os.homedir(), 'se-journeys-')); }
