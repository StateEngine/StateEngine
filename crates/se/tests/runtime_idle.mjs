#!/usr/bin/env node
// Protects: B5/B6 — original 10/70s and 60s idle probes obtain native measurements.
// Imports the independent runner unchanged. One-session mode attaches to a real
// journey fixture after its task; it never substitutes a fake provider/session.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';

const options = {};
for (let i = 2; i < process.argv.length; i += 2) {
  const key = process.argv[i];
  if (!['--runner', '--mode', '--se', '--setup-se', '--status-reader', '--out', '--fixture'].includes(key)
      || !process.argv[i + 1] || Object.hasOwn(options, key.slice(2))) throw Error(`Unknown/repeated/missing option ${key}`);
  options[key.slice(2)] = process.argv[i + 1];
}
if (!['no-session', 'one-session'].includes(options.mode) || !options.runner || !options.out || !options.se)
  throw Error('Require --runner RUNNER --mode no-session|one-session --se CLI --out NEW_DIRECTORY; one-session also --fixture JSON --status-reader COMPILED_TEST');
if (process.platform !== 'linux') throw Error('Linux idle accounting required; not reached on this OS');
const runner = fs.realpathSync(options.runner), binary = fs.realpathSync(options.se);
fs.mkdirSync(options.out, { mode: 0o700 });
const out = fs.realpathSync(options.out);
const load = name => import(pathToFileURL(path.join(runner, 'journeys', name)).href);
const { processes, environment, pause } = await load('platform.mjs');
const { reapedChild, differentialIdle } = await load('reaped.mjs');
const { hostSelfIdle } = await load('host-idle.mjs');
const { ownedProcesses } = await load('budgets.mjs');
const digest = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const binding = { binary_sha256: digest(binary), runner_files: Object.fromEntries(
  ['host-idle.mjs', 'reaped.mjs', 'reaped-linux.c', 'metrics.mjs', 'process-scope.mjs', 'platform.mjs']
    .map(name => [name, digest(path.join(runner, 'journeys', name))])) };
fs.writeFileSync(path.join(out, 'binding.json'), JSON.stringify(binding, null, 2));
let serial = 0;
async function command(executable, argv, env, cwd) {
  const label = String(++serial).padStart(3, '0');
  const result = await new Promise((resolve, reject) => {
    const child = spawn(executable, argv, { env, cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = [], stderr = []; let bytes = 0, overflow = false, native, timedOut = false, rescue;
    const inspect = () => {
      try {
        const stat = fs.readFileSync(`/proc/${child.pid}/stat`, 'utf8');
        return {birth:stat.slice(stat.lastIndexOf(') ') + 2).split(' ')[19],
          command:fs.readFileSync(`/proc/${child.pid}/cmdline`).toString('hex')};
      } catch (error) { if (['ENOENT', 'ESRCH'].includes(error.code)) return null; throw error; }
    };
    child.once('spawn', () => { native = inspect(); });
    const signalOwned = signal => {
      const current = inspect();
      if (native?.command && current?.birth === native.birth && current.command === native.command) child.kill(signal);
    };
    const timer = setTimeout(() => {
      timedOut = true; signalOwned('SIGTERM');
      rescue = setTimeout(() => signalOwned('SIGKILL'), 5000);
    }, 30_000);
    child.stdout.on('data', b => { bytes += b.length; if (bytes <= 8_388_608) stdout.push(b); else overflow = true; });
    child.stderr.on('data', b => { bytes += b.length; if (bytes <= 8_388_608) stderr.push(b); else overflow = true; });
    child.once('error', error => {clearTimeout(timer); clearTimeout(rescue); reject(error);});
    child.once('close', (code, signal) => {
      clearTimeout(timer); clearTimeout(rescue);
      resolve({code, signal, overflow, timedOut, pid:child.pid, native,
        stdout:Buffer.concat(stdout).toString(), stderr:Buffer.concat(stderr).toString()});
    });
  });
  fs.writeFileSync(path.join(out, `${label}.json`), JSON.stringify({ executable, argv, ...result }, null, 2));
  if (result.code !== 0 || result.signal || result.overflow || result.timedOut) throw Error(`Public command failed; retained ${label}.json`);
  return result;
}
function trial(home, artifact, image, repo, provider = null) {
  const t = { home, root: artifact, cwd: repo, env: environment(home), known: new Map(),
    observerPids: new Set(), prerequisites: { agent: provider }, exposure: { se: image }, surface: 'claude' };
  fs.mkdirSync(t.env.TMP, { recursive: true });
  t.command = (file, argv) => command(file, argv, t.env, t.cwd);
  t.call = async name => {
    if (name !== 'status') throw Error('Idle adapter only reads public status');
    return JSON.parse((await t.command(image, ['--home', t.stateHome, 'status', '--json'])).stdout);
  };
  t.fact = (family, name, value) => {
    if (family !== 'runtime') throw Error('Only runtime facts belong to this adapter');
    const fields = { pid: value.runtime.process?.pid, host: value.runtime.host, resources: value.runtime.resources };
    if (!Object.hasOwn(fields, name) || fields[name] === undefined) throw Error(`Missing public runtime.${name}`);
    return fields[name];
  };
  return t;
}
async function ready(t, host) {
  const until = Date.now() + 20_000;
  while (!fs.existsSync(path.join(t.stateHome, 'endpoint.json'))) {
    if (Date.now() >= until) throw Error(`Host endpoint readiness unavailable; root ${host.pid}`);
    await pause(50);
  }
  const value = await t.call('status'), pid = value.runtime.process?.pid;
  const row = processes(t.home, [{ pid }]).find(p => p.pid === pid && p.state !== 'Z');
  if (!row?.birth || !row.command?.includes(t.home)) throw Error('Exact private host identity unavailable');
  t.known.set(`${row.pid}:${row.birth}`, row); t.engineIdentity = row;
}
async function makeRun(seconds) {
  const artifact = path.join(out, `idle-${seconds}`); fs.mkdirSync(artifact, { mode: 0o700 });
  const home = fs.mkdtempSync(path.join(os.homedir(), 'se-idle-'));
  const image = path.join(home, 'se'); fs.copyFileSync(binary, image); fs.chmodSync(image, 0o700);
  const repo = path.join(home, 'repo'); fs.mkdirSync(repo); fs.writeFileSync(path.join(repo, 'user.txt'), 'Keep user work.\n');
  const t = trial(home, artifact, image, repo); t.stateHome = path.join(home, 'state');
  fs.writeFileSync(path.join(artifact, 'fixture.json'), JSON.stringify({home, image, repo, state_home:t.stateHome}));
  const setup = fs.realpathSync(options['setup-se'] ?? binary);
  binding.setup_binary_sha256 = digest(setup);
  await t.command(setup, ['--home', t.stateHome, 'init', '--repo', repo, '--name', 'idle-judge', '--agent', 'judge', '--provider', 'claude', '--json']);
  const host = await reapedChild(t, [image, '--home', t.stateHome, 'up', '--foreground', '--json']);
  const close = async () => {
    try { await t.command(image, ['--home', t.stateHome, 'down', '--json']); return []; }
    catch (error) { return [error.message]; }
  };
  const cleanup = async () => {
    const errors = [];
    if (fs.existsSync(path.join(t.stateHome, 'endpoint.json'))) errors.push('endpoint remains after complete reap');
    if (fs.readFileSync(path.join(repo, 'user.txt'), 'utf8') !== 'Keep user work.\n') errors.push('user work changed');
    try { await t.command('/usr/bin/python3', ['-c', 'import fcntl,sys; f=open(sys.argv[1],"rb"); fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)', path.join(t.stateHome, 'runtime.lock')]); }
    catch (error) { errors.push(`outside lease proof: ${error.message}`); }
    return errors;
  };
  try { await ready(t, host); }
  catch (error) { const errors = await close(); try { await host.join(); } catch (e) { errors.push(e.message); } errors.push(...await cleanup()); throw Error(`${error.message}; cleanup: ${errors.join('; ')}`); }
  return { trial: t, host, close, cleanup };
}

let report;
try {
  if (options.mode === 'no-session') report = await differentialIdle(makeRun, ownedProcesses);
  else {
    if (!options.fixture || !options['status-reader']) throw Error('One-session requires an owned real journey fixture and the public IPC adapter');
    const fixture = JSON.parse(fs.readFileSync(options.fixture, 'utf8'));
    for (const key of ['home', 'state_home', 'repo', 'provider', 'agent_id', 'task_file', 'token'])
      if (typeof fixture[key] !== 'string' || !fixture[key]) throw Error(`Missing real-session fixture ${key}`);
    if (!fs.realpathSync(fixture.task_file).startsWith(fs.realpathSync(fixture.repo) + path.sep)
        || !fs.readFileSync(fixture.task_file, 'utf8').includes(fixture.token)) throw Error('Real task file/token witness absent');
    const t = trial(fixture.home, out, binary, fixture.repo, fixture.provider); t.stateHome = fixture.state_home;
    const direct = await t.call('status');
    const sessions = direct.agents?.items?.filter(a => a.session?.state === 'running');
    if (sessions?.length !== 1 || sessions[0].id !== fixture.agent_id) throw Error('One real running session is required');
    const pid = direct.runtime.process?.pid;
    const row = processes(t.home, [{pid}]).find(p => p.pid === pid && p.state !== 'Z');
    if (!row?.command || !row.birth) throw Error('Native host identity absent');
    t.known.set(`${row.pid}:${row.birth}`, row); t.engineIdentity = row;
    // Read via the authenticated public IPC client; the file-only CLI has no
    // authority to turn its own counters into another process's counters.
    t.call = async () => {
      const reply = path.join(out, `hosted-${++serial}.json`);
      const env = {...t.env, SE_RUNTIME_JUDGE_HOME:t.stateHome, SE_RUNTIME_JUDGE_REPLY:reply};
      await command(fs.realpathSync(options['status-reader']), ['--ignored', '--exact', 'hosted_status_reader', '--nocapture'], env, t.cwd);
      return JSON.parse(fs.readFileSync(reply, 'utf8'));
    };
    report = await hostSelfIdle(t, ownedProcesses);
    report.bound = 'Attached real-task fixture remains owned by its journey runner; no provider/helper lifetime claim beyond the original self-accounting probe.';
  }
  if (report.wakeups?.state !== 'measured' || !Number.isFinite(report.cpu_percent_one_core)) throw Error('Idle accounting did not produce a real measurement');
  report.state = 'measured';
  report.passed = !report.cleanup_errors?.length && report.cpu_percent_one_core < 0.1
    && (report.wakeups.absolute_rate_for_budget ?? report.wakeups.per_second) <= (options.mode === 'one-session' ? 2 : 1);
} catch (error) {
  report = {state:'unavailable', passed:false, reason:error.message, cpu_percent_one_core:null, wakeups:{state:'unavailable', reason:error.message}};
}
fs.writeFileSync(path.join(out, 'binding.json'), JSON.stringify(binding, null, 2));
fs.writeFileSync(path.join(out, 'idle.json'), JSON.stringify(report, null, 2));
console.log(JSON.stringify(report));
process.exitCode = report.passed ? 0 : 1;
