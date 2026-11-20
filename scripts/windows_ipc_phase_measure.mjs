import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

const [binaryArg, outputArg, sampleArg = '200'] = process.argv.slice(2);
const binary = path.resolve(binaryArg);
const output = path.resolve(outputArg);
const samplesPerCohort = Number(sampleArg);
const trace = process.argv[5] === 'trace';
const hostMarkers = new Map();
const hostPreauth = new Map();
const clockMicros = () => Number(process.hrtime.bigint() / 1000n);
assert(Number.isSafeInteger(samplesPerCohort) && samplesPerCohort >= 8 && samplesPerCohort % 8 === 0);
const parent = process.env.RUNNER_TEMP || os.tmpdir();
const fixture = fs.mkdtempSync(path.join(parent, 'ipc-'));
const repo = path.join(fixture, 'repo');
const home = path.join(fixture, 'se');
const user = path.join(fixture, 'user');
const tmp = path.join(fixture, 'tmp');
const app = path.join(user, 'app');
const local = path.join(user, 'local');
const xdg = path.join(user, 'xdg');
for (const directory of [repo, user, tmp, app, local, xdg, output]) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
}
const allowed = new Set(['PATH', 'SYSTEMROOT', 'WINDIR', 'SYSTEMDRIVE', 'COMSPEC', 'PATHEXT',
  'PROGRAMFILES', 'PROGRAMFILES(X86)', 'PROGRAMW6432', 'PROGRAMDATA', 'COMMONPROGRAMFILES',
  'COMMONPROGRAMFILES(X86)', 'COMMONPROGRAMW6432', 'OS', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE',
  'LANG', 'LC_ALL', 'TERM']);
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => allowed.has(key.toUpperCase())));
Object.assign(env, {
  HOME: user, USERPROFILE: user, LOCALAPPDATA: local, APPDATA: app, XDG_CONFIG_HOME: xdg,
  XDG_DATA_HOME: local, XDG_STATE_HOME: local, XDG_CACHE_HOME: local, SE_HOME: home,
  TMPDIR: tmp, TMP: tmp, TEMP: tmp, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: path.join(user, 'no-git-config'),
});
if (process.platform === 'win32') {
  env.HOMEDRIVE = path.parse(user).root.slice(0, 2);
  env.HOMEPATH = user.slice(2);
}
const traceEnv = { ...env, IPC_PHASE_TRACE: '1', IPC_CONNECT_TRACE: '1' };
const options = { cwd: repo, env, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] };
const summarize = result => ({ ...result, stdout: undefined, stderr: result.stderr || undefined });
const digest = data => createHash('sha256').update(data).digest('hex');
function save(name, data) {
  fs.writeFileSync(path.join(output, name), JSON.stringify(data, null, 2) + '\n');
}
function executableArgs(args, project) {
  return [...args, '--home', home, '--json', '--no-color', ...(project ? ['--project', project] : [])];
}

function once(program, args, meter) {
  return new Promise(resolve => {
    const commandOptions = trace && meter ? { ...options, env: traceEnv } : options;
    const started = performance.now();
    if (meter) {
      meter.inFlight++;
      meter.peak = Math.max(meter.peak, meter.inFlight);
    }
    const spawnedUs = clockMicros();
    const child = spawn(program, args, commandOptions);
    const stdout = [], stderr = [];
    let ended, exitedUs, finished = false, counted = Boolean(meter), bytes = 0, failure = null;
    function countExit() {
      if (counted) {
        meter.inFlight--;
        counted = false;
      }
    }
    function finish(code, signal) {
      if (finished) return;
      const closed = performance.now();
      finished = true;
      countExit();
      clearTimeout(timer);
      resolve({ started_ms: started, ended_ms: ended ?? null, duration_ms: ended === undefined ? null : ended - started,
        ...(trace ? { spawned_us: spawnedUs, exited_us: exitedUs ?? null } : {}),
        drain_ms: ended === undefined ? null : closed - ended, pid: child.pid ?? null, code, signal, failure,
        stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') });
    }
    function collect(target, chunk) {
      bytes += chunk.length;
      if (bytes <= 2 * 1024 * 1024) target.push(chunk);
      else failure = 'command exceeded output bound';
    }
    child.stdout.on('data', chunk => collect(stdout, chunk));
    child.stderr.on('data', chunk => collect(stderr, chunk));
    child.stdin.on('error', () => {});
    child.stdin.end();
    child.once('exit', () => {
      exitedUs = clockMicros();
      ended = performance.now();
      countExit();
    });
    child.once('error', error => { failure = error.message; });
    child.once('close', finish);
    const timer = setTimeout(() => {
      failure = 'command exceeded deadline';
      abandonedCommands.push({ pid: child.pid ?? null, command: args.slice(0, 2) });
      child.unref();
      child.stdin.destroy();
      child.stdout.destroy();
      child.stderr.destroy();
      finish(null, null);
    }, 15_000);
  });
}

function checked(result, schema) {
  assert(result?.code === 0 && !result.failure,
    `Expected ${schema}: ${JSON.stringify(summarize(result))} ${result.stdout.slice(0, 1500)}`);
  const value = JSON.parse(result.stdout);
  assert.equal(value.schema, schema);
  return value;
}
async function call(args, schema, project) {
  return checked(await once(binary, executableArgs(args, project)), schema);
}

function startHost() {
  const child = spawn(binary, executableArgs(['up', '--foreground']), { ...options, env: trace ? traceEnv : env });
  let stdout = '', stderr = '', pending = '';
  const exit = new Promise(resolve => {
    child.once('error', error => { stderr += error.message; });
    child.once('close', (code, signal) => resolve({ pid: child.pid, code, signal, stderr }));
  });
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error('Foreground host readiness deadline')), 50_000);
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', chunk => {
      if (stderr.length < 64 * 1024) stderr += chunk;
      if (!trace) return;
      const lines = (pending + chunk).split('\n');
      pending = lines.pop();
      for (const line of lines) {
        if (line.startsWith('IPC_PREAUTH ')) {
          const fields = line.trim().split(/\s+/).slice(1).map(Number);
          const [pid, ...values] = fields;
          const previous = hostPreauth.get(pid) ?? [];
          previous.push(values);
          hostPreauth.set(pid, previous);
          continue;
        }
        const marker = /^IPC_HOST (\S+) (\d+) (\d+) (\d+)\r?$/.exec(line);
        if (!marker) continue;
        const [, id, ...stamps] = marker;
        hostMarkers.set(id, hostMarkers.has(id) ? null : stamps.map(Number));
      }
    });
    child.stdout.on('data', chunk => {
      if (stdout.includes('\n')) return;
      stdout += chunk.toString();
      if (stdout.length > 64 * 1024) {
        clearTimeout(timer);
        reject(Error('Foreground host readiness exceeded output bound'));
        return;
      }
      if (stdout.includes('\n')) {
        clearTimeout(timer);
        try {
          const value = JSON.parse(stdout.split('\n', 1)[0]);
          assert.equal(value.schema, 'se.runtime-start/v1');
          assert.equal(value.state, 'running');
          assert.equal(value.process?.pid, child.pid);
          assert(Number.isSafeInteger(value.generation) && value.generation > 0);
          assert(value.process.started_at && value.process.exe);
          resolve(value);
        } catch (error) {
          reject(error);
        }
      }
    });
    exit.then(result => {
      clearTimeout(timer);
      reject(Error(`Host exited before readiness: ${JSON.stringify(result)} ${stdout}`));
    });
  });
  child.stdin.on('error', () => {});
  child.stdin.end();
  return { child, ready, exit };
}

async function hostIdentity(project, host) {
  const { runtime } = await call(['status'], 'se.status/v1', project);
  assert.equal(runtime.state, 'running');
  assert.equal(runtime.process?.pid, host.process.pid);
  assert.equal(runtime.process?.started_at, host.process.started_at);
  assert.equal(runtime.process?.exe, host.process.exe);
  assert.equal(runtime.generation, host.generation);
  return { pid: runtime.process.pid, started_at: runtime.process.started_at, exe: runtime.process.exe,
    generation: runtime.generation, resources: runtime.resources ?? null,
    resources_unavailable: runtime.resources_unavailable ?? null };
}

function loadSnapshot() {
  return { at: new Date().toISOString(), free_bytes: os.freemem(), cpu_ms: os.cpus().map(cpu => cpu.times) };
}
function cpuUse(before, after) {
  assert(before.length && before.length === after.length, 'CPU sample topology changed');
  const current = { user: 0, nice: 0, sys: 0, idle: 0, irq: 0 };
  for (const [index, row] of after.entries()) {
    for (const key of Object.keys(current)) {
      const delta = row[key] - before[index][key];
      assert(delta >= 0, 'CPU time counter moved backward');
      current[key] += delta;
    }
  }
  const total = Object.values(current).reduce((sum, value) => sum + value, 0);
  return { delta_ms: current, non_idle_pct: total ? (total - current.idle) * 100 / total : null };
}
function writer(value, host) {
  assert.equal(value.writer?.mode, 'host');
  assert.equal(String(value.writer.host_generation), String(host.generation));
}
function identity(value) {
  assert(typeof value === 'string' && value.length > 0, 'Missing identity');
  return value;
}

async function messages(project) {
  const rows = new Map(), cursors = new Set();
  let cursor = null;
  for (let i = 0; i < 20; i++) {
    const page = await call(['msg', 'list', '--all', '--full', '--limit', '100',
      ...(cursor ? ['--cursor', cursor] : [])], 'se.message-page/v1', project);
    assert(Array.isArray(page.items), 'Message page has no items');
    for (const row of page.items) {
      assert(!row.unreadable && row.body?.complete === true, 'Message body is unreadable');
      const id = identity(row.id);
      assert(!rows.has(id), 'Repeated message ID across pages');
      rows.set(id, row);
    }
    const { complete, omitted } = page.window;
    if (complete === true) {
      assert(omitted?.count === 0 && omitted.reason === null && page.next === null, 'Inconsistent complete page');
      return rows;
    }
    assert(complete === false && ['limit', 'budget'].includes(omitted?.reason)
      && (omitted.count === null || Number.isSafeInteger(omitted.count) && omitted.count > 0)
      && page.items.length && typeof page.next === 'string' && page.next && !cursors.has(page.next),
      'Message page lacks a usable continuation');
    cursor = page.next;
    cursors.add(cursor);
  }
  throw Error('Message population exceeded the page bound');
}

async function hostCpu(pid) {
  if (process.platform !== 'win32') return null;
  assert(Number.isSafeInteger(pid) && pid > 0);
  const result = await once(binary, ['__cpu-probe', String(pid)]);
  assert(result.code === 0 && !result.failure,
    `Native host CPU sample failed: ${JSON.stringify(summarize(result))}`);
  const value = JSON.parse(result.stdout);
  assert(typeof value.born === 'string' && Number.isFinite(value.user_ms) && Number.isFinite(value.kernel_ms));
  return value;
}

async function measure({ clients, recipients, project, owner, host, nonce }) {
  const meter = { inFlight: 0, peak: 0 };
  const hostCpuBefore = await hostCpu(host.process.pid);
  const before = loadSnapshot();
  const start = performance.now();
  const batch = await Promise.all(Array.from({ length: clients }, async (_, client) => {
    const lane = [];
    for (let index = 0; index < samplesPerCohort / clients; index++) {
      const to = recipients[client];
      const body = `Journey budget ${nonce}/${clients}/send/${client}/${index}; measurement only, no task.`;
      const result = await once(binary, executableArgs(['msg', 'send', to, body, '--kind', 'question'], project), meter);
      lane.push({ client, index, to, body, result });
    }
    return lane;
  }));
  const wall_ms = performance.now() - start;
  const after = loadSnapshot();
  const hostCpuAfter = await hostCpu(host.process.pid);
  if (hostCpuBefore) {
    assert.equal(hostCpuBefore.born, hostCpuAfter.born);
    assert(hostCpuAfter.user_ms >= hostCpuBefore.user_ms && hostCpuAfter.kernel_ms >= hostCpuBefore.kernel_ms);
  }
  const cpu = cpuUse(before.cpu_ms, after.cpu_ms);
  const ordered = batch.flat();
  const samples = ordered.map(({ result, ...sample }) => ({
    ...sample, ...summarize(result), receipt: null, verified: false, error: null,
  }));
  const cohort = { clients, samples_per_client: samplesPerCohort / clients, observed_peak: meter.peak, wall_ms,
    load: { before, after, cpu },
    host_cpu: hostCpuBefore ? { user_ms: hostCpuAfter.user_ms - hostCpuBefore.user_ms,
      kernel_ms: hostCpuAfter.kernel_ms - hostCpuBefore.kernel_ms, completions: samplesPerCohort } : null,
    samples, complete: false, median_ms: null, p95_ms: null, within_budget: null };
  const filename = `cohort-${clients}.json`;
  save(filename, cohort);
  // A reply can reach the caller before the host's stderr marker is delivered.
  // Readbacks below drain the same host connection before correlating markers.
  let history, readbackError;
  try {
    history = await messages(project);
  } catch (error) {
    readbackError = error.message;
  }
  const messageIds = new Set(), eventIds = new Set();
  for (const [index, sample] of samples.entries()) {
    try {
      assert(Number.isFinite(sample.duration_ms) && sample.duration_ms >= 0 && sample.pid > 0,
        'No timed child exit');
      const receipt = checked(ordered[index].result, 'se.message-receipt/v1');
      const id = identity(receipt.message_id), eventId = identity(receipt.event_id);
      assert(!messageIds.has(id) && !eventIds.has(eventId), 'Repeated committed identity');
      messageIds.add(id);
      eventIds.add(eventId);
      assert.equal(receipt.state, 'committed');
      assert.equal(receipt.project?.id, project);
      assert.equal(receipt.from?.id, owner);
      assert.equal(receipt.to?.id, sample.to);
      assert.equal(receipt.kind, 'question');
      assert.deepEqual(receipt.body, { bytes: Buffer.byteLength(sample.body), sha256: digest(sample.body) });
      writer(receipt, host);
      sample.receipt = { id, event_id: eventId, writer: receipt.writer };
      const event = await call(['history', '--event', eventId], 'se.event/v1', project);
      assert.equal(event.event_id, eventId);
      assert.equal(event.project?.id, project);
      assert.equal(event.actor?.id, owner);
      assert.equal(event.kind, 'message.sent');
      identity(event.position);
      identity(event.read_at);
      writer(event, host);
      assert(!readbackError, readbackError);
      const row = history.get(id);
      assert(row && row.event_id === eventId && row.from?.id === owner && row.to?.id === sample.to
        && row.kind === 'question' && row.body?.text === sample.body, 'Message page readback mismatch');
      sample.event = { id: eventId, position: event.position, read_at: event.read_at, writer: event.writer };
      if (trace) {
        const result = ordered[index].result;
        sample.phases = matchedPhases(sample, result, receipt, id);
        sample.connection = matchedConnection(sample, result.stderr, host.process.pid);
      }
      sample.verified = true;
    } catch (error) {
      sample.error = error.message;
    }
  }
  if (samples.length === samplesPerCohort && samples.every(sample => sample.verified) && meter.peak === clients
      && abandonedCommands.length === 0 && Number.isFinite(cpu.non_idle_pct)) {
    const sorted = samples.map(sample => sample.duration_ms).sort((a, b) => a - b);
    cohort.complete = true;
    cohort.median_ms = (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2;
    cohort.p95_ms = sorted[Math.ceil(sorted.length * 0.95) - 1];
    cohort.within_budget = cohort.p95_ms <= 75;
  }
  save(filename, cohort);
  const { samples: _, ...summary } = cohort;
  return { ...summary, verified_samples: samples.filter(sample => sample.verified).length,
    failures: samples.filter(sample => sample.error).map(sample => ({ client: sample.client, index: sample.index, error: sample.error })) };
}

async function stopHost(host) {
  let receipt, stopError;
  try {
    receipt = await call(['down'], 'se.runtime-stop/v1');
    assert(receipt.complete && receipt.witness?.state === 'witnessed', 'Foreground host stop was not witnessed');
  } catch (error) {
    stopError = error.message;
  }
  let timer;
  const exit = await Promise.race([host.exit, new Promise(resolve => { timer = setTimeout(() => resolve(null), 20_000); })]);
  clearTimeout(timer);
  if (!exit) {
    host.child.unref();
    host.child.stdout.destroy();
    host.child.stderr.destroy();
  }
  return { exit, receipt, stop_error: stopError ?? null };
}

function matchedPhases(sample, result, receipt, id) {
  const lines = result.stderr.split(/\r?\n/).filter(line => line.startsWith('IPC_CLI '));
  assert.equal(lines.length, 1, 'Expected exactly one CLI phase marker');
  const [, raw, cpu] = /^IPC_CLI (\[[\d, ]+\]) (-?\d+)$/.exec(lines[0]) ?? [];
  const cli = JSON.parse(raw);
  const host = hostMarkers.get(id);
  assert(Array.isArray(cli) && cli.length === 13 && host?.length === 3, 'Incomplete matched phase markers');
  const [enter, owner, bootstrap, phaseOpened, callerObserved, selected, restoreStart, restoreEnd,
    connectStart, connectEnd, exchangeStart, exchangeEnd, done] = cli;
  const [admitted, encode, write] = host;
  const timeline = [sample.spawned_us, enter, owner, bootstrap, phaseOpened, callerObserved, selected,
    restoreStart, restoreEnd, connectStart, connectEnd, exchangeStart, admitted, encode, write,
    exchangeEnd, done, sample.exited_us];
  assert(timeline.every((stamp, index) => Number.isSafeInteger(stamp) && stamp > 0
    && (!index || stamp >= timeline[index - 1])), 'CLI, host and observer clocks disagree');
  const nativeWallMs = (sample.exited_us - sample.spawned_us) / 1000;
  assert(Math.abs(nativeWallMs - sample.duration_ms) <= 2, 'Observer clock interval differs by over 2 ms');
  const { write_timings: store, host_phases: service } = receipt.diagnostics ?? {};
  assert(service && store && ['normal', 'full'].includes(store.durability), 'Missing exact-request host diagnostics');
  for (const value of [service.admitted_to_encode_us, service.completion_wait_us, store.queue_ms,
    store.transaction_ms, store.commit_call_ms]) {
    assert(Number.isFinite(value) && value >= 0, 'Host diagnostic timing unavailable');
  }
  const cliCpu = Number(cpu);
  assert(Number.isSafeInteger(cliCpu) && cliCpu >= 0, 'Native process CPU counter unavailable');
  const cpuParts = result.stderr.split(/\r?\n/).filter(line => line.startsWith('IPC_CPU '));
  let nativeThreadId = null, userCpuUs = null, kernelCpuUs = null;
  if (process.platform === 'win32') {
    assert.equal(cpuParts.length, 1, 'Expected one native CPU marker');
    const match = /^IPC_CPU (\d+) (\d+) (\d+)$/.exec(cpuParts[0]);
    assert(match, 'Invalid native CPU marker');
    [nativeThreadId, userCpuUs, kernelCpuUs] = match.slice(1).map(Number);
    assert([nativeThreadId, userCpuUs, kernelCpuUs].every(Number.isSafeInteger) && nativeThreadId > 0);
  }
  return { cli_us: cli, host_us: host, cli_cpu_us: cliCpu, native_thread_id: nativeThreadId,
    user_cpu_us: userCpuUs, kernel_cpu_us: kernelCpuUs, diagnostics: receipt.diagnostics };
}

function matchedConnection(sample, stderr, hostPid) {
  const lines = stderr.split(/\r?\n/);
  function all(tag) {
    return lines.filter(line => line.startsWith(tag + ' ')).map(line => line.split(/\s+/).slice(1));
  }
  function one(tag, count) {
    const rows = all(tag);
    assert(rows.length === 1 && rows[0].length === count, `Missing or duplicate ${tag}`);
    return rows[0].map(Number);
  }
  function ordered(values) {
    assert(values.every((value, index) => Number.isSafeInteger(value) && value > 0
      && (!index || value >= values[index - 1])), 'Unordered native connection timestamps');
  }
  const handshake = one('IPC_CONNECT', 7);
  const native = one('IPC_NATIVE', 3);
  const [begin, warm, nativeDone, challenge, authority, sent, end] = handshake;
  const [nativeBegin, opened, checked] = native;
  ordered([sample.phases.cli_us[8], begin, warm, nativeBegin, opened, checked, nativeDone,
    challenge, authority, sent, end, sample.phases.cli_us[9]]);
  const pending = (hostPreauth.get(sample.pid) ?? []).filter(row => row[0] >= nativeBegin && row[0] <= challenge);
  assert.equal(pending.length, 1, 'Preauthentication did not correlate with the exact CLI PID');
  const preauth = pending[0];
  ordered(preauth);
  assert(preauth[2] <= challenge, 'Host proof finished after the observed challenge');
  const hashes = all('IPC_HASH').map(([kind, ...values]) => ({ kind, values: values.map(Number) }))
    .filter(row => row.values[1] >= begin && row.values[2] <= end);
  assert(hashes.length && hashes.every(row => ['hit', 'full'].includes(row.kind) && row.values.length === 5
    && row.values.every(value => Number.isSafeInteger(value) && value >= 0)), 'Image proof markers are incomplete');
  let pipe = null;
  let peers = [];
  if (process.platform === 'win32') {
    pipe = one('IPC_PIPE', 5);
    ordered([nativeBegin, ...pipe.slice(0, 3), opened]);
    assert(Number.isSafeInteger(pipe[3]) && pipe[3] >= 0 && Number.isSafeInteger(pipe[4])
      && pipe[4] >= 0 && pipe[4] <= pipe[1] - pipe[0]);
    peers = all('IPC_PEER').map(values => values.map(Number)).filter(row => row[1] >= begin && row[5] <= end);
    assert.deepEqual(peers.map(row => row[0]), [sample.pid, hostPid, sample.pid], 'Unexpected native peer proof order');
    for (const row of peers) {
      assert.equal(row.length, 6);
      ordered(row.slice(1));
    }
    assert.equal(hashes.length, peers.length, 'Native peer observations and image proofs disagree');
    for (const [index, hash] of hashes.entries()) {
      const peer = peers[index];
      assert(peer[3] <= hash.values[1] && hash.values[2] <= peer[4], 'Image proof crossed its peer observation');
    }
  }
  return { handshake_us: handshake, native_us: native, preauth_us: preauth, pipe, peers, hashes };
}

const abandonedCommands = [];
const summary = {
  schema: 'ipc-cli-write-baseline/v1', phase_trace: trace,
  boundary: 'Fresh OS CLI process spawn to exit; drain and public readbacks are untimed',
  workload: 'Owner-authenticated se msg send to one or eight registered recipients using independent serial CLI lanes',
  ceiling_ms_inclusive: 75, planned_samples_per_cohort: samplesPerCohort, cohorts: [],
  environment: { platform: process.platform, release: os.release(), version: os.version(), arch: process.arch,
    node: process.version, logical_cpus: os.cpus().length, available_parallelism: os.availableParallelism(),
    cpu_models: [...new Set(os.cpus().map(cpu => cpu.model))], memory_bytes: os.totalmem(),
    runner_os: process.env.RUNNER_OS ?? null, image_os: process.env.ImageOS ?? null,
    image_version: process.env.ImageVersion ?? null },
};
let host;
try {
  const git = await once('git', ['init', '--quiet', '.']);
  assert(git.code === 0 && !git.failure, JSON.stringify(summarize(git)));
  const init = await call(['init', '--repo', repo, '--name', 'Write Budget', '--agent', 'Recipient 0',
    '--provider', 'codex', '--model', 'gpt-5.3-codex'], 'se.init/v1');
  const project = identity(init.profile?.project), owner = identity(init.profile?.human_id);
  host = startHost();
  const expected = await host.ready;
  summary.startup = expected;
  for (let index = 1; index < 8; index++) {
    await call(['agent', 'add', `Recipient ${index}`, '--provider', 'codex', '--model', 'gpt-5.3-codex'],
      'se.agent-receipt/v1', project);
  }
  const agents = await call(['agent', 'list'], 'se.agent-page/v1', project);
  assert(agents.window?.complete === true && agents.window.omitted?.count === 0 && agents.next === null);
  const recipients = Array.from({ length: 8 }, (_, index) => {
    const rows = agents.items.filter(row => row.name === `Recipient ${index}`);
    assert.equal(rows.length, 1, 'Recipient missing or ambiguous');
    return identity(rows[0].id);
  });
  assert.equal(new Set(recipients).size, 8);
  summary.project = project;
  summary.host_before = await hostIdentity(project, expected);
  const nonce = randomUUID().slice(0, 8);
  for (const clients of [1, 8]) {
    const cohort = await measure({ clients, recipients, project, owner, host: expected, nonce });
    cohort.host_after = await hostIdentity(project, expected);
    summary.cohorts.push(cohort);
    save('summary.json', summary);
  }
} catch (error) {
  summary.error = error.stack;
} finally {
  if (host) summary.shutdown = await stopHost(host);
  summary.abandoned_commands = abandonedCommands;
  summary.complete = Boolean(!summary.error && !abandonedCommands.length && summary.cohorts.length === 2
    && summary.cohorts.every(cohort => cohort.complete) && summary.shutdown?.exit?.code === 0
    && summary.shutdown?.receipt?.witness?.state === 'witnessed' && !summary.shutdown?.stop_error);
  save('summary.json', summary);
  if (!abandonedCommands.length && (!host || summary.shutdown?.exit)) {
    fs.rmSync(fixture, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
  }
}
console.log(JSON.stringify({ complete: summary.complete, cohorts: summary.cohorts.map(cohort => ({
  clients: cohort.clients, verified_samples: cohort.verified_samples, p95_ms: cohort.p95_ms,
  observed_peak: cohort.observed_peak, within_budget: cohort.within_budget,
})), error: summary.error }));
process.exitCode = summary.complete ? 0 : 1;
