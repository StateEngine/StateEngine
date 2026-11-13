// The runner requires a JavaScript hook entrypoint. All workload and custody
// decisions stay in the fixed controller; no repository shell runs on the host.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const installedName = path.basename(process.argv[1]);
if (!['hook.js', 'hook-secondary.js'].includes(installedName)) throw Error('fixed runner hook entrypoint required');
const slot = installedName === 'hook-secondary.js' ? 'secondary' : 'primary';
const published = JSON.parse(fs.readFileSync('/etc/stateengine-ci/self-hosted.json', 'utf8'));
if (slot === 'secondary' && !published.slots) throw Error('second runner slot is not configured');
const config = published.slots ? { ...published, ...published.slots[slot] } : published;
const request = JSON.parse(fs.readFileSync(0, 'utf8'));
const work = fs.realpathSync(config.runner_work);
function runnerFile(value, folder) {
  const host = value?.startsWith('/__w/') ? path.join(work, value.slice('/__w/'.length)) : value;
  if (typeof host !== 'string') throw Error('runner file path absent');
  const parent = fs.realpathSync(path.dirname(host));
  if (parent !== path.join(work, '_temp', folder)) throw Error('runner file outside its fixed directory');
  const info = fs.lstatSync(host);
  if (!info.isFile() || info.isSymbolicLink() || info.size > 1024 * 1024) throw Error('runner file is not bounded and plain');
  return host;
}
if (request.command === 'run_script_step') {
  if (!['bash', '/bin/bash', '/usr/bin/bash'].includes(request.args.entryPoint)) throw Error('only fixed bash operation markers are admitted');
  const files = request.args.entryPointArgs.filter(arg => arg.endsWith('.sh'));
  if (files.length !== 1) throw Error('one runner script is required');
  const text = fs.readFileSync(runnerFile(files[0], ''), 'utf8').trim();
  const match = /^stateengine-ci (changes|route|linux|check)$/.exec(text);
  if (!match) throw Error('unsupported CI script; no host execution occurred');
  request.operation = match[1];
}
request.context = Object.fromEntries(['GITHUB_REPOSITORY', 'GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT',
  'GITHUB_EVENT_NAME', 'GITHUB_REF']
  .map(name => [name, process.env[name]]));
// The job summary and annotations are the only place a seat can read a box
// result from: the controller log is root-only, and a hosted fallback used to
// look identical to a passing box. The controller cannot write these itself
// (its env is empty under sudo), so this hook publishes what it is told, and a
// fallback that gives no reason still says so rather than staying silent.
function announce(outputs, summary) {
  const lines = String(summary || '').trim().split('\n').filter(Boolean);
  const detail = lines.filter(line => !line.startsWith('{'));
  const level = outputs.status === 'passed' ? 'notice' : outputs.status === 'failed' ? 'error' : 'warning';
  const title = outputs.status === 'passed' ? 'Box Linux checks passed'
    : outputs.status === 'failed' ? 'Box Linux checks failed'
    : 'Box Linux checks unavailable; the complete hosted chain ran instead';
  console.log(`::${level} title=${title}::${detail.length ? detail.join(' ').slice(0, 900) : 'no reason was reported'}`);
  for (const line of detail) console.error(line);
  const target = process.env.GITHUB_STEP_SUMMARY;
  if (target) fs.appendFileSync(target, `### ${title}\n\n${detail.length ? detail.map(line => '- ' + line).join('\n') : 'No reason was reported.'}\n\n`);
}
async function execute() {
  let child, canceled = false, overflow = false;
  const forward = signal => {
    canceled = true;
    if (child?.pid) {
      try { child.kill(signal); }
      catch (error) { console.error(`Controller signal failed: ${error.code}; custody remains unresolved until join`); }
    }
  };
  const interrupt = () => forward('SIGINT'), terminate = () => forward('SIGTERM');
  process.on('SIGINT', interrupt); process.on('SIGTERM', terminate);
  let result, status, output = '', bytes = 0, summary;
  try {
    child = spawn('/usr/bin/sudo', ['-n', '-u', 'stateengine-ci-controller', '/usr/local/libexec/stateengine-ci-hook', slot],
      { stdio: ['pipe', 'pipe', 'inherit'] });
    child.stdin.on('error', () => {});
    child.stdout.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > 2 * 1024 * 1024) {
        if (!overflow) { overflow = true; forward('SIGTERM'); }
      } else output += chunk.toString();
    });
    const joined = new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (code, signal) => resolve({ code, signal }));
    });
    child.once('spawn', () => { if (canceled) forward('SIGTERM'); });
    child.stdin.end(JSON.stringify(request));
    // A runner cancellation targets this hook PID. Keep the handler and exact
    // sudo child alive until it forwards the signal and joins its controller.
    status = await joined;
    if (canceled || overflow) {
      console.error(`Canceled controller joined: code=${status.code} signal=${status.signal}`);
      return 1;
    }
    result = JSON.parse(output);
    summary = result.summary;
  } finally {
    process.removeListener('SIGINT', interrupt); process.removeListener('SIGTERM', terminate);
  }
  if (result.response) fs.writeFileSync(runnerFile(request.responseFile, '_runner_hook_responses'), JSON.stringify(result.response));
  if (result.outputs) {
    const target = runnerFile(request.args.environmentVariables.GITHUB_OUTPUT, '_runner_file_commands');
    for (const [name, value] of Object.entries(result.outputs)) {
      if (!/^(rust|windows|route|status)$/.test(name) || !/^(true|false|box|hosted|passed|failed|unavailable)$/.test(value)) throw Error('invalid fixed output');
      fs.appendFileSync(target, `${name}=${value}\n`);
    }
    announce(result.outputs, summary);
  } else if (result.exit_code !== 0) {
    // A controller that dies before it can classify its own work is still a
    // box result a seat has to read, and it used to leave the summary empty.
    announce({ status: 'unavailable' }, process.env.STATEENGINE_BOX_REASON
      || 'the box controller exited without a result; the hosted chain ran instead');
  }
  return status.code === 0 && result.exit_code === 0 ? 0 : 1;
}
execute().then(code => { process.exitCode = code; }, error => {
  // Same rule on the hook's own failure path: no silent job.
  announce({ status: 'unavailable' }, `the CI hook failed before a result: ${error.message}`);
  console.error(error.message); process.exitCode = 1;
});
