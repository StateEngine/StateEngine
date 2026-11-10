// The runner requires a JavaScript hook entrypoint. All workload and custody
// decisions stay in the fixed controller; no repository shell runs on the host.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const config = JSON.parse(fs.readFileSync('/etc/stateengine-ci/self-hosted.json', 'utf8'));
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
request.context = Object.fromEntries(['GITHUB_REPOSITORY', 'GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT']
  .map(name => [name, process.env[name]]));
const child = spawnSync('/usr/bin/sudo', ['-n', '-u', 'stateengine-ci-controller', '/usr/local/libexec/stateengine-ci-hook'],
  { input: JSON.stringify(request), encoding: 'utf8', maxBuffer: 2 * 1024 * 1024, stdio: ['pipe', 'pipe', 'inherit'] });
if (child.error) throw child.error;
const result = JSON.parse(child.stdout);
if (result.response) fs.writeFileSync(runnerFile(request.responseFile, '_runner_hook_responses'), JSON.stringify(result.response));
if (result.outputs) {
  const output = runnerFile(request.args.environmentVariables.GITHUB_OUTPUT, '_runner_file_commands');
  for (const [name, value] of Object.entries(result.outputs)) {
    if (!/^(rust|windows|route|status)$/.test(name) || !/^(true|false|box|passed|failed)$/.test(value)) throw Error('invalid fixed output');
    fs.appendFileSync(output, `${name}=${value}\n`);
  }
}

if (child.status !== 0 || result.exit_code !== 0) process.exit(child.status || result.exit_code || 1);
