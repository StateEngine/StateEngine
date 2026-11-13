#!/usr/bin/env node
// Registry-installed native packages need no lifecycle script or runtime download.
import { lstatSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { constants } from 'node:os';

const require = createRequire(import.meta.url);
function fail(reason, next) {
  process.stderr.write(`StateEngine refused: ${reason}. ${next}\n`);
  process.exit(1);
}

let executable;
try {
  const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));
  const pins = JSON.parse(readFileSync(path.join(root, 'platforms.json'), 'utf8'));
  const platform = pins.platforms[`${process.platform}-${process.arch}`];
  if (!platform) fail(`unsupported platform ${process.platform}/${process.arch}`, 'Use a supported native release');
  if (process.platform === 'linux' && !process.report.getReport().header.glibcVersionRuntime) {
    fail('this release requires GNU/Linux with glibc', 'Use a supported native release');
  }
  let location;
  try { location = require.resolve(`${platform.package}/package.json`); }
  catch {
    fail(`the native optional package ${platform.package} is absent`,
      `Reinstall @stateengine/cli@${pkg.version} with optional dependencies enabled (--include=optional)`);
  }
  const nativeRoot = path.dirname(location);
  const nativePackage = JSON.parse(readFileSync(location, 'utf8'));
  if (nativePackage.name !== platform.package || nativePackage.version !== pkg.version) {
    throw new Error('native package name or version differs');
  }
  const entry = process.platform === 'win32' ? 'se.exe' : 'se';
  executable = path.join(nativeRoot, 'payload', entry);
  if (!lstatSync(executable).isFile()) throw new Error('native executable is not a regular file');
} catch (error) {
  fail(error.message, 'Reinstall @stateengine/cli from your configured registry; preserve your StateEngine data');
}
// Windows TerminateProcess bypasses JS handlers. The native entry retains this
// exact creator and stops itself if the wrapper disappears, without affecting
// independent services started by the CLI.
const args = process.platform === 'win32'
  ? ['__package-parent', String(process.pid), ...process.argv.slice(2)]
  : process.argv.slice(2);
const child = spawn(executable, args, { stdio: 'inherit', windowsHide: false });
const signals = ['SIGTERM', 'SIGINT', 'SIGHUP'];
const handlers = new Map();
for (const signal of signals) {
  const handler = () => {
    if (child.exitCode === null && child.signalCode === null) child.kill(signal);
  };
  handlers.set(signal, handler);
  process.on(signal, handler);
}
child.once('error', error => {
  fail(`cannot start the native executable: ${error.message}`, 'Check native OS requirements and reinstall the package');
});
child.once('close', (code, signal) => {
  for (const [name, handler] of handlers) process.removeListener(name, handler);
  if (signal) {
    if (process.platform !== 'win32') {
      try { process.kill(process.pid, signal); return; } catch { /* numeric fallback */ }
    }
    process.exit(128 + (constants.signals[signal] || 1));
  }
  if (code === null) fail('native completion was not observed', 'Retry the command and inspect its native error');
  process.exit(code);
});
