#!/usr/bin/env node
// Registry-installed native packages need no lifecycle script or runtime download.
import { createHash } from 'node:crypto';
import { closeSync, fstatSync, lstatSync, openSync, readFileSync, readSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const require = createRequire(import.meta.url);
function fail(reason, next) {
  process.stderr.write(`StateEngine refused: ${reason}. ${next}\n`);
  process.exit(1);
}
function hashFile(file, expectedBytes) {
  if (!lstatSync(file).isFile()) throw new Error('native payload is not a regular file');
  const fd = openSync(file, 'r');
  try {
    if (fstatSync(fd).size !== expectedBytes) throw new Error('native payload size differs');
    const hash = createHash('sha256');
    const buffer = Buffer.alloc(1024 * 1024);
    let total = 0;
    for (;;) {
      const count = readSync(fd, buffer, 0, buffer.length, null);
      if (!count) break;
      total += count;
      if (total > expectedBytes) throw new Error('native payload changed during read');
      hash.update(buffer.subarray(0, count));
    }
    if (total !== expectedBytes) throw new Error('native payload changed during read');
    return hash.digest('hex');
  } finally { closeSync(fd); }
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
  const manifestPath = path.join(nativeRoot, 'payload', 'native-payload.json');
  const manifestBytes = readFileSync(manifestPath);
  if (createHash('sha256').update(manifestBytes).digest('hex') !== platform.manifest_sha256) {
    throw new Error('native manifest checksum differs');
  }
  const manifest = JSON.parse(manifestBytes);
  const entry = process.platform === 'win32' ? 'se.exe' : 'se';
  if (manifest.schema !== 'stateengine.native-payload/v1' || manifest.version !== pkg.version
      || manifest.target !== platform.target || manifest.source_commit !== pins.source_commit
      || manifest.entry !== entry) throw new Error('native release identity differs');
  executable = path.join(nativeRoot, 'payload', entry);
  const record = manifest.files[entry];
  if (hashFile(executable, record.bytes) !== record.sha256) throw new Error('native executable checksum differs');
} catch (error) {
  fail(error.message, 'Reinstall @stateengine/cli from your configured registry; preserve your StateEngine data');
}
const result = spawnSync(executable, process.argv.slice(2), { stdio: 'inherit', windowsHide: false });
if (result.error) fail(`cannot start the native executable: ${result.error.message}`, 'Check native OS requirements and reinstall the package');
if (result.signal) {
  try { process.kill(process.pid, result.signal); }
  catch { process.exit(1); }
} else if (result.status === null) {
  fail('native completion was not observed', 'Retry the command and inspect its native error');
} else process.exit(result.status);
