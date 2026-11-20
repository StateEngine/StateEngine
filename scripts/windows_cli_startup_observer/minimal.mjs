import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

const [binaryArg, outputArg, countArg = '200'] = process.argv.slice(2);
const binary = path.resolve(binaryArg), output = path.resolve(outputArg);
const count = Number(countArg), clock = () => Number(process.hrtime.bigint() / 1000n);
assert(Number.isSafeInteger(count) && count >= 8 && count % 8 === 0);
fs.mkdirSync(output, { recursive: true });
let inFlight = 0, peak = 0;
async function sample() {
  const startMs = performance.now(), spawned = clock();
  inFlight++; peak = Math.max(peak, inFlight);
  return await new Promise((resolve, reject) => {
    const child = spawn(binary, [], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
    child.stdout.on('data', data => { stdout += data; });
    child.stderr.on('data', data => { stderr += data; });
    child.on('error', reject);
    child.on('close', (code, signal) => {
      const exited = clock(), elapsed = performance.now() - startMs;
      inFlight--;
      try {
        assert.equal(code, 0); assert.equal(signal, null); assert.equal(stderr, '');
        assert.match(stdout, /^\d+\r?\n$/);
        const entry = Number(stdout.trim());
        assert(Number.isSafeInteger(entry) && spawned <= entry && entry <= exited);
        const points = Array(13).fill(entry);
        resolve({ pid: child.pid, spawned_us: spawned, exited_us: exited, duration_ms: elapsed,
          verified: true, phases: { cli_us: points } });
      } catch (error) { reject(error); }
    });
  });
}
for (const clients of [1, 8]) {
  peak = 0;
  const lanes = Array.from({ length: clients }, async () => {
    const rows = [];
    for (let i = 0; i < count / clients; i++) rows.push(await sample());
    return rows;
  });
  const samples = (await Promise.all(lanes)).flat();
  assert.equal(samples.length, count); assert.equal(peak, clients);
  fs.writeFileSync(path.join(output, `cohort-${clients}.json`), JSON.stringify({
    complete: true, observed_peak: peak, samples,
  }, null, 2) + '\n');
}
