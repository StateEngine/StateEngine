import fs from 'node:fs';
import readline from 'node:readline';
import { cliOnce } from './nightly/cli-timing.mjs';
import { commandMap, commandArgs, readFacts } from './nightly/commands.mjs';

const settings = JSON.parse(fs.readFileSync(process.argv[2]));
const t = { cwd: settings.cwd, home: settings.home, env: settings.env,
  profile: { project: settings.project }, known: new Map(), unresolved: new Set(),
  product: { command_map: commandMap('rust', 'rust-v1') } };
const argv = [settings.binary, ...commandArgs(t, 'agents')];
if (JSON.stringify(argv) !== JSON.stringify(settings.argv)) throw Error('Nightly argv differs');
process.stdout.write(JSON.stringify({ ready: true, argv }) + '\n');
for await (const line of readline.createInterface({ input: process.stdin })) {
  if (line !== 'sample') throw Error('Unknown observation request');
  const sample = await cliOnce(t, argv);
  if (sample.code === 0 && !sample.error) {
    try { readFacts(t.product.command_map, 'agents', JSON.parse(sample.stdout)); }
    catch (error) { sample.error = error.message; }
  }
  process.stdout.write(JSON.stringify({ ...sample, error: sample.error ?? null, exit: sample.code,
    argv, unresolved: [...t.unresolved] }) + '\n');
}
if (t.unresolved.size) throw Error('Nightly probe has an unresolved child');
