// Protects: installed mail hooks preserve results, expiry holds and actual mail wake.
// HTTP authentication and durable holds still use the actual native host.
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { webcrypto } from 'node:crypto';

globalThis.crypto ??= webcrypto;
const [configPath, action] = process.argv.slice(2);
const config = JSON.parse(await readFile(configPath, 'utf8'));
const home = path.resolve(configPath, '../../..');
const pluginParent = path.join(home, 'claude-mail');
const { readdir } = await import('node:fs/promises');
const versions = (await readdir(pluginParent)).filter(name => name.startsWith('v1-'));
assert.equal(versions.length, 1, 'one exact installed mod');
const root = path.join(pluginParent, versions[0]);
const source = await readFile(path.join(root, 'hooks/register.js'), 'utf8');
const mod = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
const handlers = new Map(), queue = [], prompts = [], store = new Map();
const api = {
  plugin: { root }, env: { get: async () => config.session },
  session: { id: async () => config.conversation },
  fs: { read: file => readFile(file, 'utf8'), write: writeFile },
  store: { get: async key => store.get(key), set: async (key, value) => store.set(key, value) },
  ui: { status: () => {} }, command: { register: async () => {} },
  clock: { now: async () => Date.now(), after: (_ms, callback) => queue.push(callback),
    sleep: ms => new Promise(resolve => setTimeout(resolve, ms)) },
  prompt: { submit: async ({ text }) => { prompts.push(text); } },
  http: { fetch: async (url, options) => {
    const response = await fetch(url, options);
    return { status: response.status, ok: response.ok,
      text: await response.text(), headers: Object.fromEntries(response.headers) };
  } },
};
mod.register((name, ...rest) => handlers.set(name, rest.at(-1)));
const result = { provider: 'session-start-result' };
assert.equal(await handlers.get('session.start')(api, {}, async () => result), result);
if (action === 'human') {
  await handlers.get('turn.complete')(api, { isAborted: true }, async () => result);
} else if (action === 'expired-end') {
  await handlers.get('session.end')(api, {}, async () => result);
} else if (action === 'wake') {
  for (const callback of queue.splice(0)) callback();
  const until = Date.now() + 30000;
  while (prompts.length === 0 && Date.now() < until) await new Promise(resolve => setTimeout(resolve, 50));
  assert.ok(prompts.length, 'actual signed mail page must offer a prompt');
  await handlers.get('session.end')(api, {}, async () => result);
} else {
  assert.equal(action, 'held');
  assert.equal(queue.length, 0, 'held successor must not start an authenticated wait');
}
process.stdout.write(JSON.stringify({ retained: true, scheduled: queue.length, prompts }) + '\n');
process.exit(0);
