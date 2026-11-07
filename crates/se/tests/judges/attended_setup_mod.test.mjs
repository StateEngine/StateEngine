// Independent regressions for the production provider-native mail hooks.
// The API double preserves async reads and signed HTTP request/response behavior.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createHmac, webcrypto } from 'node:crypto';
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

globalThis.crypto ??= webcrypto;
const directory = path.dirname(fileURLToPath(import.meta.url));
const sourcePath = process.env.SE_ATTENDED_MOD ?? path.resolve(directory,
  '../../../se-host/src/harness/claude/bell.js');
let serial = 0;
const session = 'ses_01234567-89ab-7cde-8f01-23456789abcd';
async function fixture(prior) {
  const root = await mkdtemp(path.join(tmpdir(), 'attended-mod-'));
  const hold = path.join(root, 'hold.json');
  await writeFile(hold, JSON.stringify(prior));
  const config = { session, conversation: 'conversation', origin: 'http://127.0.0.1:21345',
    key: '11'.repeat(32), project: 'project', agent: 'agent', hold_file: hold,
    status_file: path.join(root, 'status.json') };
  const source = await readFile(sourcePath, 'utf8');
  const mod = await import('data:text/javascript;base64,' + Buffer.from(source + `\n// case ${serial++}`).toString('base64'));
  const hooks = new Map(), writes = [], requests = [], scheduled = [], local = new Map();
  const mac = text => createHmac('sha256', Buffer.from(config.key, 'hex')).update(text).digest('hex');
  const api = {
    plugin: { root }, env: { get: async () => session }, session: { id: async () => config.conversation },
    fs: { read: async file => file.endsWith('/claude-mail.json') ? JSON.stringify(config) : readFile(file, 'utf8'),
      write: writeFile },
    store: { get: async key => local.get(key), set: async (key, value) => { writes.push(value); local.set(key, value); } },
    command: { register: async () => {} }, ui: { status: () => {} },
    clock: { after: (_ms, callback) => scheduled.push(callback), now: async () => Date.now() },
    http: { fetch: async (url, options) => {
      const h = options.headers, body = options.body ?? '';
      assert.equal(h['x-se-mail-proof'], mac(`se.claude.mail.request/v1\n${options.method}\n${url}\n${session}\n${h['x-se-mail-time']}\n${h['x-se-mail-nonce']}\n${body}`));
      requests.push(JSON.parse(body));
      const text = JSON.stringify({ held: true });
      return { ok: true, status: 200, text, headers: { 'x-se-mail-proof': mac(`se.claude.mail.response/v1\n${session}\n${h['x-se-mail-nonce']}\n200\n${text}`) } };
    } },
  };
  mod.register((name, ...rest) => hooks.set(name, rest.at(-1)));
  const result = { provider: 'original hook result' };
  assert.equal(await hooks.get('session.start')(api, {}, async () => result), result,
    'onboarding hook must preserve the provider result');
  return { hooks, api, result, requests, writes, scheduled,
    read: async () => JSON.parse(await readFile(hold, 'utf8')),
    close: () => rm(root, { recursive: true }) };
}

for (const held of [false, true]) {
  test(`expired setup session-end preserves prior held=${held} without adding local or durable hold`, async () => {
    const prior = { held, reason: held ? 'human-stop' : null, expired_setup: session };
    const f = await fixture(prior);
    try {
      assert.equal(await f.hooks.get('session.end')(f.api, {}, async () => f.result), f.result);
      assert.deepEqual(await f.read(), prior);
      assert.deepEqual(f.requests, []);
      assert.deepEqual(f.writes, []);
      if (held) assert.equal(f.scheduled.length, 0, 'prior hold prevents automatic wait');
    } finally { await f.close(); }
  });
}
test('explicit human stop still holds an expired setup', async () => {
  const f = await fixture({ held: false, expired_setup: session });
  try {
    await f.hooks.get('turn.complete')(f.api, { isAborted: true }, async () => f.result);
    assert.deepEqual(f.requests, [{ hold: 'human-stop' }]);
    assert.deepEqual(f.writes, [true]);
  } finally { await f.close(); }
});
test('another session expiry cannot suppress the current session-end hold', async () => {
  const f = await fixture({ held: false, expired_setup: 'ses_ffffffff-ffff-7fff-8fff-ffffffffffff' });
  try {
    await f.hooks.get('session.end')(f.api, {}, async () => f.result);
    assert.deepEqual(f.requests, [{ hold: 'session-end' }]);
    assert.deepEqual(f.writes, [true]);
  } finally { await f.close(); }
});
