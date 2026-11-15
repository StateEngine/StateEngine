import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

export function expand(value, context) {
  if (Array.isArray(value)) return value.map(v => expand(v, context));
  return value.replace(/\{([a-z_]+)\}/g, (_, name) => {
    if (!Object.hasOwn(context, name)) throw Error(`Unknown product placeholder {${name}}`);
    return String(context[name]);
  });
}

// A map translates spelling and field paths only. It cannot supply response
// values, success flags, expected effects, thresholds or executable decoders.
export function commandMap(profile, supplied) {
  if (!['node', 'rust'].includes(profile) || supplied !== `${profile}-v1`) throw Error('Select only the shipped node-v1 or rust-v1 command_map by name');
  const map = JSON.parse(fs.readFileSync(new URL(`./maps/${profile}.json`, import.meta.url)));
  if (map.format !== 'journey-commands/v1' || map.implementation !== profile) throw Error('Shipped command map/profile mismatch');
  return map;
}

export function mapDigest(map) {
  return createHash('sha256').update(JSON.stringify(map, null, 2)).digest('hex');
}

export function family(map, action, value) {
  if (map.schemas[action] && value?.schema !== map.schemas[action]) throw Error(`Wrong public family for ${action}`);
  if (!value || typeof value !== 'object' || value.ok === false || value.schema === 'se.error/v1') throw Error(`Refused/invalid ${action} response`);
  return value;
}

export function commandArgs(t, name, variables = {}, json = true) {
  const map = t.product.command_map, action = map.actions[name];
  if (!action) throw Error(`Unmapped journey action ${name}`);
  const context = { ...t.profile, home: t.home, state_home: path.join(t.home, 'stateengine-state'), repo: t.cwd, ...variables };
  const args = [...expand(action.argv, context), ...expand(map.globals, context), ...(action.context ? expand(map.context, context) : [])];
  if (variables.cursor !== undefined) {
    if (!action.cursor) throw Error(`No public continuation for ${name}`);
    args.push(...expand(action.cursor, context));
  }
  if (action.model && t.model) args.push('--model', t.model);
  if (json) args.push('--json');
  return args;
}

export function field(map, view, name, value) {
  const pointer = map.fields?.[view]?.[name];
  if (!pointer) throw Error(`Unresolved ${map.implementation} output contract: ${view}.${name}`);
  let current = value;
  for (const key of pointer.split('.')) {
    if (!current || typeof current !== 'object' || !Object.hasOwn(current, key)) throw Error(`Missing public fact ${view}.${name} at ${pointer}`);
    current = current[key];
  }
  return current;
}

export function record(map, view, names, value) {
  return Object.fromEntries(names.map(name => [name, field(map, view, name, value)]));
}

export function completeMessages(map, value, { pageValidated = false } = {}) {
  const rows = field(map, 'messages', 'items', value);
  if (!Array.isArray(rows)) throw Error('Message list has no explicit array');
  if (map.implementation === 'node') {
    if (field(map, 'messages', 'skipped_invalid', value) !== 0 || value.truncated === true) throw Error('Message evidence is incomplete');
  } else if (!pageValidated) completePage(map, 'messages', value);
  return rows.map(row => {
    const result = record(map, 'message', ['msg_id', 'from_seat', 'to_seat', 'kind', 'body'], row);
    if (map.implementation === 'rust' && field(map, 'message', 'body_complete', row) !== true) throw Error('Message body incomplete');
    if (map.implementation === 'rust' && field(map, 'message', 'unreadable', row) !== null) throw Error('Message row unreadable');
    if (Object.values(result).some(v => typeof v !== 'string')) throw Error('Invalid message identity/body');
    return result;
  });
}

export function completePage(map, view, value) {
  if (field(map, view, 'complete', value) !== true || field(map, view, 'omitted', value) !== 0
    || field(map, view, 'reason', value) !== null || field(map, view, 'next', value) !== null) throw Error(`${view} evidence is incomplete`);
}

export function readFacts(map, action, value) {
  family(map, action, value);
  if (action === 'status') {
    if (typeof field(map, 'runtime', 'state', value) !== 'string') throw Error('Unreadable runtime state');
    const pid = field(map, 'runtime', 'pid', value);
    if (!Number.isSafeInteger(pid) || pid <= 0) throw Error('Read has no running host identity');
    return;
  }
  const view = { agents: 'agents', inbox: 'inbox', messages: 'messages', decisions: 'decisions' }[action];
  const rows = field(map, view, 'items', value);
  if (!Array.isArray(rows)) throw Error(`Unreadable ${view} items`);
  if (map.implementation === 'rust') completePage(map, view, value);
  if (action === 'messages') completeMessages(map, value);
  if (action === 'inbox' && map.implementation === 'node' && field(map, 'inbox', 'complete', value) !== true) throw Error('Inbox read incomplete');
  for (const row of rows) {
    const rowView = action === 'agents' ? 'agent' : action === 'decisions' ? 'decision_row' : 'message';
    const id = field(map, rowView, action === 'agents' ? 'agent_id' : action === 'decisions' ? 'id' : 'msg_id', row);
    if (typeof id !== 'string' || !id) throw Error(`Unreadable ${view} row identity`);
    const names = action === 'agents' ? ['name'] : action === 'decisions' ? ['body'] : ['from_seat', 'to_seat', 'kind'];
    for (const name of names) if (typeof field(map, rowView, name, row) !== 'string') throw Error(`Unreadable ${view} ${name}`);
    if (map.implementation === 'rust' && action !== 'agents' && field(map, rowView, 'unreadable', row) !== null) throw Error(`Unreadable ${view} row`);
  }
}
