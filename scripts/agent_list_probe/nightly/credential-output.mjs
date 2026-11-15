import fs from 'node:fs';
import path from 'node:path';
import { Transform } from 'node:stream';

export function redactOutput(value, token = process.env.CLAUDE_CODE_OAUTH_TOKEN?.trim()) {
  if (!token) return value;
  if (typeof value === 'string') return value.replaceAll(token, '<redacted-automation-token>'.includes(token) ? '' : '<redacted-automation-token>');
  if (Array.isArray(value)) return value.map(item => redactOutput(item, token));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value)
    .map(([key, item]) => [redactOutput(key, token), redactOutput(item, token)]));
  return value;
}

// Hold a possible token prefix across chunk boundaries, including UTF-8 splits.
export function redactedStream(stream, token = process.env.CLAUDE_CODE_OAUTH_TOKEN?.trim()) {
  if (!token) return stream;
  const needle = Buffer.from(token), replacement = Buffer.from(redactOutput(token, token));
  let pending = Buffer.alloc(0);
  return stream.pipe(new Transform({
    transform(chunk, encoding, done) {
      pending = Buffer.concat([pending, chunk]);
      let index;
      while ((index = pending.indexOf(needle)) !== -1) {
        this.push(pending.subarray(0, index)); this.push(replacement);
        pending = pending.subarray(index + needle.length);
      }
      let keep = Math.min(pending.length, needle.length - 1);
      while (keep && !pending.subarray(pending.length - keep).equals(needle.subarray(0, keep))) keep--;
      const safe = pending.length - keep;
      this.push(pending.subarray(0, safe)); pending = pending.subarray(safe); done();
    },
    flush(done) { this.push(pending); done(); },
  }));
}

export function requireTokenAbsent(roots, token) {
  const needle = Buffer.from(token), stack = [...roots];
  try {
    while (stack.length) {
      const file = stack.pop(), info = fs.lstatSync(file);
      if (path.basename(file).includes(token)) throw Error('Automation token found in an output filename; preserve the private fixture and remove the exposed token before retrying');
      if (info.isSymbolicLink()) continue;
      if (info.isDirectory()) {
        for (const name of fs.readdirSync(file)) stack.push(path.join(file, name));
      } else if (info.isFile()) {
        const descriptor = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
        try {
          const before = fs.fstatSync(descriptor);
          if (!before.isFile()) throw Error('Automation output scan requires regular files');
          let tail = Buffer.alloc(0), length;
          const chunk = Buffer.alloc(65536); let remaining = before.size;
          while (remaining > 0) {
            length = fs.readSync(descriptor, chunk, 0, Math.min(chunk.length, remaining));
            if (!length) throw Error('Automation output changed during its scan; preserve the private fixture for inspection');
            remaining -= length;
            const bytes = Buffer.concat([tail, chunk.subarray(0, length)]);
            if (bytes.includes(needle)) throw Error('Automation token found in retained output; preserve the private fixture and remove the exposed token before retrying');
            tail = bytes.subarray(Math.max(0, bytes.length - needle.length + 1));
          }
          const after = fs.fstatSync(descriptor);
          if (before.size !== after.size || before.mtimeMs !== after.mtimeMs) throw Error('Automation output changed during its scan; preserve the private fixture for inspection');
        } finally { fs.closeSync(descriptor); }
      } else throw Error('Automation output scan encountered a non-regular file; preserve the private fixture for inspection');
    }
  } catch (error) {
    if (error.code) throw Error(`Automation output scan unavailable (${error.code}); preserve the private fixture for inspection`);
    throw error;
  }
}
