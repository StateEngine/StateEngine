import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { requireTokenAbsent } from './credential-output.mjs';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');

// The scheduler checks the dedicated source before supplying this value. It
// belongs only in child environments, never in a native login file or receipt.
export function automationCredentials(home, environment, token, outputs = []) {
  if (typeof token !== 'string' || !token.trim() || token.trim().length > 16384
    || /[\s\u0000-\u0020]/u.test(token.trim())) throw Error('A bounded Claude automation token is required in the selected environment variable');
  const absent = () => {
    const directories = [home];
    while (directories.length) {
      const directory = directories.pop();
      for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        if (['.credentials.json', 'auth.json'].includes(entry.name.toLowerCase())) return false;
        // Inspect every real directory, including hidden configuration trees.
        // Links are leaves: never inspect files outside the private home.
        if (entry.isDirectory()) directories.push(path.join(directory, entry.name));
      }
    }
    return true;
  };
  if (!absent()) throw Error('Automation token journeys require a private home without provider credential files');
  environment.CLAUDE_CODE_OAUTH_TOKEN = token.trim();
  return () => {
    delete environment.CLAUDE_CODE_OAUTH_TOKEN;
    if (!absent()) throw Error('Automation token journey left a provider credential file; preserve the fixture for inspection');
    requireTokenAbsent([home, ...outputs], token.trim());
    return { transport: 'environment', credential_files_absent: true, output_token_absent: true, refresh_tokens_copied: false };
  };
}

// The native CLI may refresh or clear its store. Give it independent bytes and
// never a refresh token that could invalidate the normal account's login.
export function credentials(home, authHome, surface, credentialSource) {
  if (!['claude', 'codex'].includes(surface)) throw Error('Unknown credential surface');
  if (fs.realpathSync(home) === fs.realpathSync(authHome)) throw Error('Credential HOME must be private');
  const name = surface === 'claude' ? '.claude' : '.codex';
  const filename = surface === 'claude' ? '.credentials.json' : 'auth.json';
  if (credentialSource !== undefined && !path.isAbsolute(credentialSource)) throw Error('Credential source must be an absolute file path');
  const source = credentialSource ?? path.join(authHome, name, filename), target = path.join(home, name, filename);
  const sourceInfo = fs.lstatSync(source);
  if (!sourceInfo.isFile() || sourceInfo.isSymbolicLink()) throw Error(`Credential source is not a plain file: ${source}`);
  const bytes = fs.readFileSync(source), original = { digest: digest(bytes), dev: sourceInfo.dev, inode: sourceInfo.ino };
  const copy = JSON.parse(bytes.toString('utf8'), (key, value) => /^refresh_?token$/i.test(key) ? undefined : value);
  // Native Codex requires this string field even for an access-only copy.
  // An empty placeholder preserves its schema without copying a refresh token.
  if (surface === 'codex' && copy.tokens && typeof copy.tokens === 'object' && !Array.isArray(copy.tokens)) copy.tokens.refresh_token = '';
  if (surface === 'claude' && (typeof copy.claudeAiOauth?.accessToken !== 'string' || !copy.claudeAiOauth.accessToken.trim())) throw Error('Native Claude access token prerequisite missing');
  const directory = path.dirname(target);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  if (!fs.lstatSync(directory).isDirectory() || fs.lstatSync(directory).isSymbolicLink()) throw Error('Private credential directory is not plain');
  if (surface === 'claude') {
    const config = JSON.parse(fs.readFileSync(path.join(authHome, '.claude.json')),
      (key, value) => /^refresh_?token$/i.test(key) ? undefined : value);
    if (config.hasCompletedOnboarding !== true) throw Error('Complete native Claude onboarding before running journeys');
    const native = Object.fromEntries(['hasCompletedOnboarding', 'lastOnboardingVersion', 'oauthAccount']
      .filter(key => Object.hasOwn(config, key)).map(key => [key, config[key]]));
    const configPath = path.join(home, '.claude.json');
    let existing = {};
    try {
      const info = fs.lstatSync(configPath);
      if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) throw Error('Private Claude config must be a plain unlinked file');
      existing = JSON.parse(fs.readFileSync(configPath));
      if (!existing || typeof existing !== 'object' || Array.isArray(existing)) throw Error('Private Claude config must be an object');
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    // Public init already registered this project's MCP server. Keep that
    // configuration and add only native login metadata, using a private inode.
    const temporary = `${configPath}.${randomUUID()}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify({ ...existing, ...native }), { mode: 0o600, flag: 'wx' });
    try { fs.renameSync(temporary, configPath); }
    finally { fs.rmSync(temporary, { force: true }); }
  }
  fs.writeFileSync(target, JSON.stringify(copy), { mode: 0o600, flag: 'wx' });
  const privateInfo = fs.lstatSync(target);
  if (privateInfo.dev === original.dev && privateInfo.ino === original.inode) throw Error('Credential copy shares the original inode');
  return () => {
    const current = fs.lstatSync(source);
    const changed = !current.isFile() || current.isSymbolicLink() || current.dev !== original.dev
      || current.ino !== original.inode || digest(fs.readFileSync(source)) !== original.digest;
    // Unlink only the private entry, even when a native writer replaced it.
    try { fs.unlinkSync(target); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (changed) throw Error('Original credential store changed during the journey');
    return { original_inode_unchanged: true, original_digest_unchanged: true,
      private_copy_absent: !fs.existsSync(target), refresh_tokens_copied: false };
  };
}
