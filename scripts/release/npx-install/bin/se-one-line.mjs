#!/usr/bin/env node
// npx route of the one-shot install. Like the shell one-liners it keeps no
// state of its own: fetch the release index, download the signed package for
// this platform, verify its published checksum and its signature, and hand
// off to `secode update --from`. It installs signed releases only. It needs
// Node by definition, so it is the extra route, not a first-hour route. The
// base URL is a release-time setting: the published script carries it, or set
// SE_RELEASE_BASE for a local release server.
import { createHash, createPublicKey, createVerify } from 'node:crypto';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

function fail(message) {
  process.stderr.write(`Install refused: ${message}\n`);
  process.exit(1);
}

// Release-time settings: the release job stamps these two values when it
// publishes. Nothing is published until then.
const SE_RELEASE_BASE_DEFAULT = '';
const SE_RELEASE_PUBLIC_KEY_B64_DEFAULT = ''; // base64 DER/SPKI RSA public key

const base = (process.argv[2] ?? process.env.SE_RELEASE_BASE ?? SE_RELEASE_BASE_DEFAULT).replace(/\/+$/, '');
if (!/^https?:\/\//.test(base)) {
  fail('no release base URL is set; the release host stamps this script when it publishes, or set SE_RELEASE_BASE for a local release server');
}
let target;
if (process.platform === 'linux' && process.arch === 'x64') target = 'x86_64-unknown-linux-gnu';
else if (process.platform === 'darwin' && process.arch === 'arm64') target = 'aarch64-apple-darwin';
else if (process.platform === 'darwin' && process.arch === 'x64') target = 'x86_64-apple-darwin';
else if (process.platform === 'win32' && process.arch === 'x64') target = 'x86_64-pc-windows-msvc';
else fail(`this machine is not supported by this route: ${process.platform}/${process.arch}`);
const windows = process.platform === 'win32';
const archiveExt = windows ? '.zip' : '.tar.gz';
const pubKeyB64 = process.env.SE_RELEASE_PUBLIC_KEY_B64 || SE_RELEASE_PUBLIC_KEY_B64_DEFAULT;

const work = mkdtempSync(path.join(tmpdir(), 'se-one-line-'));
try {
  process.stdout.write(`Fetching the release index from ${base}\n`);
  let index;
  try {
    index = await (await fetch(`${base}/releases/index.json`)).json();
  } catch {
    fail(`cannot reach ${base}/releases/index.json; check the URL and your network connection, then rerun`);
  }
  if (index?.schema !== 'secode.release-index.v1') fail('the release index is not a readable secode.release-index.v1 document; do not install from it');
  if (!index?.version) fail('the release index names no version; do not install from it');
  const entry = index?.packages?.[target];
  if (!entry?.url || !/^[0-9a-f]{64}$/.test(entry?.sha256 ?? '')) {
    fail(`the release index has no verified package entry for this platform (${target}); supported targets are in the index`);
  }
  if (!entry?.signature) fail('the release index names no signature for this platform; this route only installs signed releases');
  const trust = typeof index?.trust === 'string' ? index.trust : '';
  if (!trust.startsWith('signed:')) {
    fail('this release is not signed; this route only installs signed releases, so check back when the signed release is published');
  }
  const scheme = trust.slice('signed:'.length);
  if (scheme !== 'rsa-sha256') fail(`signature scheme ${scheme} is not supported by this installer build; do not install until the installer names it`);
  if (!pubKeyB64) fail('no public verification key is set for this release; this route only installs signed releases, so check back when the signed release is published');
  const archiveUrl = /^https?:\/\//.test(entry.url) ? entry.url : `${base}${entry.url}`;
  if (!archiveUrl.endsWith(archiveExt)) fail(`the release package URL for ${target} must end in ${archiveExt}: ${entry.url}`);
  const sigUrl = /^https?:\/\//.test(entry.signature) ? entry.signature : `${base}${entry.signature}`;

  process.stdout.write(`Downloading ${path.basename(archiveUrl)} (release ${index.version})...\n`);
  let bytes;
  try {
    bytes = Buffer.from(await (await fetch(archiveUrl)).arrayBuffer());
  } catch {
    fail(`the download from ${archiveUrl} failed; check your network connection and rerun`);
  }
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== entry.sha256) {
    fail('the downloaded package does not match its published checksum; do not bypass this check, rerun, and if it repeats tell the maintainer which version you installed');
  }
  const archivePath = path.join(work, `package${archiveExt}`);
  writeFileSync(archivePath, bytes);

  process.stdout.write(`Verifying the signature (${scheme})...\n`);
  let sigBytes;
  try {
    sigBytes = Buffer.from(await (await fetch(sigUrl)).arrayBuffer());
  } catch {
    fail(`the signature from ${sigUrl} could not be downloaded; do not install unsigned-by-omission, rerun`);
  }
  let key;
  try {
    key = createPublicKey({ key: Buffer.from(pubKeyB64, 'base64'), format: 'der', type: 'spki' });
  } catch {
    fail('the release public key is not readable base64; do not install from it');
  }
  let signatureOk = false;
  try {
    const verifier = createVerify('RSA-SHA256');
    verifier.update(bytes);
    signatureOk = verifier.verify(key, sigBytes);
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) fail('the package signature does not verify against the release key; do not install it, and tell the maintainer which version you tried');

  process.stdout.write('Extracting and checking the package...\n');
  const extracted = path.join(work, 'pkg');
  mkdirSync(extracted);
  if (windows) {
    const quoted = (p) => `'${p.replace(/'/g, "''")}'`;
    const command = `Expand-Archive -LiteralPath ${quoted(archivePath)} -DestinationPath ${quoted(extracted)} -Force`;
    const powershell = spawnSync('powershell.exe', ['-NoProfile', '-NoLogo', '-Command', command], { stdio: 'inherit' });
    if (powershell.status !== 0) fail('the package is not a readable zip archive; the release is corrupt, do not install it');
  } else {
    const tar = spawnSync('tar', ['-xzf', archivePath, '-C', extracted], { stdio: 'inherit' });
    if (tar.status !== 0) fail('the package is not a readable tar.gz archive; the release is corrupt, do not install it');
  }
  let entries;
  try {
    entries = readdirSync(extracted, { withFileTypes: true });
  } catch {
    fail('the package must hold exactly one top-level folder; this one does not, so do not install it');
  }
  const dirs = entries.filter((e) => e.isDirectory());
  if (dirs.length !== 1) fail('the package must hold exactly one top-level folder; this one does not, so do not install it');
  const pkgRoot = path.join(extracted, dirs[0].name);
  const secode = path.join(pkgRoot, windows ? 'secode.exe' : 'secode');
  const secodeStat = statSync(secode, { throwIfNoEntry: false });
  if (!secodeStat) fail('the package is missing its installer command (secode); do not install it');
  if (!windows && (secodeStat.mode & 0o111) === 0) fail('the package installer command (secode) is not marked executable; do not install it');

  let bundlesSe = false;
  const payload = path.join(pkgRoot, 'stateengine', 'stateengine-payload.json');
  if (statSync(payload, { throwIfNoEntry: false })) {
    let payloadJson;
    try {
      payloadJson = JSON.parse(readFileSync(payload, 'utf8'));
    } catch {
      fail('the package carries a StateEngine payload that is not a readable stateengine.se-payload.v1 manifest; do not install it');
    }
    if (payloadJson?.schema !== 'stateengine.se-payload.v1') {
      fail('the package carries a StateEngine payload that is not a readable stateengine.se-payload.v1 manifest; do not install it');
    }
    bundlesSe = true;
  }

  process.stdout.write(`Installing release ${index.version} as your normal user...\n`);
  const rc = spawnSync(secode, ['update', '--from', pkgRoot], { stdio: 'inherit' }).status;
  if (rc !== 0) fail(`the installer stopped (exit ${rc}); read the message it printed above, do what it says, and rerun`);
  process.stdout.write(bundlesSe
    ? 'Installed. Open a new terminal and run: se --version\n'
    : 'Installed SE Code without the StateEngine engine; se is not available in this package. Open a new terminal and run: secode --version\n');
} finally {
  rmSync(work, { recursive: true, force: true });
}
