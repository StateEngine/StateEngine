import { spawn } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { processes } from './platform.mjs';
import { redactOutput } from './credential-output.mjs';

// No census, instrumentation, disk writes or helper processes in the timed path.
// Startup-to-exit includes OS spawn and product work; pipe draining is separately bounded.
export async function cliOnce(t, argv, input = '') {
  return new Promise(resolve => {
    const start = performance.now(), child = spawn(argv[0], argv.slice(1), { cwd: t.cwd, env: t.env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    child.stdin.on('error', () => {}); child.stdin.end(input);
    let ms, settled = false, stdout = '', stderr = '', bytes = 0, timer, escalation;
    const finish = (code, error) => {
      if (settled) return; settled = true; clearTimeout(timer); clearTimeout(escalation);
      if (error) { child.unref(); child.stdout.destroy(); child.stderr.destroy(); }
      resolve(redactOutput({ ms, code, error, stdout, stderr, pid: child.pid }));
    };
    const stop = () => {
      const current = processes(t.home, [{ pid: child.pid }], 500).find(p => p.pid === child.pid);
      if (current?.parent === process.pid && current.command) {
        const again = processes(t.home, [current], 500).find(p => p.pid === current.pid);
        if (again?.birth === current.birth && again.command === current.command && again.parent === process.pid) {
          t.known.set(`${current.pid}:${current.birth}`, current); process.kill(current.pid, 'SIGKILL');
        }
      }
    };
    child.once('spawn', () => t.unresolved.add(child.pid));
    child.once('exit', () => { ms = performance.now() - start; });
    child.once('error', error => finish(null, error.message));
    child.once('close', code => { t.unresolved.delete(child.pid); finish(code); });
    for (const [stream, append] of [[child.stdout, value => stdout += value], [child.stderr, value => stderr += value]]) stream.on('data', chunk => {
      bytes += chunk.length;
      if (bytes <= 2 * 1024 * 1024) append(chunk.toString());
      else { try { stop(); } catch { /* Unverified identities remain in t.unresolved. */ } finish(null, 'read output bound exceeded'); }
    });
    timer = setTimeout(() => {
      try { stop(); } catch (error) { stderr += `\nTimeout identity: ${error.message}`; }
      escalation = setTimeout(() => finish(null, 'read command deadline'), 750);
    }, 10_000);
  });
}
