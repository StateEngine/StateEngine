"""Count full image proofs through fresh native status commands; instrumentation only."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

data = Path(sys.argv[1])
data.mkdir()
source = data / 'source'
observer = Path(os.environ['HASH_COUNT_OBSERVER'])
revision = os.environ['HASH_SOURCE']
subprocess.run(['git', 'worktree', 'add', '--detach', str(source), revision], check=True)
assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip() == revision
image_source = source / 'crates/se-proc/src/native_ipc/image.rs'
text = image_source.read_text()
needle = 'pub(super) fn hash_image(file: std::fs::File, bound: &IpcIoBound) -> IpcNativeResult<Sha256> {'
assert text.count(needle) == 1
text = text.replace(needle, '#[track_caller]\n' + needle + '\n    let trace_started = std::time::Instant::now(); let trace_caller = std::panic::Location::caller();')
needle = '    let digest = Sha256::from_bytes(hasher.finalize().into());'
assert text.count(needle) == 1
text = text.replace(needle, needle + '\n    eprintln!("HASH_COUNT {}", serde_json::json!({"pid":std::process::id(),"kind":"full","bytes":read,"key":&stamp,"caller_file":trace_caller.file(),"caller_line":trace_caller.line(),"ms":trace_started.elapsed().as_secs_f64()*1000.0}));')
needle = '        return Ok(digest);'
assert text.count(needle) == 1
text = text.replace(needle, '        eprintln!("HASH_COUNT {}", serde_json::json!({"pid":std::process::id(),"kind":"cached","bytes":0,"key":&stamp,"caller_file":trace_caller.file(),"caller_line":trace_caller.line()}));\n' + needle)
image_source.write_text(text, encoding='utf-8')
peer = source / 'crates/se-proc/src/native_ipc/windows_peer.rs'
text = peer.read_text()
needle = '    let image_sha256 = hash_image('
assert text.count(needle) == 1
text = text.replace(needle, '    eprintln!("HASH_PEER {}", serde_json::json!({"pid":std::process::id(),"target_pid":pid}));\n' + needle)
peer.write_text(text, encoding='utf-8')
patch = subprocess.check_output(['git', 'diff', '--', 'crates/se-proc/src/native_ipc/image.rs', 'crates/se-proc/src/native_ipc/windows_peer.rs'], cwd=source)
(data / 'instrumentation.log').write_bytes(patch)
target = Path(os.environ['RUNNER_TEMP']) / 'hash-count-target'
args = ['cargo', 'build', '--locked', '-p', 'se', '--bin', 'se', '--profile', 'distribution',
        '--target', 'x86_64-pc-windows-msvc', '--target-dir', str(target)]
with (data / 'build.stdout').open('wb') as stdout, (data / 'build.stderr').open('wb') as stderr:
    result = subprocess.run(args, cwd=source, stdout=stdout, stderr=stderr, timeout=5400)
(data / 'build.json').write_text(json.dumps({'exit': result.returncode}) + '\n', encoding='utf-8')
result.check_returncode()
binary = target / 'x86_64-pc-windows-msvc/distribution/se.exe'
with binary.open('rb') as stream:
    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
image = {'image': str(binary), 'sha256': digest, 'bytes': binary.stat().st_size, 'source': revision}
(data / 'image.json').write_text(json.dumps(image, indent=2) + '\n', encoding='utf-8')
sys.path.insert(0, str(observer / 'scripts/startup_package'))
from observe import prepare, sample, stop

smokes = []
receipt = {'source': revision, 'image': image, 'instrumentation_sha256': hashlib.sha256(patch).hexdigest(),
           'samples': [], 'cleanup': [], 'failures': {},
           'scope': 'Author call-count diagnostics through fresh public status; instrumented shipping-profile build, not latency acceptance'}
try:
    smoke = prepare(data / 'fixture', image, smokes)
    for index in range(3):
        observed = sample(smoke, False, index)
        def events(raw, prefix):
            return [json.loads(line[len(prefix):]) for line in raw.splitlines() if line.startswith(prefix)]
        status = observed['peer_status']
        traces = events(status['stderr'], 'HASH_COUNT ')
        peers = events(status['stderr'], 'HASH_PEER ')
        assert status['exit'] == 0 and traces
        pids = {row['pid'] for row in traces}
        assert len(pids) == 1
        full = [row for row in traces if row['kind'] == 'full']
        receipt['samples'].append({'observation': observed, 'status_full_hashes': len(full),
                                   'status_proofs': traces, 'status_peer_targets': peers,
                                   'startup_proofs': events(observed['stderr'], 'HASH_COUNT ')})
        (data / 'count.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
finally:
    for smoke in smokes:
        closure = stop(smoke, 'final-down') if smoke.initialization_attempted else {'outside': smoke.commands.observer.observe()}
        assert closure['outside'] == []
        receipt['cleanup'].append(closure)
    (data / 'count.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
assert len(receipt['samples']) == 3
(data / 'paired-receipt.json').write_text(json.dumps({'failures': {}}) + '\n', encoding='utf-8')
print(json.dumps({'full_hashes': [row['status_full_hashes'] for row in receipt['samples']]}), flush=True)
