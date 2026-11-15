"""Add opt-in timestamp probes to a disposable source tree, never the product PR."""
from pathlib import Path
import subprocess
import sys


def replace(root, name, old, new):
    path = root / name
    text = path.read_text()
    if text.count(old) != 1:
        raise ValueError('Probe anchor is not unique: ' + name)
    path.write_text(text.replace(old, new))


def apply(root):
    helper = root / 'crates/se-host/src/output_observer.rs'
    helper.write_text('''//! Disposable measurement probes, absent from the product revision.
use std::io::Write;
pub fn record(stage: &str, bytes: &[u8]) {
    static LOG: std::sync::OnceLock<Option<std::sync::Mutex<std::fs::File>>> = std::sync::OnceLock::new();
    let log = LOG.get_or_init(|| std::env::var_os("OUTPUT_OBSERVER_TRACE").and_then(|path|
        std::fs::OpenOptions::new().create(true).append(true).open(path).ok()).map(std::sync::Mutex::new));
    let Some(log) = log else { return; };
    let Ok(us) = se_proc::monotonic_micros() else { return; };
    let mut seen = std::collections::BTreeSet::new();
    for window in bytes.windows(18) {
        if window.starts_with(b"output-probe-") && window[13..].iter().all(u8::is_ascii_digit) {
            seen.insert(String::from_utf8_lossy(window).into_owned());
        }
    }
    if seen.is_empty() { return; }
    let Ok(mut file) = log.lock() else { return; };
    for id in seen { writeln!(file, "{stage} {id} {us} {}", std::process::id()).expect("probe write"); }
}
''')
    path = root / 'crates/se-host/src/lib.rs'
    path.write_text(path.read_text() + '\npub mod output_observer;\n')
    replace(root, 'crates/se/src/runtime/host/environment.rs',
            '    let mut entries = se_host::provider_environment();',
            '    let mut entries = se_host::provider_environment();\n    if let Some(path) = std::env::var_os("OUTPUT_OBSERVER_TRACE") {\n        entries.push(("OUTPUT_OBSERVER_TRACE".into(), path));\n    }')
    replace(root, 'crates/se-host/src/harness/claude_harness/completion.rs',
            '        #[derive(serde::Deserialize)]\n',
            '        crate::output_observer::record("stream_read", line);\n        #[derive(serde::Deserialize)]\n')
    replace(root, 'crates/se-host/src/runtime/capture/source/scan.rs',
            '            let decoded = claude::decode(&line, &source.binding.conversation)?;',
            '            crate::output_observer::record("transcript_read", &line);\n            let decoded = claude::decode(&line, &source.binding.conversation)?;')
    replace(root, 'crates/se-host/src/runtime/capture/batch.rs',
            '                capture.request.recovery_owner = self.recovery_owner.clone();',
            '                crate::output_observer::record("capture_ready", capture.request.text.as_str().as_bytes());\n                capture.request.recovery_owner = self.recovery_owner.clone();')
    replace(root, 'crates/se-host/src/remote/publish.rs',
            '            state.drain_pending();\n        }',
            '            state.drain_pending();\n        }\n        crate::output_observer::record("published", text.as_bytes());')
    replace(root, 'crates/se-host/src/remote/service/watch.rs',
            '        let length = wire::encode(&batch, wire::Phase::Authenticated)?.len();',
            '        crate::output_observer::record("watch_page_ready", &serde_json::to_vec(&batch).expect("probe batch"));\n        let length = wire::encode(&batch, wire::Phase::Authenticated)?.len();')
    replace(root, 'crates/se-host/src/ipc/listener/connection.rs',
            '        self.awaiting = None;\n',
            '        crate::output_observer::record("ipc_response_flushed", frame.as_bytes());\n        self.awaiting = None;\n')
    replace(root, 'crates/se/src/remote/mod.rs',
            '                stdout.flush()?;\n                if measured',
            '                stdout.flush()?;\n                if let AnyOutput::RemoteWatch(v) = &output {\n                    se_host::output_observer::record("stdout_flushed", &serde_json::to_vec(&v.value).expect("probe render"));\n                }\n                if measured')
    return subprocess.check_output(['git', 'diff', '--no-ext-diff'], cwd=root)


if __name__ == '__main__':
    apply(Path(sys.argv[1]))
