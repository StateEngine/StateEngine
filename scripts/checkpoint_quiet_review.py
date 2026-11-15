"""Run independent quiet-period controls on pinned native base and candidate."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PINS = dict(base='737bee8caf03e17d2a61e21594d7b0285d6619dc',
            candidate='906ca100f773a8d824a47905f0f700d38de3f63c')
UNIT = 'crates/se-store/src/checkpoint_task/quiet_period_review.rs'
PUBLIC = 'crates/se-store/tests/quiet_period_public_review.rs'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    output = Path(sys.argv[1]).resolve()
    output.mkdir(parents=True, exist_ok=False)
    target = subprocess.check_output(['rustc', '--print', 'host-tuple'], text=True).strip()
    require_native = ('x86_64-unknown-linux-gnu', 'x86_64-pc-windows-msvc')
    if target not in require_native:
        raise ValueError('This judge requires native Linux or Windows')
    environment = dict(os.environ, CARGO_TARGET_DIR=str(output / 'target'))
    receipt = dict(target=target, judge_commit=subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(), pins=PINS,
        judge_sha256={name: digest(ROOT / name) for name in (UNIT, PUBLIC)}, sides={})
    for side, source in PINS.items():
        tree = output / ('source-' + side)
        subprocess.run(['git', 'worktree', 'add', '--detach', str(tree), source],
                       cwd=ROOT, check=True)
        original = tree / 'crates/se-store/src/checkpoint_task.rs'
        evidence = dict(source=source, original_checkpoint_sha256=digest(original), commands={})
        for name in (UNIT, PUBLIC):
            destination = tree / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
            if digest(destination) != receipt['judge_sha256'][name]:
                raise ValueError('Judge overlay differs')
        with original.open('a') as stream:
            stream.write('\n#[cfg(test)]\n#[path = "checkpoint_task/quiet_period_review.rs"]\nmod quiet_period_review;\n')
        commands = dict(
            scheduling=['--lib', 'quiet_period_review'],
            public=['--test', 'quiet_period_public_review'],
            retained=['--test', 'background_checkpoint_independent', '--test', 'deferred_checkpoint_independent'])
        for label, arguments in commands.items():
            argv = ['cargo', 'test', '--target', target, '--release', '--locked',
                    '--all-features', '-p', 'se-store', *arguments,
                    '--', '--show-output', '--test-threads=1']
            log = output / f'{side}-{label}.log'
            with log.open('wb') as stream:
                result = subprocess.run(argv, cwd=tree, env=environment,
                                        stdout=stream, stderr=subprocess.STDOUT, timeout=1800)
            text = log.read_text(errors='replace')
            cases = dict(re.findall(r'^test ([\w:]+) \.\.\. (ok|FAILED)$', text, re.M))
            evidence['commands'][label] = dict(exit=result.returncode, cases=cases,
                log_sha256=digest(log), compiled='Finished ' in text,
                test_summaries=re.findall(r'^test result: .+$', text, re.M))
            receipt['sides'][side] = evidence
            save(output / 'receipt.json', receipt)
    base, candidate = (receipt['sides'][name]['commands'] for name in ('base', 'candidate'))
    required_failures = ['an_idle_edge_requires_a_full_quiet_interval',
                         'new_idle_edges_restart_quiet_even_with_retry_debt']
    baseline_discriminates = (base['scheduling']['compiled'] and
        all(any(name.endswith('::' + suffix) and state == 'FAILED'
                for name, state in base['scheduling']['cases'].items()) for suffix in required_failures))
    candidate_passes = all(row['exit'] == 0 and row['compiled'] and row['cases']
                           and all(value == 'ok' for value in row['cases'].values())
                           for row in candidate.values())
    expected_retained = 6 if target.endswith('windows-msvc') else 7
    candidate_passes = candidate_passes and len(candidate['scheduling']['cases']) == 5 and len(candidate['public']['cases']) == 1 and len(candidate['retained']['cases']) == expected_retained
    retained_base_passes = base['retained']['exit'] == 0 and len(base['retained']['cases']) == expected_retained
    receipt.update(baseline_discriminates=baseline_discriminates,
                   candidate_passes=candidate_passes, retained_base_passes=retained_base_passes,
                   qualified=baseline_discriminates and candidate_passes and retained_base_passes)
    save(output / 'receipt.json', receipt)
    print(json.dumps(receipt), flush=True)
    if not receipt['qualified']:
        raise ValueError('Independent native quiet-period judging did not qualify')


if __name__ == '__main__':
    main()
