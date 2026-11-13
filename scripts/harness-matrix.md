# Native harness smoke matrix

The matrix runs installed public commands against an extracted native distribution.
Each selected harness must launch, complete a real file task, exchange an authenticated
owner message, and resume the same provider conversation with a new managed session.
Resume must recall a random phrase absent from the follow-up prompt. Canonical assistant
capture, exact task-file bytes, public shutdown and native process closure are required.

This is smoke evidence. It does not qualify clean-machine login, performance budgets,
an execution sandbox, or a platform that has not run natively. Native harnesses own
permissions and sandboxing. The runner supports descriptor-bound ACP harnesses and the native Claude and Codex
adapters, including the native SE Code service. Unsupported drivers are SKIPPED with a reason. Missing native inputs,
images or required environment values are ABSENT; unreadable evidence is
UNREADABLE. A failed command or assertion is FAIL. Later phases that could not
run remain NOT RUN. None of these states count as PASS.

Use Python 3.11 or later from a terminal or OS scheduler outside managed agent
ancestry, in an administrator-registered disposable OS test account. The runner
uses `scripts/ci/installation_account.py` before installing: a disposable HOME
does not isolate the native installation lock or Windows account PATH. Supply a new private output directory outside the source tree.
Raw results contain conversation text and must not be published.

```sh
python3 scripts/harness-matrix.py \
  --cycle UNIQUE_ATTEMPT_ID \
  --package /absolute/extracted-native-distribution \
  --source-commit FULL_SOURCE_COMMIT \
  --manifest /absolute/private-matrix-input.json \
  --out /absolute/new-private-results
```

The manifest has `schema: "se.harness-matrix-input/v1"` and a nonempty `harnesses`
list. Every planned entry stays in the results. Each entry contains:

- `id`: a unique bounded identifier used for its result directory.
- `driver`: `acp-stdio`, `claude-stream-json`, `codex-app-server` or
  `secode-native`.
- Optional `skip`: an explicit reason to retain this planned row as SKIPPED.
- `platforms`: native settings keyed by `linux`, `win32` or `darwin`.

A platform may declare `absent` with a reason when its native inputs are not
available. Otherwise its settings contain:

- `harness`: the saved descriptor name selected by `se init --harness` for ACP.
  Built-in drivers select their provider instead.
- `configuration`: `path` and `sha256` of a plain configuration file containing
  the descriptor and its explicit named launch profile. Credential values belong
  in the native environment, not this file or the manifest.
- For SE Code, `seed_profile` contains the private seed `path` matching the
  selected provider configuration and a `files` map of SHA256 digests for
  `secode.jsonc`, `provider.credential` and `account-models.json`. Use a disposable
  seed prepared for this run; never use the normal account store.
- `permission_profile`: the exact expected `name`, `sandbox`, `approval`, `network`
  and `bypass` fields of the selected saved profile. This is a launch selection,
  not an assertion that StateEngine supplies OS containment.
- `environment`: additional inherited environment variable names, and
  `required_environment`: the required subset. Receipts record presence without
  retaining values. No account credential file or refresh token is copied.
- `home_environment`: native home-variable names mapped to paths relative to
  the disposable home, such as a native provider's configuration directory.
- `images`: `path` and `sha256` for each required native executable or installed
  script, including the interpreter when needed.
- `version_command` and `version_stdout`: a native argument list and its expected standard output after trimming surrounding whitespace. The version command must use a pinned image.
- Optional `task_seconds`: a bounded per-task deadline, defaulting to 240 seconds.
- On Windows, `terminal_prefix`: the argument prefix of a native terminal driver
  that executes the appended command and preserves its exit code and output.

The current process supplies only explicitly selected native environment values.
The runner creates a private home and native configuration directories. It never
uses a normal account's credential file or changes its login state. Missing
environment values, images or native platform input remain ABSENT.
The runner saves public discovery and history before cleaning up a failed task,
and retains failed fixture homes for diagnosis. Cleanup failures fail the cell.
After successful file work, a failed mail exchange does not prevent an independent
resume attempt; each phase retains its own outcome.

For a combined report, provide native result directories for the same exact product
source, unique cycle identity, input-manifest digest, exact native producer files and
ordered harness list:

```sh
python3 scripts/harness-matrix-report.py \
  --cycle UNIQUE_ATTEMPT_ID \
  --input /absolute/linux-results --input /absolute/windows-results \
  --input /absolute/macos-results \
  --source-commit FULL_SOURCE_COMMIT --manifest-sha256 INPUT_MANIFEST_SHA256 \
  --expected harness-a harness-b --out /absolute/new-private-summary
```

The combined report checks receipt identity, evidence for each passing phase and
cleanup. Native producer files must match; the scheduler pins the report reader
independently, so a reader-only correction can still examine retained captures. A missing
platform remains ABSENT. A malformed cell becomes UNREADABLE while other
verified cells remain visible. Exit zero requires every planned harness on all three
platforms to pass; it still denotes smoke evidence rather than full qualification.
