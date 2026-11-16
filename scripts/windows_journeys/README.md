# Native Windows journeys

Run `python scripts/windows-journeys.py run --manifest INPUT.json --harness ID --cycle ATTEMPT --out NEW_DIRECTORY`
from an OS scheduler in a registered disposable installation-test account,
outside managed agent trees. Python 3.11+, Git, Windows PowerShell and pinned
native provider images must already be available. This uses real providers.

Select one harness id from the existing `se.harness-matrix-input/v1` table per
invocation, so credentials can be provisioned immediately before each run.
Claude and Codex share one journey implementation. Other drivers remain
explicitly incomplete; embedded-provider rows await their registry integration.

Each selected `platforms.win32` object keeps the existing configuration,
permission profile, image digests and version-command fields. Add
`credential_seed: {"path": "ABSOLUTE_PRIVATE_SEED_PATH", "sha256": "SEED_DIGEST"}`.
Provider environment inheritance is refused. `CODEX_HOME: ".codex"` is the only
optional home binding. The driver supplies its native pseudoconsole prefix.
Add this top-level object to the same manifest:

```json
{
  "windows_journeys": {
    "release": {
      "url": "https://example.invalid/release.zip",
      "sha256": "ARCHIVE_DIGEST",
      "source_commit": "FULL_SOURCE_COMMIT"
    }
  }
}
```

Use a real standalone release archive containing `build.json`, `manifest.json`,
`SHA256SUMS`, `se.exe` and `install.ps1`. The driver checks HTTPS, archive digest,
complete member inventory, native target and exact source identity. A private
download may name `authorization_environment`; its value is used only by the
downloader and never inherited by providers.

Before each invocation a separate native credential provisioner must mint fresh
provider access credentials. Pipe its JSON directly into
`python scripts/windows-journeys.py provision --provider claude --out NEW_PRIVATE_DIRECTORY`
(or `--provider codex`). Input contains `credential`, the native authentication
object, and for Claude a `native` object containing completed onboarding. This
command does not log in, refresh tokens, read a login file or accept its path.
It recursively removes refresh tokens, checks declared access expiry and
creates a protected current-user/SYSTEM seed. Stdout reports only path, digest
and expiry. Use that identity in the private manifest. Never put credential
values in the manifest, shell arguments or repository.

The Codex copy emits its required `refresh_token` string as empty. No refresh
token bytes are copied, and the seed itself contains no refresh-token field.

Seed age must be at most five minutes at run start. Each private test home gets
independent protected bytes; seed identity and bytes must stay unchanged.
Expired access makes the attempt `INCOMPLETE` with an `EXPIRED` prerequisite,
including expiry during a failing call. Cleanup still runs, retaining private
evidence when closure cannot be proved. Resolve retained processes and native
installation ownership before reusing the installation account.

| Cell | Required observation |
| --- | --- |
| J1 | Download and install; a new terminal discovers the exact image and version through native PATH. |
| J2 | Adopt committed, staged, unstaged and untracked Git work; a real agent writes new bytes and its assistant turn is captured. |
| J3 | Close agents and runtime; execute public reopen argv; recover a random phrase omitted from the recall prompt. |
| J4 | Two real agents exchange a keyed request; observe the durable message, authenticated recipient read and recipient file work. |
| J5 | Remove and uninstall; preserve user files, Git and exact saved event payloads; restore USER Path and prove process/credential closure. |

Tiny prompts bound paid work. Each cell records native token-counter deltas and
their observation interval; cached/reasoning subsets are kept separate. Missing
usage makes qualification incomplete, never zero-cost success. Transcript
counters are observations rather than billing statements; asynchronous writes
can cross phase boundaries. Raw commands, output and exits remain in the private
evidence directory. Do not publish it or credential homes.

Hosted runners can check inputs, parse scripts and build pinned releases. Real
provider sessions, cold detached restart, native terminal ownership and account
installation/uninstallation require a disposable native VM. This driver alone
does not prove clean-image provenance or qualify performance. Failed attempts
retain their homes for investigation; successful homes retain the Git/history
witnesses, with the provider credential copy removed.
