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
`SHA256SUMS`, `se.exe` and `install.ps1`. The driver checks archive digest,
complete member inventory, native target and exact source identity. For an
unpublished build, an authenticated courier downloads and verifies the artifact
outside the Windows machine, then places the standalone ZIP in the sealed bundle.
Use `path` with an absolute local ZIP path instead of `url`; keep the package's
`sha256` and `source_commit`. The runner verifies the ZIP again before installation.
Public release URLs use HTTPS. Download credentials are refused by the runner.

Before each invocation a separate native credential provisioner must mint fresh
provider access credentials. Pipe its JSON directly into
`python scripts/windows-journeys.py provision --provider claude --out NEW_PRIVATE_DIRECTORY`
(or `--provider codex`). Input contains `credential`, the native authentication
object, and for Claude a `native` object containing completed onboarding. Claude
uses `credential: {"oauth_token": "SETUP_TOKEN"}` from the provider's setup-token
command. It is supplied only through `CLAUDE_CODE_OAUTH_TOKEN` in the private
command environment before init starts the host. No Claude credential file is
written. The opaque token exposes no account or expiry claims: these stay
unknown, and no expiry is invented. This command does not log in, refresh tokens,
read a login file or accept its path.
It recursively removes refresh tokens, checks Codex's declared access expiry and
creates a protected current-user/SYSTEM seed. Stdout reports only path, digest
and expiry. Use that identity in the private manifest. Never put credential
values in the manifest, shell arguments or repository.

Dedicated API keys can use the same stdin-only provisioning command. Claude
accepts `credential: {"api_key": "SYNTHETIC_EXAMPLE_KEY"}` plus the completed
onboarding object. Codex accepts its native API-key object,
`credential: {"auth_mode": "apikey", "OPENAI_API_KEY": "SYNTHETIC_EXAMPLE_KEY"}`.
The provisioner never reads the normal account's credential files. API keys have
unknown expiry, and API and subscription credentials cannot be mixed. The
selected configuration supplies the model for each provider.

Claude API keys enter only `ANTHROPIC_API_KEY` in the private process tree;
Codex API keys enter only its protected native file. Subscription Codex copies
emit the required `refresh_token` string as empty. No refresh token bytes are
copied, and the seed itself contains no refresh-token field. After the driver
has closed its private credential copy, the caller deletes its owned seed.

Seed age must be at most five minutes at run start. Codex gets an independent
protected native file; Claude gets only the private process environment. Seed
identity and bytes must stay unchanged.
Codex's declared expiry makes the attempt `INCOMPLETE` with an `EXPIRED`
prerequisite, including expiry during a failing call. Opaque Claude token
rejection is retained as the observed provider failure; the driver cannot
distinguish expiry from revocation. Cleanup still runs, retaining private
evidence when closure cannot be proved. Resolve retained processes and native
installation ownership before reusing the installation account.

| Cell | Required observation |
| --- | --- |
| J1 | Read the authenticated bundled release or download a public release, then install; a new terminal discovers the exact image and version through native PATH. |
| J2 | Adopt committed, staged, unstaged and untracked Git work (with `--adopt` user-started hook installation in the private provider home on Windows); a real agent writes new bytes and its assistant turn is captured. |
| J3 | Close agents and runtime; execute public reopen argv; recover a random phrase omitted from the recall prompt. |
| J4 | Two real agents exchange a keyed request; observe the durable message, authenticated recipient read and recipient file work. |
| J5 | Remove and uninstall; preserve user files, Git and exact saved event payloads; restore USER Path and prove process/credential closure. |

Text tasks accept LF or CRLF for their final newline on Windows, reject extra
bytes, and retain the actual file digest for later preservation checks.

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
