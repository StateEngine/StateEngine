# StateEngine agent guide

StateEngine runs coding assistants in a project, saves their conversations, and lets them
exchange messages and resume later. It is a Rust workspace with the `se` command and host.
It must work for a stranger on their first try, on a clean machine, with no manual steps.

## This repository is going public

Write everything as if it were already public: code, tests, fixtures, comments, docs, PR
text and commit messages.

- Never include secrets or tokens, even expired or fake-looking real ones. Tests use
  synthetic credentials that are obviously fake.
- Never include personal names or emails, except in required license notices.
- Never include machine or team details: hostnames, non-loopback IPs, real home or drive
  paths, agent names and ids, internal message ids.
- Keep diagnostics, evidence and reports out of the repo. They go in the PR or outside it.
- Product code carries no operator defaults: no fixed agent names, hosts or drive paths.
- Never name other products or companies, such as tools we studied or compete with. Describe
  the behaviour in our own words. Providers the product integrates are the exception.
- Don't copy code from other projects: a copy needs a license notice that names them.
- Don't add or change license text.
- Check your diff and message for all of this before you push. If something slipped through,
  tell the reviewer. Never force-push a shared branch or rewrite shared history to fix it
  without the maintainer's approval.

## Commits and PRs

- Work on your own branch in your own worktree. Never commit to `main`.
- One PR per outcome. It merges by squash, so the PR title becomes the commit on `main`.
- Title: `type(scope): imperative summary`, under 72 characters.
- Commit messages: one short sentence, plus at most two lines of why if the diff can't show
  it. Recent messages are read into agent context, so each word is paid for repeatedly.
- PR text has three parts: Testing (how you checked it and what you could not check), Risk (its
  tier and why), How to revert. No test logs, evidence files, process notes or internal ids.
- Author: the project's configured identity or a GitHub noreply address, never a personal or
  machine email. Check `git config user.email` first.
- Agent commits end with a trailer naming the model: `Co-Authored-By: <model> <noreply
  address>`.
- Agents don't change `.github/workflows`; the maintainer does.

## What must never be compromised

- **Honest results.** Absent, unreadable and zero are different facts. Never collapse them,
  discard a failure, truncate silently, or report success nothing witnessed.
- **Other agents' work.** Anything that can eat another agent's work or a user's data is a
  blocker, not a style point.
- **Refusals that help.** A refusal names its reason and a step that actually works. A truthful
  refusal isn't a supported outcome, and a hand-run step isn't a user flow.

## Implementation rules

- No file over 800 lines, or 1,000 for tests. Split by responsibility, not to hit a number.
- Every change must work on Linux and Windows, and say what it did not exercise on macOS.
  Run Windows-target Clippy before review: Linux never compiles Windows-only code.
- A fix on one path is often missing on its twin. Check both: CLI and MCP, Linux and Windows,
  Claude and Codex, read and write. Say why if one side is exempt.
- Speed and memory are product features. Measure them; don't claim "fast" without numbers.
- Don't add a new guard per incident when a smaller product fix removes the cause.

## Working method

- A question gets an answer, not an edit. Propose simplifications before building.
- When something that used to work breaks, find what changed first (`git log -S`). Name the
  change, or show the history is silent, before redesigning.
- Prove behaviour through its real consumer, not only an isolated test.
- Before blaming the base for a failure, reproduce it there.
- A change isn't live until the process using it restarts. Restart it, make the effect happen,
  and read it back from outside the writer.
- Use your own judgment and finish the whole outcome before asking for review. Escalate only
  what needs missing access, breaks a stated constraint, or changes the agreed outcome.

## Tests

- Only user-facing docs live in this repository.
- Never open a pull request that only changes documentation; a doc change rides with a code change.

- Authors don't write the tests that judge their own change. The reviewer owns those, and a
  good one fails on the base and passes on the fix.
- A test that breaks on an unrelated change gets fixed or removed, not re-pinned.
- Test doubles must behave like the real thing they replace.
- CI's one required status is `check`. Author test runs help you develop; they aren't proof.
- Linux gates every PR. Windows is judged nightly in a VM. macOS compiles nightly.
- Linux CI runs on the self-hosted runner. Hosted Linux is only the fallback when that runner is unavailable.
- Owner-only commands in a test use a throwaway home, synthetic credentials and no provider markers.
- Don't poll CI, because each check costs tokens. Wait with `gh pr checks --watch`.
- Keep `main` releasable. If it breaks, fixing it comes before new work.

## Review

Before asking for review, review your own diff in a fresh context and fix what you find.

Risk sets the review, and the change sets the risk, not the author:

| Risk | Examples | Review |
|---|---|---|
| Low | Docs, tests, copy | CI only |
| Medium | Ordinary product changes | One reviewer |
| High | Installers, credentials, migrations, process control, data deletion | One reviewer. The maintainer also reads pivotal or very large changes. A native Windows run is required only for Windows-only code or the Windows installer. |

Failure here means: it reports success nothing witnessed, it eats another agent's work or a user's
data, it collapses absent, unreadable and zero, or it fails a stranger's first hour.

- Report correctness and craft separately: is it over- or under-built, does it grow a god file, is
  the layer right, is the code easier to work in afterwards? A green PR with poor craft goes back.
- Tag every finding Important, Nit or Pre-existing, with file and line evidence and no guesses. Cap
  nits at three. Pre-existing findings don't block the PR; they get their own issue or PR.
- Start with a count of findings, and say plainly when nothing needs fixing.
- Flag the class of bug, so the author fixes every instance. Don't repeat a posted finding.
- Every Important finding gets fixed or answered with a reason before merge.
- After the first review, re-review only the new diff. After three rounds, stop and reconsider the
  approach instead of adding another fix.

## Commands

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run -p <crate>
cargo test --workspace --all-features --locked --doc
```

Build heavy tests in your own target directory, one build at a time, and clear it when done.

## Shared repository safety

Many worktrees share one `.git`.

- Never `git stash`: the stack is shared, so a pop can take someone else's work.
- Never `git commit --amend` in a shared tree. Use path-limited commits:
  `git commit -F - -- PATH1 PATH2`. Never `git add -A`.
- Never link `node_modules` or other shared folders into a worktree: a recursive delete can
  follow the link.
- Stop processes only by exact pid, after reading the full command line. Never by name.
- Read exit codes directly, not through a pipe.
- On Windows, never rewrite source through PowerShell `Get-Content`/`Set-Content`: it can
  silently corrupt UTF-8.
- Preserve other contributors' uncommitted files.

## What counts

User-visible changes merged, a stranger's first hour, and measured speed and memory. Commit,
test and message counts are not progress.
