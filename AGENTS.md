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
- Agents don't change license or contributor-agreement text; the maintainer does.
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
- Only user-facing docs live in this repository. Never open a pull request that only changes
  documentation; a doc change rides with a code change.
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
- **Refusals that help.** A refusal names its reason and a step that actually works. An honest
  refusal doesn't count as handling the case, and a hand-run step isn't a user flow.

## Implementation rules

- No file over 800 lines, or 1,000 for tests.
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

- Authors don't write the tests that judge their own change. The reviewer owns those, and a
  good one fails on the base and passes on the fix.
- A test that breaks on an unrelated change gets fixed or removed, not re-pinned.
- Test doubles must behave like the real thing they replace.
- CI's one required status is `check`. Author test runs help you develop; they aren't proof.
- Linux gates every PR; Windows and macOS are checked nightly.
- Owner-only commands in a test use a throwaway home, synthetic credentials and no provider markers.
- Don't poll CI, because each check costs tokens. Wait with `gh pr checks --watch`.
- Keep `main` releasable. If it breaks, fixing it comes before new work.

## Review

Before asking for review, review your own diff in a fresh context and fix what you find.

Risk sets the review, and the change sets the risk, not the author:

| Risk | Examples | Review |
|---|---|---|
| Low | Tests, copy | CI only |
| Medium | Ordinary product changes | One reviewer |
| High | Installers, credentials, migrations, process control, data deletion | One reviewer. The maintainer also reads pivotal or very large changes. A native Windows run is required only for Windows-only code or the Windows installer. |

- Report correctness and craft separately: is it over- or under-built, is the layer right, is the
  code easier to work in afterwards? A green PR with poor craft goes back.
- Craft includes structure. Follow the single responsibility principle: each module has one reason to change, and code is split along responsibilities, never to beat a size limit. These are Important findings, not nits:
  - Rule gaming: obeying a rule's wording while defeating its purpose. That includes splitting a file just to pass a limit, stitching code back with `include!`, silencing a check instead of fixing the cause, and weakening a test until it passes.
  - Boundary violations: reaching into another module's private state, several levels up with `super::super::`, past a crate's public interface, or around an existing check or safety step.
  - Coupling and length: a new cycle between modules, or a function too long to follow in one read.
- Limits are warning signs, not goals. When one trips, extract a distinct responsibility; don't slice the file in half.
- Some code is legitimately large: generated tables, a dispatcher or state machine that reads best in one place, protocol definitions, test fixtures. It gets a named exception with a one-line reason, approved in review. A forced split that scatters one idea is as bad as a grab bag.
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
- Never link shared folders into a worktree: a recursive delete can follow the link.
- Stop processes only by exact pid, after reading the full command line. Never by name.
- Read exit codes directly, not through a pipe.
- On Windows, never rewrite source through PowerShell `Get-Content`/`Set-Content`: it can
  silently corrupt UTF-8.
- Preserve other contributors' uncommitted files.

## What counts

User-visible changes merged, a stranger's first hour, and measured speed and memory. Commit,
test and message counts are not progress.
