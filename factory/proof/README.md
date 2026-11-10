# Nightly Rust proof

This Linux scheduler runs the existing independent `journeys/run.mjs` judge with
its `rust-v1` command map. It adds no product assertions and does not replace the
judge's verdicts or thresholds. Product and judge Git revisions, map and file
hashes, native release identity, raw output and every first failure are retained.

Install `nightly.py` and `report.py` together, and use the supplied user service and
timer. The service runs outside managed agent trees; fixture environment isolation
does not change ancestry or bypass owner guards. The adapter refuses a fleet or
session environment. It checks for 34 GiB available before building or starting a
judge. Its lock serializes all invocations, and each judge still owns fixture
cleanup. A timeout retains its evidence and requires inspection of native custody.

The configuration names absolute `state`, `product_git`, `judge_git`, `node` and
`auth_home` paths, trusted `product_ref` and `judge_ref` revisions, an array of
`prerequisite_paths`, and `probes`, for example:

```json
{
  "state": "/srv/proof/results",
  "product_git": "/srv/proof/product.git",
  "product_ref": "main",
  "judge_git": "/srv/proof/judge.git",
  "judge_ref": "REVIEWED_JUDGE_COMMIT",
  "node": "/opt/judge-runtime/bin/node",
  "auth_home": "/srv/proof/native-login",
  "prerequisite_paths": ["/opt/judge-runtime/bin", "/opt/native-clis/bin"],
  "probes": [["codex", "first-hour"], ["claude", "wave-2"]]
}
```

The native CLIs must already be installed and signed in. Only the independent
judge reads the login files to make private copies without refresh tokens; it
checks the original inode and digest and removes the private copies after closure.
No native provider command uses the normal login home. Source and artifact trees
are retained, without credentials; cleanup of old evidence is a separate operator
operation. Native release builds use a private temporary directory on the result
filesystem, rather than a RAM-backed system temporary directory.

Each attempt has `run.json`, `grid.md`, `budgets.json`, a combined `report.json` and
`report.md`, plus the judge's original receipts. `latest.json` points to one
attempt's grid and budgets, including a failed attempt. The directory is a local
spool: there is no publisher, service identity, remote command or credential helper.
An outside reader publishes the grid. `--report DIRECTORY` regenerates reports
without running the product; `--prepared-build DIRECTORY` accepts a native release
only when its source matches the selected product revision, and the trusted
assembler verifies its inventory and hashes.

The original five journeys and the five sequential stock Codex first-hour checks
have different meanings, especially row four. They are separate scoped grids.
Windows and macOS are `NOT RUN` until native receipts exist. A measured zero remains
zero; an absent, unreadable, invalid or unavailable measurement never becomes zero
or a pass. The budget file retains all numeric samples and the judge's limits and
probe verdicts, without deriving a new verdict from a partial budget. Missing
embedded B1/B2, handover B8, FULL-write and Codex-budget probes are named gaps.
