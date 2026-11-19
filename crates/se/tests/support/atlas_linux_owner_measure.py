"""Observe the release owner on Linux without calling RSS a commit charge."""
import glob
import json
import os
from pathlib import Path
import subprocess
import sys
import time

root = Path(sys.argv[1]).resolve()
target = root / "target" / "judge-diagnostics"
target.mkdir(parents=True, exist_ok=True)
executables = [p for p in glob.glob(str(root / "target" / "release" / "deps" / "atlas_startup_dev-*")) if os.access(p, os.X_OK) and not p.endswith('.d')]
if len(executables) != 1:
    raise RuntimeError(f"expected exactly one test executable, found {len(executables)}")
env = os.environ.copy()
env["ATLAS_FULL_REPOSITORY"] = str(root)
log = target / "atlas-full-owner.log"
peak_rss_anon = 0
peak_vm = 0
post_baseline_peak = 0
observations = 0
baseline_seen = False
with log.open("wb") as out:
    child = subprocess.Popen([executables[0], "--exact", "automatic_owner_indexes_and_catches_committed_records_up", "--nocapture"], env=env, stdout=out, stderr=subprocess.STDOUT)
    while True:
        try:
            status = Path(f"/proc/{child.pid}/status").read_text()
            values = {}
            for line in status.splitlines():
                if line.startswith(("RssAnon:", "VmPeak:")):
                    key, value, _unit = line.split()
                    values[key[:-1]] = int(value) * 1024
            if "RssAnon" in values and "VmPeak" in values:
                observations += 1
                peak_rss_anon = max(peak_rss_anon, values["RssAnon"])
                peak_vm = max(peak_vm, values["VmPeak"])
                if not baseline_seen and b"ATLAS_BENCH_BASELINE " in log.read_bytes():
                    baseline_seen = True
                if baseline_seen:
                    post_baseline_peak = max(post_baseline_peak, values["RssAnon"])
        except FileNotFoundError:
            pass
        if child.poll() is not None:
            break
        time.sleep(0.01)
    status = child.wait()
text = log.read_text(encoding="utf-8", errors="replace")
print(text, flush=True)
lines = [line[line.index("ATLAS_BENCH_"):] for line in text.splitlines() if "ATLAS_BENCH_" in line]
def item(prefix):
    values = [line.split() for line in lines if line.startswith(prefix + " ")]
    if len(values) != 1:
        raise RuntimeError(f"missing or repeated {prefix} observation")
    return values[0]
baseline = int(item("ATLAS_BENCH_BASELINE")[1])
first_index_ms = int(item("ATLAS_BENCH_FIRST_INDEX_MS")[1])
history_count = int(item("ATLAS_BENCH_HISTORY")[1])
indexed_files = int(item("ATLAS_BENCH_INDEXED_FILES")[1])
queries = [line.split() for line in lines if line.startswith("ATLAS_BENCH_QUERY ")]
if status != 0 or observations == 0 or not baseline_seen or len(queries) != 4 or history_count < 2:
    raise RuntimeError(f"owner benchmark incomplete: exit={status}, observations={observations}, queries={len(queries)}, history={history_count}")
report = {
    "basis": "release automatic-owner consumer process; resident anonymous memory sampled externally, not Windows private commit; includes test harness and client, excludes child processes",
    "baseline_resident_anonymous_bytes": baseline,
    "peak_resident_anonymous_sampled_bytes": peak_rss_anon,
    "post_baseline_resident_anonymous_peak_bytes": post_baseline_peak,
    "post_baseline_sampled_peak_minus_baseline_bytes": post_baseline_peak - baseline,
    "peak_virtual_address_space_bytes": peak_vm,
    "documented_reservation_sum_bytes": 13000000,
    "first_index_ms": first_index_ms,
    "history_commits": history_count,
    "indexed_files": indexed_files,
    "query_response_bytes": {parts[1]: int(parts[2]) for parts in queries},
    "query_result_counts": {parts[1]: int(parts[3]) for parts in queries},
    "max_query_limit": 50,
    "max_query_byte_budget": 32768,
    "observations": observations,
}
(target / "atlas-full-owner-linux.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
print(json.dumps(report, indent=2), flush=True)
