"""The sole required status: skipped work needs an explicit change-detector exemption."""
import json
import os
import sys


def accepted(jobs):
    expected = {"changes", "fmt", "clippy", "archive", "test"}
    if set(jobs) != expected or jobs["changes"]["result"] != "success":
        return False
    prose_only = jobs["changes"].get("outputs", {}).get("rust") == "false"
    return all(job["result"] == "success" or
               (prose_only and name != "changes" and job["result"] == "skipped")
               for name, job in jobs.items())


if __name__ == "__main__":
    results = json.loads(os.environ["RESULTS"])
    for name, result in results.items():
        print(f"{name}: {result['result']}")
    sys.exit(0 if accepted(results) else 1)
