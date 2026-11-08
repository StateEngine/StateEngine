"""The sole required status: skipped work needs an explicit change-detector exemption."""
import json
import os
import sys


def accepted(jobs):
    expected = {"changes", "linux-route", "linux-box", "fmt", "clippy", "windows-clippy", "archive", "test"}
    if set(jobs) != expected or jobs["changes"]["result"] != "success":
        return False
    outputs = jobs["changes"].get("outputs", {})
    if outputs.get("rust") == "false":
        return all(j["result"] == "skipped" for n, j in jobs.items() if n != "changes")
    if outputs.get("rust") != "true":
        return False
    windows = jobs["windows-clippy"]["result"]
    if windows != ("skipped" if outputs.get("windows") == "false" else "success"):
        return False
    routing, box = jobs["linux-route"], jobs["linux-box"]
    route = routing.get("outputs", {}).get("route", "")
    status = box.get("outputs", {}).get("status", "")
    linux = [jobs[n]["result"] for n in ("fmt", "clippy", "archive", "test")]
    if route == "box" and routing["result"] == "success":
        if status == "failed":
            return False
        if status == "passed":
            return box["result"] == "success" and all(s == "skipped" for s in linux)
        fallback = (status == "unavailable" and box["result"] == "success") or (
            not status and box["result"] == "failure")
        return fallback and all(s == "success" for s in linux)
    if ((route == "hosted" and routing["result"] == "success") or
            (not route and routing["result"] == "failure")):
        return box["result"] == "skipped" and all(s == "success" for s in linux)
    return False



if __name__ == "__main__":
    results = json.loads(os.environ["RESULTS"])
    for name, result in results.items():
        print(f"{name}: {result['result']}")
    sys.exit(0 if accepted(results) else 1)
