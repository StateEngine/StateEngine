"""A non-renderable home must never become a default-store force command."""
import argparse
import json
from pathlib import Path
import traceback
from mail_cli import Fixture
from launch_startup import exited


def run(args):
    f = Fixture(args.se, args.output / "line\nbreak", log_directory="calls")
    args.evidence.mkdir(parents=True, exist_ok=False)
    report = {"checks": []}
    identities = []
    try:
        f.launch()
        identities = list(f.processes)
        refused = f.call("--project", f.project, "launch", f.agent, "--detach")
        assert refused.returncode != 0
        detail = json.loads(refused.stdout)
        assert detail["code"] == "launch-confirmation-required", detail
        assert all(not exited(p) for p in identities), "plain refusal stopped an original birth"
        report["checks"].append("newline home supports public init and launch; plain refusal preserves original births")
        mcp = f.rpc("stateengine_agent_launch", {"idempotency_key": "newline-home-review"})
        assert mcp.get("isError") and all(not exited(p) for p in identities), mcp
        report["checks"].append("MCP refusal preserves original births")
        remedy = detail["detail"]["next_step"]
        report.update(remedy=remedy, original_home=str(f.home))
        assert "The data home is not UTF-8 or contains a line break" in remedy, "non-renderable home silently lost: " + remedy
        assert "se --project " not in remedy, "refusal offered an executable default-store command"
        report["checks"].append("refusal explains why the exact home has no portable command")
    except BaseException:
        report["failure"] = traceback.format_exc()
    finally:
        try:
            f.close()
            report["shutdown_witnessed"] = True
            report["all_original_births_closed"] = all(exited(p) for p in identities)
        except BaseException:
            report["cleanup_failure"] = traceback.format_exc()
        for path in f.log_root.iterdir():
            if path.is_file():
                (args.evidence / path.name).write_bytes(path.read_bytes())
        (args.evidence / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report), flush=True)
    return 1 if report.get("failure") or report.get("cleanup_failure") else 0


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--se", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--mode")
    raise SystemExit(run(p.parse_args()))
