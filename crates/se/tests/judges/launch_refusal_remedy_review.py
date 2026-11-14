"""Execute the exact printed replacement; refuse to supply missing scope for it."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import traceback
from mail_cli import Fixture
from launch_startup import pin, exited


def run(args):
    f = Fixture(args.se, args.output, log_directory="calls")
    args.evidence.mkdir(parents=True, exist_ok=False)
    report = {"mode": args.mode, "checks": []}
    identities = []
    try:
        if args.mode == "environment":
            f.env["SE_HOME"] = str(f.home)
        else:
            assert "SE_HOME" not in f.env
        f.env["PATH"] = str(f.se.parent) + os.pathsep + f.env["PATH"]
        f.ok("launch", "--help")
        f.launch()
        identities = list(f.processes)
        refused = f.call("--project", f.project, "launch", f.agent, "--detach")
        assert refused.returncode != 0, "unconfirmed launch succeeded"
        detail = json.loads(refused.stdout)
        assert detail["code"] == "launch-confirmation-required", detail
        assert all(not exited(p) for p in identities), "plain refusal stopped an original birth"
        report["checks"].append("CLI refusal preserves every original provider birth")
        mcp = f.rpc("stateengine_agent_launch", {"idempotency_key": "unconfirmed-remedy-review"})
        assert mcp.get("isError"), mcp
        assert all(not exited(p) for p in identities), "MCP refusal stopped an original birth"
        report["checks"].append("MCP refusal preserves every original provider birth")
        remedy = detail["detail"]["next_step"]
        marker = "before starting the replacement: "
        assert marker in remedy, "refusal does not print the executable replacement command"
        command = remedy.split(marker, 1)[1].split(". An interactive owner terminal", 1)[0]
        argv = shlex.split(command)
        assert argv[0] == "se" and argv[-1] == "--force", argv
        report.update(command=command, argv=argv, original_home=str(f.home), original_births=identities)
        # Execute exactly what was printed, retaining only the invoking user's
        # ordinary environment. Do not append --home, --project, or --json.
        result = subprocess.run(argv, env=f.env, cwd=f.repo, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=90)
        (args.evidence / "printed.stdout").write_bytes(result.stdout)
        (args.evidence / "printed.stderr").write_bytes(result.stderr)
        report.update(printed_exit=result.returncode, printed_stdout=result.stdout.decode(errors="replace"),
                      printed_stderr=result.stderr.decode(errors="replace"),
                      original_births_still_live=[not exited(p) for p in identities])
        assert result.returncode == 0, "literal replacement failed: " + json.dumps(report)
        assert all(exited(p) for p in identities), "replacement did not close original native births"
        report["checks"].append("literal --force command succeeds and witnesses original births closed")
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
    p.add_argument("--mode", choices=["environment", "explicit"], required=True)
    raise SystemExit(run(p.parse_args()))
