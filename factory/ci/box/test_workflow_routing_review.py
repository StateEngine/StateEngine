"""Drive the workflow's actual route script and Windows predicates."""
import copy
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = (ROOT / ".github/workflows/ci.yml").read_text()
spec = importlib.util.spec_from_file_location("workflow_review_check", ROOT / "scripts/ci/check.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def job(name):
    match = re.search(r"^  " + re.escape(name) + r":\n(.*?)(?=^  [a-zA-Z][\w-]*:|\Z)", WORKFLOW, re.M | re.S)
    if not match:
        raise AssertionError("workflow job missing: " + name)
    return match[1]


def node(source, value):
    result = subprocess.run(["node", "-e", source], input=json.dumps(value), text=True,
                            capture_output=True, timeout=10)
    if result.returncode:
        raise AssertionError(result.stderr)
    return json.loads(result.stdout)


def predicate(name, needs, event="pull_request", cancelled=False):
    match = re.search(r"^    if: \$\{\{ (.*?) \}\}$", job(name), re.M)
    if not match:
        raise AssertionError("workflow predicate missing: " + name)
    expression = re.sub(r"needs\.([\w-]+)", r'needs["\1"]', match[1])
    return node("const fs=require('fs'); const v=JSON.parse(fs.readFileSync(0,'utf8')); "
                "const needs=v.needs, github={event_name:v.event}, cancelled=()=>v.cancelled, "
                "always=()=>true; process.stdout.write(JSON.stringify(eval(v.expression)));",
                dict(expression=expression, needs=needs, event=event, cancelled=cancelled))


class WorkflowRoutingReview(unittest.TestCase):
    def jobs(self):
        return {"changes": {"result": "success", "outputs": {"rust": "true", "windows": "true"}},
                "linux-route": {"result": "success", "outputs": {"route": "box"}},
                "linux-box": {"result": "success", "outputs": {"status": "passed", "windows": "passed"}},
                **{n: {"result": "skipped"} for n in ["fmt", "clippy", "archive", "test", "windows-clippy"]}}

    def route(self, enabled=True, event="pull_request", origin="owner/repo", fork=False, attempt="1"):
        match = re.search(r"^          script: \|\n((?:            .*\n)+)", job("linux-route"), re.M)
        self.assertIsNotNone(match)
        script = "\n".join(line[12:] for line in match[1].splitlines())
        return node("const fs=require('fs'), v=JSON.parse(fs.readFileSync(0,'utf8')); "
                    "process.env.BOX_ENABLED=v.enabled?'true':'false'; "
                    "process.env.GITHUB_REPOSITORY='owner/repo'; process.env.GITHUB_RUN_ATTEMPT=v.attempt; "
                    "let output; const core={info(){},warning(){},setOutput(k,v){if(k!=='route')throw Error(k);output=v;}}; "
                    "const github=new Proxy({}, {get(){throw Error('availability API must not select busy overflow');}}); "
                    "const context={eventName:v.event,payload:{pull_request:{draft:false,head:{repo:{full_name:v.origin,fork:v.fork}}}},repo:{owner:'owner',repo:'repo'},runId:7}; "
                    "(async()=>{await new (Object.getPrototypeOf(async function(){}).constructor)('core','github','context',v.script)(core,github,context); "
                    "process.stdout.write(JSON.stringify(output));})().catch(e=>{console.error(e);process.exitCode=1;});",
                    dict(script=script, enabled=enabled, event=event, origin=origin, fork=fork, attempt=attempt))

    def test_busy_and_rerun_owned_work_stays_on_the_box_without_api_observation(self):
        for event in ["pull_request", "push", "schedule", "workflow_dispatch"]:
            for attempt in ["1", "2"]:
                with self.subTest(event=event, attempt=attempt):
                    self.assertEqual(self.route(event=event, attempt=attempt), "box")

    def test_disabled_or_fork_sources_never_select_the_box(self):
        self.assertEqual(self.route(enabled=False), "hosted")
        self.assertEqual(self.route(origin="outside/repo", fork=True), "hosted")
        self.assertEqual(self.route(fork=True), "hosted")

    def test_hosted_windows_skips_only_with_explicit_successful_box_proof(self):
        base = self.jobs()
        self.assertFalse(predicate("windows-clippy", base))
        self.assertTrue(check.accepted(base))
        for path, value in [("route", "hosted"), ("routing", "failure"), ("box", "failure"),
                            ("status", "unavailable"), ("windows", ""), ("windows", "failed")]:
            jobs = copy.deepcopy(base)
            if path == "route": jobs["linux-route"]["outputs"]["route"] = value
            elif path == "routing": jobs["linux-route"]["result"] = value
            elif path == "box": jobs["linux-box"]["result"] = value
            else: jobs["linux-box"]["outputs"][path] = value
            with self.subTest(path=path, value=value):
                self.assertTrue(predicate("windows-clippy", jobs))
                self.assertFalse(check.accepted(jobs))

    def test_compiler_failure_never_uses_a_green_hosted_fallback(self):
        jobs = self.jobs(); jobs["linux-box"]["outputs"]["status"] = "failed"
        self.assertFalse(predicate("windows-clippy", jobs))
        self.assertFalse(predicate("fmt", jobs))
        for name in ["fmt", "clippy", "archive", "test", "windows-clippy"]:
            jobs[name]["result"] = "success"
        self.assertFalse(check.accepted(jobs))

    def test_infrastructure_refusal_requires_the_complete_hosted_chain(self):
        jobs = self.jobs(); jobs["linux-box"]["outputs"] = {"status": "unavailable", "windows": "unavailable"}
        for result in ["success", "failure"]:
            jobs["linux-box"]["result"] = result
            self.assertTrue(predicate("fmt", jobs))
            self.assertTrue(predicate("windows-clippy", jobs))
            for name in ["fmt", "clippy", "archive", "test", "windows-clippy"]:
                jobs[name]["result"] = "success"
            self.assertTrue(check.accepted(jobs))
            for name in ["fmt", "clippy", "archive", "test", "windows-clippy"]:
                broken = copy.deepcopy(jobs); broken[name]["result"] = "failure"
                self.assertFalse(check.accepted(broken))

    def test_cancelled_or_exempt_work_never_starts_windows(self):
        jobs = self.jobs(); jobs["linux-box"]["outputs"]["windows"] = ""
        self.assertFalse(predicate("windows-clippy", jobs, cancelled=True))
        jobs["changes"]["outputs"]["windows"] = "false"
        self.assertFalse(predicate("windows-clippy", jobs))
        jobs["changes"]["outputs"]["windows"] = "true"; jobs["changes"]["outputs"]["rust"] = "false"
        self.assertFalse(predicate("windows-clippy", jobs))

    def test_nightly_native_jobs_can_follow_proven_cross_target_clippy(self):
        jobs = self.jobs()
        for name in ["windows-archive", "windows-test"]:
            for event in ["schedule", "workflow_dispatch"]:
                self.assertTrue(predicate(name, jobs, event=event))
                bad = copy.deepcopy(jobs); bad["linux-box"]["outputs"]["windows"] = ""
                self.assertFalse(predicate(name, bad, event=event))
            self.assertFalse(predicate(name, jobs, event="pull_request"))


if __name__ == "__main__":
    unittest.main()
