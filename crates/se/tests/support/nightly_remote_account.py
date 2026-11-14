"""Guard-only controls: real native registration, recording downstream stages.

The process transport executes the emitted registration program in a separate
process. It does not claim an SSH handshake, provider journey, token transfer,
or latency measurement. No credential file or provider account is used.
"""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import pwd
import sys
from unittest.mock import patch


tree, fixtures, artifacts = map(Path, sys.argv[1:])
sys.path.insert(0, str(tree / "factory/proof"))
import remote_journey
import nightly


native = pwd.getpwuid(os.geteuid())
expected = {"identity": str(native.pw_uid), "profile": native.pw_dir}
shim = fixtures / "transport"
shim.mkdir()
transport = shim / "ssh"
transport.write_text('''#!/usr/bin/python3
import json,os,shlex,sys
from pathlib import Path
if sys.argv[1:5] != ['-T','-o','BatchMode=yes','synthetic-fixture']:
    raise SystemExit('unexpected account probe transport')
with Path(os.environ['GUARD_PROBE_EVENTS']).open('a') as stream:
    stream.write('native-account-probe\\n')
args=shlex.split(sys.argv[5])
if args[:2] != ['python3','-c']:
    raise SystemExit('account probe must execute a Python registration program')
os.execv('/usr/bin/python3', ['/usr/bin/python3', *args[1:]])
''')
transport.chmod(0o700)
image = fixtures / "synthetic-product-image"
image.write_bytes(b"synthetic guard control; never executed or staged\n")


def control(name, selection, accepted=False):
    case = fixtures / name
    case.mkdir()
    probe_events = case / "probe-events"
    phases = []
    env = {"PATH": str(shim) + os.pathsep + os.defpath, "HOME": native.pw_dir,
           "LANG": "C.UTF-8", "GUARD_PROBE_EVENTS": str(probe_events)}

    class RecordingCredentials:
        def __init__(self, journey, configuration):
            phases.append("credential-construction")

        def snapshot(self):
            return {"kind": "recording credential control; no token"}

        def stage(self):
            phases.append("token-handoff")

        def close(self):
            phases.append("credential-closure")

    def exercise(journey):
        phases.append("exercise-stub")
        # These are explicit test-double outputs, not provider measurements.
        for label in ("attach", "pending_echo", "live_output", "reconnect"):
            journey.record["timings"][label] = {
                "milliseconds": 0, "qualification": "synthetic guard control only"}

    config = {"state": str(case / "state"), "auth_home": str(case / "unused-auth"),
              "remote": {"destination": "synthetic-fixture", "surface": "claude"}}
    if selection is not None:
        config["remote"]["destination_account"] = selection
    invocation = {"output": "remote-control"}
    run = {"product": {"worktree": str(tree), "commit": "synthetic-guard-source"}}
    with ExitStack() as stack:
        stack.enter_context(patch.object(remote_journey, "Credentials", RecordingCredentials))
        stack.enter_context(patch.object(remote_journey, "begin_recovery",
                                        lambda journey: phases.append("recovery")))
        stack.enter_context(patch.object(remote_journey, "finish_recovery", lambda journey: None))
        for method, label in (("lock_account", "lock"),
                              ("stage_executables", "image-staging"),
                              ("initialize_projects", "project-staging")):
            stack.enter_context(patch.object(remote_journey.Journey, method,
                                            lambda journey, label=label: phases.append(label)))
        stack.enter_context(patch.object(remote_journey.Journey, "exercise", exercise))
        stack.enter_context(patch.object(nightly, "capacity", lambda: None))
        stack.enter_context(patch.object(nightly, "checkpoint", lambda *args: None))
        nightly.invoke_remote(config, run, case, image, env, invocation,
                              remote_journey.time.monotonic() + 60)
    report = json.loads((case / "remote-control/remote.json").read_text())
    probes = probe_events.read_text().splitlines() if probe_events.exists() else []
    result = {"case": name, "accepted_expected": accepted, "invocation": invocation,
              "phases": phases, "native_probe_count": len(probes),
              "journey_state": report["state"], "journey_passed": report["passed"],
              "errors": report["errors"], "registered": report.get("destination_account")}
    if accepted:
        assert invocation["exit"] == 0 and report["passed"] is True, result
        assert report["destination_account"] == {"registered": True, **expected}, result
        assert len(probes) == 1, result
        assert phases == ["lock", "recovery", "credential-construction", "image-staging",
                          "token-handoff", "project-staging", "exercise-stub",
                          "credential-closure"], result
    else:
        assert invocation["state"] == "finished" and invocation["exit"] == 1, result
        assert report["state"] == "failed" and report["passed"] is False, result
        assert report["behavior_passed"] is False and report["errors"], result
        assert phases == [], result
        if name.startswith("wrong-"):
            assert len(probes) == 1, result
            assert report["destination_account"] == {"registered": True, **expected}, result
        else:
            assert probes == [], result
    return result


cases = [
    ("missing-selection", None, False),
    ("missing-both-fields", {}, False),
    ("missing-identity", {"profile": expected["profile"]}, False),
    ("missing-profile", {"identity": expected["identity"]}, False),
    ("nonnumeric-identity", {**expected, "identity": "not-a-native-uid"}, False),
    ("integer-identity", {**expected, "identity": native.pw_uid}, False),
    ("relative-profile", {**expected, "profile": "relative-profile"}, False),
    ("extra-selection-field", {**expected, "unexpected": True}, False),
    ("wrong-native-identity", {**expected, "identity": str(native.pw_uid + 1)}, False),
    ("wrong-native-profile", {**expected, "profile": expected["profile"] + "/other"}, False),
    ("matching-registration", expected, True),
]
results, failures = [], []
for name, selection, accepted in cases:
    try:
        results.append(control(name, selection, accepted))
    except Exception as error:
        failures.append({"case": name, "error": repr(error)})
report = {"schema": "independent.remote-account-guard/v1",
          "scope": "native account selection and failed nightly reporting; downstream stages are stubs",
          "controls": results, "failures": failures}
(artifacts / "controls.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({"passed_controls": len(results), "failed_controls": failures}))
raise SystemExit(bool(failures))
