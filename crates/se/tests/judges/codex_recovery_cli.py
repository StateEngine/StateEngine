"""Independent public-CLI crash recovery and slow-live-provider control on Linux."""
import argparse
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import time
import uuid
from judge_records import wait_json


def observe_windows(pid):
    import ctypes
    from ctypes import wintypes
    native = ctypes.WinDLL("kernel32", use_last_error=True)
    native.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    native.OpenProcess.restype = wintypes.HANDLE
    native.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
    native.GetProcessTimes.restype = wintypes.BOOL
    native.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    native.WaitForSingleObject.restype = wintypes.DWORD
    native.CloseHandle.argtypes = [wintypes.HANDLE]
    native.CloseHandle.restype = wintypes.BOOL
    handle = native.OpenProcess(0x00100000 | 0x1000, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:
            return None
        raise ctypes.WinError(error)
    try:
        stamps = [wintypes.FILETIME() for _ in range(4)]
        if not native.GetProcessTimes(handle, *(ctypes.byref(stamp) for stamp in stamps)):
            raise ctypes.WinError(ctypes.get_last_error())
        state = native.WaitForSingleObject(handle, 0)
        if state not in (0, 258):
            raise ctypes.WinError(ctypes.get_last_error())
        birth = (stamps[0].dwHighDateTime << 32) | stamps[0].dwLowDateTime
        return {"pid": pid, "birth": str(birth), "state": "Z" if state == 0 else "R"}
    finally:
        native.CloseHandle(handle)


def observe(pid):
    if os.name == "nt":
        return observe_windows(pid)
    try:
        proc = Path(f"/proc/{pid}")
        argv = [v.decode(errors="replace") for v in (proc / "cmdline").read_bytes().split(b"\0") if v]
        stat = (proc / "stat").read_text().rsplit(") ", 1)[1].split()
        return {"pid": pid, "birth": stat[19], "state": stat[0], "ppid": int(stat[1]),
                "argv": argv, "image": str((proc / "exe").resolve())}
    except FileNotFoundError:
        return None


def live(identity):
    row = observe(identity["pid"])
    return bool(row and row["birth"] == identity["birth"] and row["state"] != "Z")


def owned_rows(root):
    rows = []
    marker = str(root).encode()
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            argv = (proc / "cmdline").read_bytes()
            environ = (proc / "environ").read_bytes()
            if marker not in argv and marker not in environ:
                continue
            row = observe(int(proc.name))
            if row and row["argv"]:
                rows.append(row)
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return rows


class Judge:
    def __init__(self, args):
        self.args = args
        self.root = args.output.resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        for name in ("owner", "repo", "runtime", "tmp", "codex"):
            (self.root / name).mkdir(mode=0o700)
        self.home = self.root / "state"
        self.env = {k:v for k,v in os.environ.items()
                    if not k.startswith(("SE_", "STATEENGINE_", "CODEX_", "CLAUDE", "OPENAI"))}
        self.env.update(HOME=str(self.root / "owner"), USERPROFILE=str(self.root / "owner"),
                        CODEX_HOME=str(self.root / "codex"), XDG_RUNTIME_DIR=str(self.root / "runtime"),
                        TMPDIR=str(self.root / "tmp"))
        # Shorten the real provider-control windows at spawn; the engine
        # still runs the same recovery and stop paths against the injected
        # thresholds, and the production defaults are unchanged.
        self.env["SE_PROVIDER_STOP_GRACE_MS"] = "500"
        if self.args.scenario == "slow":
            self.env["SE_PROVIDER_RESTORE_DEADLINE_MS"] = "1000"
        self.calls = 0
        self.foreground = None
        if os.name == "nt":
            for key in ("APPDATA", "LOCALAPPDATA"):
                private = self.root / "owner" / key.lower()
                private.mkdir()
                self.env[key] = str(private)
        self.stopped = []
        self.identities = []
        source = self.root / "provider.rs"
        helper_source = Path(__file__).with_name("codex_recovery_provider.py").resolve(strict=True)
        # Keep the helper for the whole native lifecycle, independently of the
        # caller's checkout or temporary driver extraction directory.
        helper = self.root / "provider.py"
        shutil.copyfile(helper_source, helper)
        source.write_text('fn main(){let a:Vec<String>=std::env::args().collect();'
                          'if a.iter().any(|v|v=="--version"){println!("codex-cli 0.152.0");return;}'
                          'let root=std::path::Path::new(HELPER).parent().unwrap();'
                          'let log=std::fs::File::create(root.join("provider-stderr.txt")).unwrap();'
                          'let s=std::process::Command::new(PYTHON).arg(HELPER).args(&a[1..])'
                          '.stderr(log).status().unwrap();'
                          'std::fs::write(root.join("provider-exit.txt"),format!("{s}\n")).unwrap();'
                          'std::process::exit(s.code().unwrap_or(1));}'
                          .replace("PYTHON",json.dumps(os.sys.executable)).replace("HELPER",json.dumps(str(helper))))
        args.codex = self.root / ("provider.exe" if os.name == "nt" else "provider")
        compiled = subprocess.run(["rustc", "--edition=2024", str(source), "-o", str(args.codex)],
                                  capture_output=True, timeout=40)
        if compiled.returncode:
            raise AssertionError(compiled.stderr.decode())
        self.result = {"scenario": args.scenario, "se": str(args.se.resolve()),
                       "provider": str(args.codex.resolve()), "root": str(self.root)}

    def call(self, *args, timeout=100):
        self.calls += 1
        r = subprocess.run([str(self.args.se.resolve()), "--home", str(self.home), "--json", *args],
                           env=self.env, cwd=self.root / "repo", stdin=subprocess.DEVNULL,
                           capture_output=True, timeout=timeout)
        prefix = self.root / f"call-{self.calls:02}"
        prefix.with_suffix(".stdout").write_bytes(r.stdout)
        prefix.with_suffix(".stderr").write_bytes(r.stderr)
        prefix.with_suffix(".json").write_text(json.dumps({"args":args,"exit_code":r.returncode}) + "\n")
        print(json.dumps({"call": self.calls, "args": args, "exit_code": r.returncode}), flush=True)
        return r

    def ok(self, *args):
        r = self.call(*args)
        if r.returncode:
            raise AssertionError((args, r.returncode, r.stdout.decode(), r.stderr.decode()))
        return json.loads(r.stdout)

    def signal(self, identity, sig):
        current = observe(identity["pid"])
        if not current or current["birth"] != identity["birth"] or current["argv"] != identity["argv"]:
            raise AssertionError("exact owned process changed before signal")
        # Both the full current command and private-home membership were read before dispatch.
        if not any(v["pid"] == identity["pid"] for v in owned_rows(self.root)):
            raise AssertionError("process no longer belongs to this private fixture")
        self.result.setdefault("signals", []).append({"identity": current, "signal": int(sig)})
        os.kill(identity["pid"], sig)

    def setup(self):
        # Record supported public flags before using them.
        for args in (("--help",), ("init", "--help"), ("launch", "--help"), ("up", "--help")):
            r = self.call(*args)
            if r.returncode:
                raise AssertionError("public command help unavailable")
        initialized = self.ok("--key", str(uuid.uuid4()), "init", "--repo", str(self.root / "repo"),
                              "--name", "Recovery Judge", "--agent", "Worker", "--provider", "codex",
                              "--model", "gpt-5.3-codex")
        self.project, self.agent = initialized["project"]["id"], initialized["agent"]["id"]
        config = self.home / "config.toml"
        text = config.read_text()
        text = text.replace(f'listen_port = {initialized["profile"]["native_server_port"]}', "", 1)
        text = text.replace("[providers.codex]", "[providers.codex]\ncommand = " + json.dumps(str(self.args.codex.resolve())), 1)
        config.write_text(text)

    def start_host(self):
        if os.name != "nt":
            return self.ok("up")["process"]["pid"]
        stdout = self.root / "foreground.stdout"
        stderr = self.root / "foreground.stderr"
        with stdout.open("wb") as output, stderr.open("wb") as errors:
            self.foreground = subprocess.Popen(
                [str(self.args.se), "--home", str(self.home), "--json", "up", "--foreground"],
                env=self.env, cwd=self.root / "repo", stdin=subprocess.DEVNULL,
                stdout=output, stderr=errors)
        wait_json(self.home / "endpoint.json", seconds=45)
        if self.foreground.poll() is not None:
            raise AssertionError("the foreground runtime exited during startup")
        return self.foreground.pid

    def launch_shared(self, agent):
        launch = self.ok("--project", self.project, "launch", agent, "--detach")
        if launch["state"] != "running":
            raise AssertionError("the shared-server agent did not start")
        session = launch["session_id"]
        ready = wait_json(self.root / "codex" / f"ready-{session}.json")
        if ready["session"] != session:
            raise AssertionError("the provider received a different session")
        forwarder = observe(launch["process"]["pid"])
        server = observe(ready["native_pid"])
        helper = observe(ready["helper_pid"])
        if not all(row and live(row) for row in (forwarder, server, helper)):
            raise AssertionError("an exact shared-server process was not live")
        self.identities.extend((forwarder, server, helper))
        return ready, forwarder, server

    def stop_shared_agent(self, agent, process):
        receipt = self.ok("--project", self.project, "stop", agent)
        if not receipt["complete"] or receipt["witness"]["state"] != "witnessed":
            raise AssertionError("the stop did not witness this agent's exit")
        self.expect_exit(process, "the stopped agent is still live")

    @staticmethod
    def expect_exit(process, reason):
        limit = time.monotonic() + 12
        while time.monotonic() < limit and live(process):
            time.sleep(0.05)
        if live(process):
            raise AssertionError(reason)

    def run_shared(self):
        self.setup()
        runtime = observe(self.start_host())
        if runtime is None:
            raise AssertionError("the runtime birth was unavailable")
        self.identities.append(runtime)
        second = self.ok("--project", self.project, "agent", "add", "Second",
                         "--provider", "codex", "--model", "gpt-5.3-codex")["agent"]["id"]
        first_ready, first_agent, server = self.launch_shared(self.agent)
        second_ready, second_agent, second_server = self.launch_shared(second)
        agents = ((self.agent, first_ready, first_agent), (second, second_ready, second_agent))
        if ((server["pid"], server["birth"]) != (second_server["pid"], second_server["birth"])
                or len({server["pid"], first_agent["pid"], second_agent["pid"]}) != 3
                or first_ready["thread_id"] == second_ready["thread_id"]
                or first_ready["session"] == second_ready["session"]):
            raise AssertionError("the agents did not retain separate sessions on one server")

        record, = (self.home / "codex-servers").glob("*.json")
        if os.name != "nt":
            self.signal(runtime, signal.SIGKILL)
            self.expect_exit(runtime, "the test runtime did not exit")
            if not all(live(row) for row in (server, first_agent, second_agent)):
                raise AssertionError("the runtime exit ended a live agent or its shared server")
            self.start_host()
            for _, ready, process in agents:
                after = wait_json(self.root / "codex" / f"reconnect-{ready['thread_id']}.json", seconds=50)
                if (after["session"] != ready["session"] or after["native_pid"] != server["pid"]
                        or not live(process) or not live(server)):
                    raise AssertionError("the restarted runtime did not recover the same agent session")
            self.result["runtime_recovered_both_agents"] = True

        for agent, ready, _ in agents:
            self.ok("--project", self.project, "msg", "send", agent, "Check the current session.")
            turn = wait_json(self.root / "codex" / f"turn-{ready['thread_id']}.json", seconds=35)
            if turn != {"thread_id": ready["thread_id"], "session": ready["session"]}:
                raise AssertionError("a new turn reached a different session")
        self.result["separate_sessions"] = True

        self.stop_shared_agent(self.agent, first_agent)
        if not live(second_agent) or not live(server) or not record.is_file():
            raise AssertionError("stopping the first agent ended the shared server early")
        self.result["server_kept_for_second_agent"] = True
        self.stop_shared_agent(second, second_agent)
        self.expect_exit(server, "the shared server remained after its last agent stopped")
        limit = time.monotonic() + 5
        while record.exists() and time.monotonic() < limit:
            time.sleep(0.05)
        if record.exists():
            raise AssertionError("the stopped server still has an active custody record")
        self.result["server_ended_after_last_agent"] = True
        self.result["passed"] = True

    def run_record(self, stale):
        self.setup()
        runtime = observe(self.start_host())
        if runtime is None:
            raise AssertionError("the runtime birth was unavailable")
        earlier = None
        if stale:
            _, first_agent, first_server = self.launch_shared(self.agent)
            record, = (self.home / "codex-servers").glob("*.json")
            earlier = record.read_bytes()
            self.stop_shared_agent(self.agent, first_agent)
            self.expect_exit(first_server, "the previous shared server is still live")
            limit = time.monotonic() + 5
            while record.exists() and time.monotonic() < limit:
                time.sleep(0.05)
            if record.exists():
                raise AssertionError("the previous record was not removed")
        _, agent, server = self.launch_shared(self.agent)
        record, = (self.home / "codex-servers").glob("*.json")
        exact = record.read_bytes()
        if earlier is not None and earlier == exact:
            raise AssertionError("the previous and current server records are identical")
        try:
            if earlier is None:
                record.unlink()
            else:
                record.write_bytes(earlier)
            reply = self.call("down", timeout=40)
            self.result["record_refusal_exit"] = reply.returncode
            self.result["server_live_after_record_refusal"] = live(server)
            self.result["agent_live_after_record_refusal"] = live(agent)
            text = (reply.stdout + reply.stderr).decode("utf-8", "replace")
            self.result["record_path_reported"] = record.name in text
            self.result["record_remedy_reported"] = "relaunch" in text or "resolve the named custody" in text
            if not self.result["server_live_after_record_refusal"]:
                raise AssertionError("the shared server was stopped without its current record")
            if not reply.returncode or not self.result["record_path_reported"] or not self.result["record_remedy_reported"]:
                raise AssertionError("the stop refusal did not identify the record and a recovery step")
            self.result["passed"] = True
        finally:
            if live(server):
                record.write_bytes(exact)
                if not live(runtime):
                    self.start_host()

    def run(self):
        self.setup()
        launched = self.ok("--project", self.project, "launch", self.agent, "--detach", "--force")
        self.result["initial_launch"] = launched
        if launched["state"] != "running":
            raise AssertionError("initial provider did not reach running")
        rows = owned_rows(self.root)
        runtimes = [r for r in rows if "--stateengine-private-runtime-bootstrap" in r["argv"]]
        providers = [r for r in rows if r["image"] == str(self.args.codex.resolve())]
        if len(runtimes) != 1 or len(providers) != 1:
            raise AssertionError(("fixture identities ambiguous", rows))
        runtime, provider = runtimes[0], providers[0]
        agent_process = observe(launched["process"]["pid"])
        if not agent_process or not any(row["pid"] == agent_process["pid"] for row in rows):
            raise AssertionError("native agent identity absent")
        shared = agent_process["pid"] != provider["pid"]
        if shared and "--stateengine-private-codex-forward" not in agent_process["argv"]:
            raise AssertionError("the distinct agent process is not the provider forwarder")
        ready = wait_json(self.root / "repo/provider-ready.json")
        helper_pid = ready["helper_pid"]
        helper = observe(helper_pid)
        if not helper or not any(row["pid"] == helper_pid for row in rows):
            raise AssertionError("native provider helper identity absent")
        self.identities += [runtime, provider, helper]
        if shared:
            self.identities.append(agent_process)
        self.result["before_crash"] = rows
        self.signal(runtime, signal.SIGKILL)
        end = time.monotonic() + 5
        while live(runtime) and time.monotonic() < end:
            time.sleep(0.05)
        if live(runtime) or not all(live(row) for row in (provider, agent_process)):
            raise AssertionError("the agent and its provider did not survive the runtime exit")
        if self.args.scenario == "slow":
            # Stall the one agent's transport when it has its own forwarding
            # process. A private provider continues to own its original pair.
            for process in (agent_process,) if shared else (helper, provider):
                self.signal(process, signal.SIGSTOP)
                self.stopped.append(process)
        self.result["after_crash"] = owned_rows(self.root)
        started = time.monotonic()
        up = self.call("up")
        self.result["up_exit"] = up.returncode
        self.result["up_seconds"] = time.monotonic() - started
        if up.returncode:
            raise AssertionError(("se up failed", up.stdout.decode(), up.stderr.decode()))
        # Recovery supervision is asynchronous after endpoint readiness.
        # The slow control waits for the engine's committed conclusion under
        # a failure ceiling; the crash control keeps waiting on its reconnect
        # event.
        slow = self.args.scenario == "slow"
        end = time.monotonic() + (30 if slow else 55)
        self.result["slow_conclusion"] = None
        while time.monotonic() < end:
            if not all(live(row) for row in (provider, agent_process)):
                break
            if slow:
                session = (self.ok("--project", self.project, "status")
                           ["agents"]["items"][0]["session"])
                # A status read can outlast the ceiling on a loaded box;
                # recheck it before acting on the read.
                if time.monotonic() >= end:
                    break
                if (session["state"] == "recovery-pending"
                        and session["process_state"]["value"] == "stop-unproved"):
                    self.result["slow_conclusion"] = {
                        "state": session["state"],
                        "process_state": session["process_state"]["value"],
                        "liveness": session["liveness"]["value"],
                        "waited_seconds": round(time.monotonic() - started, 2),
                    }
                    break
            elif (self.root / "repo/provider-reconnect.json").exists():
                break
            time.sleep(0.25)
        self.result["original_provider_alive_after_recovery"] = live(provider)
        self.result["after_recovery"] = owned_rows(self.root)
        if self.args.scenario == "slow":
            if not all(live(row) for row in (provider, agent_process)):
                raise AssertionError("recovery ended a slow but still-live agent or provider")
            if self.result["slow_conclusion"] is None:
                raise AssertionError(
                    "the engine did not commit the provider-recovery conclusion "
                    "while the slow provider stayed live")
            for process in self.stopped:
                self.signal(process, signal.SIGCONT)
            self.stopped = []
            self.result["passed"] = True
        else:
            if not all(live(row) for row in (provider, helper, agent_process)):
                raise AssertionError("recovery stopped the original provider without explicit consent")
            recovered = json.loads((self.root / "repo/provider-reconnect.json").read_text())
            if (recovered["connection"] < 2 or recovered["native_pid"] != provider["pid"]
                    or recovered["helper_pid"] != helper["pid"]
                    or recovered["thread_id"] != ready["thread_id"]
                    or recovered["policy"] != ready["policy"]):
                raise AssertionError("the original provider did not echo its saved policy on reconnect")
            self.result["provider_reconnect"] = recovered
            refused = self.call("--project", self.project, "launch", self.agent, "--detach")
            refusal = refused.stdout + refused.stderr
            self.result["plain_launch_exit"] = refused.returncode
            if (not refused.returncode or b"launch-confirmation-required" not in refusal
                    or b"--force" not in refusal or b"Worker" not in refusal
                    or b"No process was stopped" not in refusal):
                raise AssertionError(("plain launch did not name the exact force route", refusal.decode()))
            if not all(live(row) for row in (provider, helper, agent_process)):
                raise AssertionError("plain launch disturbed the original provider")
            retry = self.call("--project", self.project, "--key", "crash-force",
                              "launch", self.agent, "--detach", "--force")
            self.result["relaunch_exit"] = retry.returncode
            if retry.returncode:
                raise AssertionError(("forced relaunch required a hand-run stop", retry.stdout.decode(), retry.stderr.decode()))
            relaunched = json.loads(retry.stdout)
            self.result["relaunch"] = relaunched
            if relaunched["state"] != "running" or live(agent_process):
                raise AssertionError("relaunch did not replace and retire the old agent")
            if not shared and (live(provider) or live(helper)):
                raise AssertionError("relaunch left the old private provider scope active")
            takeover = relaunched["takeover"]
            if (takeover["previous_session"] != launched["session_id"]
                    or relaunched["session_id"] == launched["session_id"]
                    or takeover.get("inventory_failure")
                    or takeover.get("jobs_remaining") or takeover.get("jobs_unproved")):
                raise AssertionError(("forced takeover was not completely witnessed", relaunched))
            successor = observe(relaunched["process"]["pid"])
            expected_image = self.args.se if shared else self.args.codex
            if not successor or not live(successor) or successor["image"] != str(expected_image.resolve()):
                raise AssertionError("replacement native agent birth absent")
            self.identities.append(successor)
            replay = self.ok("--project", self.project, "--key", "crash-force",
                             "launch", self.agent, "--detach", "--force")
            if replay["session_id"] != relaunched["session_id"] or not live(successor):
                raise AssertionError("same-key forced replay replaced its own successor")
            self.result["force_replay"] = replay
            self.result["passed"] = True

    def cleanup(self):
        for process in self.stopped:
            if live(process):
                self.signal(process, signal.SIGCONT)
        try:
            down = self.call("down", timeout=40)
            self.result["cleanup_down_exit"] = down.returncode
            receipt = json.loads(down.stdout) if down.returncode == 0 else {}
            if (down.returncode or not receipt.get("complete")
                    or receipt.get("witness", {}).get("state") != "witnessed"):
                raise AssertionError("public down did not witness complete shutdown")
        except Exception as error:
            self.result["cleanup_down_error"] = str(error)
            self.result["passed"] = False
        if os.name == "nt":
            if self.foreground is not None:
                try:
                    self.foreground.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.result["passed"] = False
            remaining = [row for row in self.identities if live(row)]
            self.result["cleanup_remaining"] = remaining
            if remaining:
                self.result["passed"] = False
            self.save_result()
            return
        remaining = owned_rows(self.root)
        self.result["cleanup_remaining"] = remaining
        if any(live(row) for row in remaining):
            self.result["passed"] = False
        # Cleanup never broad-kills: only fixture-owned identities just read in full.
        for row in remaining:
            if live(row):
                self.signal(row, signal.SIGKILL)
        end = time.monotonic() + 5
        while any(live(row) for row in remaining) and time.monotonic() < end:
            time.sleep(.05)
        self.result["cleanup_after_signals"] = owned_rows(self.root)
        self.save_result()

    def save_result(self):
        for name in ("provider-stderr.txt", "provider-error.txt", "provider-exit.txt"):
            path = self.root / name if name != "provider-error.txt" else self.root / "repo" / name
            if path.exists():
                self.result[name] = path.read_text()
        (self.root / "result.json").write_text(json.dumps(self.result, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scenario", choices=("crash", "slow", "shared", "missing-record", "stale-record"), required=True)
    args = parser.parse_args()
    judge = Judge(args)
    try:
        if args.scenario == "shared":
            judge.run_shared()
        elif args.scenario in ("missing-record", "stale-record"):
            judge.run_record(stale=args.scenario == "stale-record")
        else:
            judge.run()
    except Exception as error:
        judge.result["passed"] = False
        judge.result["failure"] = str(error)
        print(str(error), flush=True)
    finally:
        judge.cleanup()
    return 0 if judge.result.get("passed") else 1

if __name__ == "__main__":
    raise SystemExit(main())
