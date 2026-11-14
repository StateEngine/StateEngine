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


def observe(pid):
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
        self.calls = 0
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
        args.codex = self.root / "provider"
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

    def run(self):
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
        ready = json.loads((self.root / "repo/provider-ready.json").read_text())
        helper_pid = ready["helper_pid"]
        helper = observe(helper_pid)
        if not helper or not any(row["pid"] == helper_pid for row in rows):
            raise AssertionError("native provider helper identity absent")
        self.identities += [runtime, provider, helper]
        self.result["before_crash"] = rows
        self.signal(runtime, signal.SIGKILL)
        end = time.monotonic() + 5
        while live(runtime) and time.monotonic() < end:
            time.sleep(0.05)
        if live(runtime) or not live(provider):
            raise AssertionError("runtime crash did not leave the exact provider alive")
        if self.args.scenario == "slow":
            for process in (helper, provider):
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
        end = time.monotonic() + (48 if self.args.scenario == "slow" else 55)
        while time.monotonic() < end:
            if not live(provider):
                break
            if self.args.scenario == "crash" and (self.root / "repo/provider-reconnect.json").exists():
                break
            time.sleep(0.25)
        self.result["original_provider_alive_after_recovery"] = live(provider)
        self.result["after_recovery"] = owned_rows(self.root)
        if self.args.scenario == "slow":
            if not live(provider):
                raise AssertionError("recovery reaped a slow but still-live provider")
            for process in self.stopped:
                self.signal(process, signal.SIGCONT)
            self.stopped = []
            self.result["passed"] = True
        else:
            if not live(provider) or not live(helper):
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
            if not live(provider) or not live(helper):
                raise AssertionError("plain launch disturbed the original provider")
            retry = self.call("--project", self.project, "--key", "crash-force",
                              "launch", self.agent, "--detach", "--force")
            self.result["relaunch_exit"] = retry.returncode
            if retry.returncode:
                raise AssertionError(("forced relaunch required a hand-run stop", retry.stdout.decode(), retry.stderr.decode()))
            relaunched = json.loads(retry.stdout)
            self.result["relaunch"] = relaunched
            if relaunched["state"] != "running" or live(provider) or live(helper):
                raise AssertionError("relaunch did not replace and retire the orphan")
            takeover = relaunched["takeover"]
            if (takeover["previous_session"] != launched["session_id"]
                    or relaunched["session_id"] == launched["session_id"]
                    or takeover.get("inventory_failure")
                    or takeover.get("jobs_remaining") or takeover.get("jobs_unproved")):
                raise AssertionError(("forced takeover was not completely witnessed", relaunched))
            successor = observe(relaunched["process"]["pid"])
            if not successor or not live(successor) or successor["image"] != str(self.args.codex.resolve()):
                raise AssertionError("replacement native provider birth absent")
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
        for name in ("provider-stderr.txt", "provider-error.txt", "provider-exit.txt"):
            path = self.root / name if name != "provider-error.txt" else self.root / "repo" / name
            if path.exists():
                self.result[name] = path.read_text()
        (self.root / "result.json").write_text(json.dumps(self.result, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scenario", choices=("crash", "slow"), required=True)
    args = parser.parse_args()
    judge = Judge(args)
    try:
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
