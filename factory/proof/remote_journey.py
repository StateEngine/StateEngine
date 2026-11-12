"""Observe the public SSH/CLI remote journey; never substitute a local transport.

The destination must be a registered disposable Linux account. Its provider
login is copied into the fixture without refresh tokens for each attempt.
Run from an OS scheduler outside managed agent ancestry, as for nightly.py.
"""
import hashlib
import json
from pathlib import Path
import shlex
import time
import uuid

from remote_credentials import Credentials, provider_binary
from remote_process import Command


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")
    temporary.replace(path)


class Journey:
    def __init__(self, config, executable, directory, env, product, deadline=None):
        self.config, self.se, self.directory, self.env = config, Path(executable), directory, env
        self.directory.mkdir(mode=0o700)
        self.source = directory / "source-home"
        self.workspace = directory / "source-work"
        self.workspace.mkdir()
        self.nonce = uuid.uuid4().hex
        self.remote_root = ".stateengine-remote-proof/" + self.nonce
        self.remote_se = self.remote_root + "/se"
        self.target = self.session = None
        self.watch = self.lock = self.credentials = None
        self.remote_runtime = False
        self.custody_safe = True
        self.deadline = deadline or time.monotonic() + 900
        self.commands = 0
        self.record = {"schema": "se.remote-journey/v1", "product_commit": product,
            "binary_sha256": sha256(self.se), "surface": config.get("surface"),
            "source_platform": "linux", "destination_platform": "linux", "state": "running",
            "steps": [], "timings": {}, "cleanup_errors": [], "errors": []}
        self.persist()

    def persist(self):
        save(self.directory / "remote.json", self.record)

    def start(self, argv, data=None, hold_stdin=False):
        self.commands += 1
        return Command(argv, self.directory / f"{self.commands:02}-command", self.env, data, hold_stdin)

    def command(self, argv, data=None):
        process = self.start(argv, data)
        try:
            return process.finish(self.bound(self.config.get("command_timeout_seconds", 120)))
        finally:
            process.close()

    def bound(self, maximum):
        remaining = min(maximum, self.deadline - time.monotonic())
        if remaining <= 0:
            raise RuntimeError("whole-run deadline expired")
        return remaining

    def local(self, *args):
        return self.command([self.se, "--home", self.source, "--json", *args])

    def ssh(self, *args):
        return ["ssh", "-T", "-o", "BatchMode=yes", self.config["destination"], *args]

    def remote(self, *args):
        return self.command(self.ssh('PATH=' + shlex.quote(self.remote_root + '/bin') + ':"$PATH" ' +
                                    shlex.join([self.remote_se, "--json", *args])))

    def transfer(self, source, destination):
        transfer = self.start(["scp", "-q", "-B", source, self.config["destination"] + ":" + destination])
        try:
            deadline = time.monotonic() + self.bound(120)
            while transfer.selector.get_map():
                if time.monotonic() > deadline:
                    raise RuntimeError("native image transfer timed out")
                transfer.pump(0.25)
            if transfer.process.wait(timeout=5):
                raise RuntimeError("native image transfer failed")
        finally:
            transfer.close()

    def step(self, name):
        self.record["steps"].append(name)
        self.persist()

    def timing(self, name, milliseconds, boundary, qualification="observed"):
        self.record["timings"][name] = {"milliseconds": milliseconds,
            "boundary": boundary, "qualification": qualification}
        self.persist()

    @staticmethod
    def page(value):
        return value.get("value", value)

    def open_watch(self, cursors=None):
        args = [self.se, "--home", self.source, "--json", "remote", "watch", "--host", "journey",
                "--target", self.target, "--visible", self.target, "--measure", "--wait-ms", "1000"]
        if cursors is not None:
            args += ["--cursors", json.dumps(cursors)]
        self.watch = self.start(args)
        observed = self.watch.until(lambda pipe, _, value: pipe == "stdout" and
            any(row.get("type") == "snapshot" for row in self.page(value).get("records", [])), self.bound(60))
        if self.page(observed[2]).get("reset_required") is not False:
            raise RuntimeError("watch snapshot requires a reset; reconnect continuity is unavailable")
        return observed

    def view(self):
        page = self.local("remote", "list", "--host", "journey", "--target", self.target)
        rows = page["agents"]["items"]
        if len(rows) != 1 or rows[0]["target"] != self.target_parts:
            raise RuntimeError("remote list did not witness the exact launched target")
        return rows[0]

    def running(self):
        status = self.view()["status"]
        if status.get("state") != "present" or status["value"].get("state") != "running":
            raise RuntimeError("exact remote session is not witnessed running")
        return status["value"]

    def observe_reply(self, marker):
        row = self.watch.until(lambda pipe, _, value: pipe == "stdout" and any(
            record.get("type") == "provisional" and record.get("target") == self.target_parts and
            record.get("item", {}).get("role") == "assistant" and
            marker in record["item"]["preview"]["text"]
            for record in self.page(value).get("records", [])), self.bound(self.config.get("task_timeout_seconds", 180)))
        return self.page(row[2])

    def prepare(self):
        if self.config.get("surface") not in {"claude", "codex"}:
            raise RuntimeError("remote surface must be claude or codex")
        if not self.config.get("destination") or self.config["destination"].startswith("-"):
            raise RuntimeError("configure a dedicated SSH destination; remote coverage cannot be skipped")
        # Reuse the administrator-registration check rather than trusting HOME.
        check = Path(self.config.get("account_check", Path(__file__).resolve().parents[2] /
                                     "scripts/ci/installation_account.py"))
        program = check.read_text().split('if __name__ == "__main__":')[0]
        program += ('\nrequire()\nidentity,profile=account()\n'
                    'if Path.home()!=profile: raise RuntimeError("SSH home differs from native registered profile")\n'
                    'print(json.dumps({"registered":True,"identity":identity,"profile":str(profile)}))\n')
        args = self.ssh("python3 -c " + shlex.quote(program))
        registered = self.command(args)
        self.record["destination_account"] = registered
        self.remote_root = str(Path(registered["profile"]) / self.remote_root)
        self.remote_se = self.remote_root + "/se"
        lock = '''import fcntl,json,os,stat,sys
from pathlib import Path
p=Path.home()/'.stateengine-remote-proof'
p.mkdir(mode=0o700,exist_ok=True)
i=p.lstat()
if not stat.S_ISDIR(i.st_mode) or i.st_uid!=os.getuid() or i.st_mode & 0o077:
 raise RuntimeError('unsafe fixture directory')
with (p/'lock').open('a') as f:
 fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
 print(json.dumps({'locked':True}),flush=True)
 sys.stdin.read()
'''
        self.lock = self.start(self.ssh("python3 -u -c " + shlex.quote(lock)), hold_stdin=True)
        self.lock.until(lambda pipe, _, value: pipe == "stdout" and value.get("locked") is True, self.bound(30))
        # Every attempt stages its own image and repository; no incumbent image
        # or user project is overwritten. The remote account is fixture-only.
        setup = ("umask 077; mkdir " + shlex.quote(self.remote_root) + " && mkdir " +
                 shlex.quote(self.remote_root + "/work") + " " + shlex.quote(self.remote_root + "/bin") +
                 " && printf '{\"created\":true}\\n'")
        self.command(self.ssh(setup))
        self.transfer(self.se, self.remote_se)
        self.transfer(provider_binary(self.config["surface"], self.config),
                      self.remote_root + "/bin/" + self.config["surface"])
        self.credentials = Credentials(self, self.config["auth_home"], self.config.get("credential_sources", {}))
        self.credentials.stage()
        # A structured native hash readback avoids interpreting a pipeline's exit.
        program = ("import hashlib,json\nfrom pathlib import Path\np=Path(" + repr(self.remote_se) +
                   ")\nwith p.open('rb') as f:\n print(json.dumps({'sha256':hashlib.file_digest(f,'sha256').hexdigest()}))")
        actual = self.command(self.ssh("python3 -c " + shlex.quote(program)))
        if actual["sha256"] != self.record["binary_sha256"]:
            raise RuntimeError("remote staged image differs from the selected product")
        initialized = self.remote("init", "--repo", self.remote_root + "/work", "--name", "remote-" + self.nonce,
                                  "--provider", self.config["surface"])
        self.target_parts = {"project": initialized["project"]["id"], "agent": initialized["agent"]["id"]}
        self.target = "/".join(self.target_parts.values())
        self.remote("up")
        self.remote_runtime = True
        self.local("init", "--repo", str(self.workspace), "--name", "source")
        self.step("dedicated account, exact native image and fresh project verified")

    def exercise(self):
        started = time.monotonic_ns()
        self.local("remote", "add", self.config["destination"], "--name", "journey")
        self.open_watch()
        self.timing("attach", (time.monotonic_ns() - started) / 1e6,
                    "remote add invocation through first rendered watch snapshot; destination runtime prepared")
        initial = self.view()["status"]
        if initial.get("state") != "present" or initial["value"].get("state") != "stopped":
            raise RuntimeError("fresh target was not stopped before launch")
        marker = "REMOTE_LIVE_" + self.nonce
        launch_args = ["--project", self.target_parts["project"], "launch",
                      self.target_parts["agent"], "--detach", "--key", self.nonce + "-launch",
                      "--task", "Reply with exactly " + marker]
        launch = self.remote(*launch_args)
        self.session = launch["session_id"]
        deadline = time.monotonic() + self.bound(120)
        while launch.get("state") == "starting" and time.monotonic() < deadline:
            time.sleep(1)
            launch = self.remote(*launch_args)
        if launch.get("state") in {"starting", "setup-needed"}:
            raise RuntimeError("remote launch did not activate; inspect the retained setup refusal")
        if self.running()["session"] != self.session:
            raise RuntimeError("remote list differs from the SSH launch receipt")
        page = self.observe_reply(marker)
        self.step("connected, launched over SSH, and observed live assistant output")
        # Native --measure observes stdout flush. Its cross-host monotonic clock
        # estimate is explicitly unqualified; it is never a proven budget pass.
        cursors = {r["cursor"] for r in page["records"] if r.get("type") == "provisional" and
                   r.get("item", {}).get("role") == "assistant" and marker in r["item"]["preview"]["text"]}
        _, _, sample = self.watch.until(lambda pipe, _, value: pipe == "stderr" and
            value.get("boundary") == "provisional_flushed" and value.get("cursor") in cursors, self.bound(10))
        estimate = sample.get("producer_to_flush_estimate_us")
        if type(estimate) is not int or estimate < 0:
            raise RuntimeError("live output clock estimate unavailable")
        self.timing("live_output", estimate / 1000, "producer observation through CLI stdout flush",
                    sample["qualification"])
        reply = "REMOTE_MAIL_" + self.nonce
        send = self.start([self.se, "--home", self.source, "--json", "remote", "send", "--host", "journey",
            "--target", self.target, "--session", self.session, "--key", self.nonce,
            "Reply with exactly " + reply])
        try:
            _, received, _ = send.until(lambda pipe, _, value: pipe == "stderr" and
                value.get("status") == "local_pending" and value.get("idempotency_key") == self.nonce, self.bound(30))
            self.timing("pending_echo", (received - send.started) / 1e6,
                        "send process invocation through local_pending stderr observation")
            sent = send.finish(self.bound(60))
            if sent["receipt"].get("state") not in {"committed", "replayed"}:
                raise RuntimeError("remote send did not return a durable commit receipt")
        finally:
            send.close()
        page = self.observe_reply(reply)
        self.watch.pump(0)
        cursors = next(self.page(value)["cursors"] for pipe, _, value in reversed(self.watch.rows)
                       if pipe == "stdout" and "cursors" in self.page(value))
        self.step("remote message committed and assistant reply observed")
        before = self.running()
        self.watch.close()
        self.watch = None
        self.local("remote", "disconnect", "--name", "journey")
        started = time.monotonic_ns()
        self.local("remote", "add", self.config["destination"], "--name", "journey")
        self.open_watch(cursors)
        after = self.running()
        if before != after or after["session"] != self.session:
            raise RuntimeError("reconnect replaced the remote session or lifecycle")
        self.timing("reconnect", (time.monotonic_ns() - started) / 1e6,
                    "explicit reconnect through resumed snapshot and exact session readback")
        self.step("disconnected and reconnected with consumed cursors and original lifecycle")

    def cleanup(self):
        # Cleanup has its own finite allowance even when the probe deadline ran
        # out. The scheduler's outer service deadline still bounds the attempt.
        self.deadline = time.monotonic() + 180
        actions = []
        if self.watch is not None:
            actions.append(self.watch.close)
        if self.session is not None:
            actions.append(self.stop_session)
        if self.remote_runtime:
            actions.append(lambda: self.down(remote=True))
        if self.source.exists():
            actions.append(lambda: self.down(remote=False))
        if self.credentials is not None:
            actions.append(self.credentials.close)
        for action in actions:
            try:
                action()
            except Exception as error:
                self.record["cleanup_errors"].append(str(error))
        if self.lock is not None:
            try:
                self.lock.close()
            except Exception as error:
                self.record["cleanup_errors"].append(str(error))
        self.persist()

    def stop_session(self):
        self.custody_safe = False
        current = self.running()
        if current["session"] != self.session:
            raise RuntimeError("remote session changed; cleanup refused to stop another session")
        stopped = self.remote("--project", self.target_parts["project"], "stop",
                              self.target_parts["agent"])
        if stopped.get("complete") is not True:
            raise RuntimeError("remote stop did not witness complete process closure")
        if stopped.get("target", {}).get("session_id") != self.session:
            raise RuntimeError("stop receipt names a different session")
        pid = stopped["target"]["process"]["pid"]
        if type(pid) is not int or pid <= 0:
            raise RuntimeError("stop receipt has no exact native process identity")
        program = ("import json; from pathlib import Path; "
                   "print(json.dumps({'process_absent':not Path('/proc/" + str(pid) + "').exists()}))")
        outside = self.command(self.ssh("python3 -c " + shlex.quote(program)))
        if outside.get("process_absent") is not True:
            raise RuntimeError("outside native readback still observes the stopped process ID")
        self.record["process_closure"] = {"session": self.session, "pid": pid,
                                          "stop_complete": True, "outside_process_absent": True}
        self.custody_safe = True

    def down(self, remote):
        if remote and not self.custody_safe:
            raise RuntimeError("destination runtime retained because original session custody is unresolved")
        result = self.remote("down") if remote else self.local("down")
        if result.get("complete") is not True:
            raise RuntimeError("runtime shutdown did not witness complete closure")

    def run(self):
        try:
            self.prepare()
            self.exercise()
            self.record["state"] = "finished"
        except Exception as error:
            self.record["errors"].append(str(error))
            self.record["state"] = "failed"
        finally:
            self.cleanup()
        self.record["passed"] = self.record["state"] == "finished" and not self.record["cleanup_errors"]
        self.persist()
        return self.record
