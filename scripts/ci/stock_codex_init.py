"""Check stock provider setup and Codex managed launch on Linux x64.

Run with a built se executable. Use --loopback for PRs or provide
CI_OPENAI_API_KEY and CI_CODEX_MODEL from nightly-providers for the live run.
This test installs its pinned clients and publishes only a bounded summary.
"""

import argparse
from contextlib import nullcontext
from hashlib import file_digest
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from time import monotonic, sleep
import tomllib
from urllib.request import urlopen
from uuid import uuid4

from stock_codex_responses import KEY as LOOPBACK_KEY, MODEL as LOOPBACK_MODEL, TASK, LoopbackModel

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "crates/se/tests/judges"))
from provider_home import isolate, run_provider_command


CODEX_VERSION = "0.169.0"
CODEX_ARCHIVE = f"https://registry.npmjs.org/@openai/codex/-/codex-{CODEX_VERSION}-linux-x64.tgz"
CODEX_SHA = "89801b4b97faba562eb80fe0a833159ac79399be674022f4b1a0ccab1d153faa"
CLAUDE_VERSION = "2.1.326"
CLAUDE_ARCHIVE = ("https://registry.npmjs.org/@anthropic-ai/claude-code-linux-x64/-/"
                  f"claude-code-linux-x64-{CLAUDE_VERSION}.tgz")
CLAUDE_SHA = "113a6b58f9ee5a94b8bb841252070f60ff5f295b3d28c7f40b480a5b54f5579b"
WEBSOCKETS_WHEEL = ("https://files.pythonhosted.org/packages/fa/a8/"
                    "5b41e0da817d64113292ab1f8247140aac61cbf6cfd085d6a0fa77f4984f/"
                    "websockets-15.0.1-py3-none-any.whl")
WEBSOCKETS_SHA = "f7a866fbc1e97b5c617ee4116daaa09b722101d4a3c170c787450ba409f9736f"
COLLISION_NAMES = ("stateengine-agent", "stateengine-agent-2")
TOOLS = {"stateengine_whoami", "stateengine_help", "stateengine_resume"}
CONNECTOR = Path(__file__).resolve().parent / "fixtures/stock_codex_connector.py"
LOOPBACK_NETWORK = {"HTTP_PROXY": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9",
                    "ALL_PROXY": "http://127.0.0.1:9", "NO_PROXY": "127.0.0.1,localhost"}
CONFIG_PATHS = {"codex": "CODEX_HOME", "claude": "CLAUDE_CONFIG_DIR"}
REFUSALS = {"missing": ("does not exist",), "not-directory": ("not a directory",),
            "unreadable": ("unreadable", "permission denied", "could not read", "cannot read")}


class WitnessFailure(Exception):
    """A fixed diagnostic safe to include in a CI artifact."""


def require(condition, message):
    if not condition:
        raise WitnessFailure(message)


def download(url, path, expected):
    with urlopen(url, timeout=30) as source, path.open("xb") as output:
        shutil.copyfileobj(source, output)
    with path.open("rb") as source:
        require(file_digest(source, "sha256").hexdigest() == expected, "Pinned download hash differs")
    return path


def install(root):
    archive = download(CODEX_ARCHIVE, root / "codex.tgz", CODEX_SHA)
    with tarfile.open(archive) as package:
        package.extractall(root, filter="data")
    codex = root / "package/vendor/x86_64-unknown-linux-musl/bin/codex"
    wheel = download(WEBSOCKETS_WHEEL, root / "websockets-15.0.1-py3-none-any.whl", WEBSOCKETS_SHA)
    sys.path.insert(0, str(wheel))
    from websockets.sync.client import unix_connect
    return codex, unix_connect


def install_claude(root):
    archive = download(CLAUDE_ARCHIVE, root / "claude.tgz", CLAUDE_SHA)
    with tarfile.open(archive, mode="r|gz") as package:
        executable = package.next()
        require(executable is not None and executable.name == "package/claude" and executable.isfile(),
                "The pinned archive did not begin with the Claude executable")
        package.extract(executable, root / "claude", filter="data")
    return root / "claude/package/claude"


class AppServer:
    def __init__(self, connection):
        self.connection = connection
        self.request_id = 0
        self.call("initialize", {"clientInfo": {"name": "stock-init-judge", "version": "1"},
                                 "capabilities": {"experimentalApi": True}})
        self.send({"method": "initialized"})

    def send(self, value):
        self.connection.send(json.dumps({"jsonrpc": "2.0", **value}))

    def call(self, method, params, timeout=15):
        self.request_id += 1
        self.send({"id": self.request_id, "method": method, "params": params})
        deadline = monotonic() + timeout
        while monotonic() < deadline:
            reply = json.loads(self.connection.recv(timeout=max(0, deadline - monotonic())))
            if "method" in reply and "id" in reply:
                self.send({"id": reply["id"], "error": {"code": -32601,
                           "message": "The fixture is noninteractive"}})
            elif reply.get("id") == self.request_id:
                if "result" in reply:
                    return reply["result"]
                code = reply.get("error", {}).get("code")
                raise WitnessFailure(f"Codex {method} failed with RPC code {code if type(code) is int else 'unknown'}")
        raise WitnessFailure(f"Codex {method} did not reply before the deadline")

    def inventory(self, thread, extra, expected_http):
        deadline = monotonic() + 20
        while monotonic() < deadline:
            reply = self.call("mcpServerStatus/list", {"threadId": thread, "detail": "full", "limit": 100})
            require(reply.get("nextCursor") is None, "The MCP inventory unexpectedly has another page")
            active = {row["name"]: row for row in reply["data"]
                      if row.get("runtimeStatus") != "disabled"}
            stateengine = [row for row in active.values() if TOOLS.intersection(row["tools"])]
            if stateengine and all("fixture_status" in active.get(name, {}).get("tools", ()) for name in extra):
                require(len(stateengine) == 1, "The stock thread sees duplicate StateEngine connectors")
                row = stateengine[0]
                require(TOOLS.issubset(row["tools"]), "The StateEngine catalogue is incomplete")
                require((row.get("httpOrigin") is not None) == expected_http, "The StateEngine connector transport changed")
                return row["name"], len(row["tools"])
            sleep(0.25)
        raise WitnessFailure("The expected MCP catalogues were not discovered")

    def whoami(self, thread, server, launch):
        reply = self.call("mcpServer/tool/call", {"threadId": thread, "server": server,
                                                  "tool": "stateengine_whoami", "arguments": {}})
        require(not reply.get("isError"), "The managed StateEngine tool call failed")
        identity = reply.get("structuredContent")
        if identity is None:
            identity = json.loads(reply["content"][0]["text"])
        require(identity["session"]["id"] == launch["session_id"]
                and identity["agent"]["id"] == launch["agent"]["id"],
                "The managed tool returned a different agent or session")

    def witness_model_turn(self, thread):
        deadline = monotonic() + 60
        while monotonic() < deadline:
            result = self.call("thread/read", {"threadId": thread, "includeTurns": True},
                               timeout=min(15, max(0, deadline - monotonic())))
            for turn in result["thread"]["turns"]:
                if turn["status"] == "completed" and any(
                    item["type"] == "agentMessage" and item.get("text", "").strip() for item in turn["items"]
                ):
                    return
                require(turn["status"] not in ("failed", "interrupted"), "The stock model turn failed")
            sleep(0.4)
        raise WitnessFailure("The stock model did not complete a reply before the deadline")


class Fixture:
    def __init__(self, root, se, codex):
        self.root, self.se, self.codex = root, se, codex
        self.repo, self.home, self.bin = (root / name for name in ("repo", "home", "bin"))
        self.login, self.state, self.runtime = self.home / ".codex", root / "se", root / "run"
        self.config, self.auth = self.login / "config.toml", self.login / "auth.json"
        self.env = {"PATH": str(self.bin),
                    "TMPDIR": str(self.runtime), "SHELL": "/bin/bash", "LANG": "C.UTF-8",
                    **{f"XDG_{part.upper()}_HOME": str(root / part)
                       for part in ("cache", "config", "data", "state")}}

    def spawn(self, binary, *words):
        return run_provider_command(subprocess.run, [str(binary), *words], cwd=self.repo,
                                    environment=self.env, fixture=self.root, stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=45)

    def run(self, binary, *words):
        result = self.spawn(binary, *words)
        if result.returncode:
            try:
                code = json.loads(result.stdout).get("code", "")
            except (ValueError, AttributeError):
                code = ""
            code = code if isinstance(code, str) and re.fullmatch(r"[a-z0-9-]{1,64}", code) else "unknown"
            raise WitnessFailure(f"{binary.name} exited {result.returncode} ({code})")
        return result.stdout

    def cli(self, *words):
        return json.loads(self.run(self.se, "--json", "--home", str(self.state), *words))

    def prepare_repository(self, provider, executable):
        git = shutil.which("git")
        require(git is not None, "Git is required for the fixture repository")
        for directory in (self.root, self.repo, self.home, self.login, self.bin, self.runtime):
            directory.mkdir(mode=0o700)
        isolate(self.env, self.root, self.home, codex=self.login)
        for name, path in (("se", self.se), (provider, executable), ("git", Path(git).resolve(strict=True))):
            (self.bin / name).symlink_to(path)
        self.run(self.bin / "git", "init", "-q")

    def prepare(self, key, model, loopback_url):
        self.prepare_repository("codex", self.codex)
        # Stock workspace-write launches can save project trust. Preload that
        # setting so the byte check measures changes to MCP registration.
        config = f"""model = {json.dumps(model)}
cli_auth_credentials_store = "file"
sandbox_mode = "read-only"
approval_policy = "never"

[features]
apps = false

[projects.{json.dumps(str(self.repo))}]
trust_level = "trusted"
"""
        if loopback_url is not None:
            config = 'model_provider = "fixture"\n' + config + f"""
[model_providers.fixture]
name = "Stock Codex smoke fixture"
base_url = {json.dumps(loopback_url)}
wire_api = "responses"
requires_openai_auth = true
supports_websockets = false
request_max_retries = 0
stream_max_retries = 0
"""
            self.env.update(LOOPBACK_NETWORK)
        self.config.write_text(config, encoding="utf-8")
        descriptor = os.open(self.auth, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump({"auth_mode": "apikey", "OPENAI_API_KEY": key}, stream)
        require(self.run(self.codex, "--version").decode().strip() == f"codex-cli {CODEX_VERSION}",
                "The stock executable did not report the pinned version")

    def exercise(self, case, model, connect, receipt):
        if case == "existing":
            self.run(self.codex, "mcp", "add", "stateengine", "--", "se", "--home", str(self.state), "mcp")
        collision = COLLISION_NAMES if case == "collision" else ()
        for occupied in collision:
            self.run(self.codex, "mcp", "add", occupied, "--", sys.executable, "-B", str(CONNECTOR))
        before = self.config.read_bytes()
        receipt["stage"] = "se init"
        self.cli("--key", str(uuid4()), "init", "--repo", str(self.repo), "--name", "Codex smoke fixture",
                 "--agent", "Worker", "--provider", "codex", "--model", model)
        saved = self.config.read_bytes()
        entry = tomllib.loads(saved.decode())["mcp_servers"]["stateengine"]
        require(entry["command"] == "se" and entry["args"] == ["--home", str(self.state), "mcp"],
                "se init did not leave a usable saved stdio registration")
        if case == "existing":
            require(before == saved, "se init rewrote the existing Codex registration")
        receipt["stage"] = "managed launch"
        launch = self.cli("launch", "Worker", "--detach", "--task", TASK)
        require(launch["state"] == "running", "The managed launch did not reach running")
        socket = self.login / "app-server-control/app-server-control.sock"
        thread = launch["conversation_id"]
        with connect(str(socket), uri="ws://localhost/", open_timeout=5, close_timeout=2) as connection:
            rpc = AppServer(connection)
            receipt["stage"] = "managed MCP discovery"
            name, count = rpc.inventory(thread, collision, expected_http=True)
            require(name == ("stateengine-agent-3" if collision else "stateengine-agent"),
                    "The managed thread did not select the first free connector name")
            rpc.whoami(thread, name, launch)
            receipt.update(connector=name, tool_count=count, managed_identity_matched=True)
            receipt["stage"] = "stock model turn"
            rpc.witness_model_turn(thread)
            receipt["model_reply_completed"] = True
            receipt["stage"] = "ordinary stock thread"
            external = rpc.call("thread/start", {"cwd": str(self.repo), "ephemeral": True})["thread"]["id"]
            name, _ = rpc.inventory(external, collision, expected_http=False)
            require(name == "stateengine", "An ordinary thread did not find its standing registration")
        require(self.config.read_bytes() == saved, "Managed launch or discovery changed the saved Codex config")
        receipt.update(saved_config_unchanged=True, ordinary_thread_uses_saved_connector=True)

    def stop(self):
        self.auth.unlink(missing_ok=True)
        if self.state.exists():
            reply = self.cli("down")
            require(reply["complete"] and not (self.state / "endpoint.json").exists(),
                    "The private runtime did not stop completely")


def check_case(fixture, case, key, model, connect, loopback_url):
    started = monotonic()
    receipt = {"passed": False, "stage": "fixture setup"}
    try:
        fixture.prepare(key, model, loopback_url)
        fixture.exercise(case, model, connect, receipt)
        receipt.update(passed=True, stage="complete")
    except Exception as failure:
        receipt["failure"] = str(failure) if isinstance(failure, WitnessFailure) else type(failure).__name__
    finally:
        try:
            fixture.stop()
            receipt["runtime_stopped"] = True
        except Exception as failure:
            receipt.update(passed=False, runtime_stopped=False, cleanup_error=type(failure).__name__)
    receipt["seconds"] = round(monotonic() - started, 2)
    return receipt


def profile_snapshot(profile):
    snapshot = {}
    for path in profile.rglob("*"):
        relative = path.relative_to(profile)
        if path.is_symlink():
            snapshot[relative] = ("link", path.readlink())
        elif path.is_dir():
            snapshot[relative] = ("directory", None)
        else:
            require(path.is_file(), "The provider profile gained a special file")
            with path.open("rb") as stream:
                snapshot[relative] = ("file", file_digest(stream, "sha256").hexdigest())
    return snapshot


def check_config_refusal(fixture, provider, executable, problem):
    receipt = {"passed": False}
    try:
        fixture.env.update(LOOPBACK_NETWORK)
        fixture.prepare_repository(provider, executable)
        version = fixture.run(executable, "--version").decode().strip()
        expected = f"codex-cli {CODEX_VERSION}" if provider == "codex" else f"{CLAUDE_VERSION} (Claude Code)"
        require(version == expected, "The harness did not report its pinned version")
        key = CONFIG_PATHS[provider]
        parent = fixture.home / "selected"
        parent.mkdir(mode=0o700)
        target = parent / "config"
        if problem == "not-directory":
            target.write_bytes(b"existing private file\n")
        if problem == "unreadable":
            target.mkdir(mode=0o700)
        before = profile_snapshot(fixture.home)
        fixture.env[key] = str(target)
        try:
            if problem == "unreadable":
                parent.chmod(0)
                try:
                    target.stat()
                except PermissionError:
                    pass
                else:
                    raise WitnessFailure("The OS did not deny access to the fixture path")
            result = fixture.spawn(fixture.se, "--json", "--home", str(fixture.state), "init", "--repo",
                                   str(fixture.repo), "--agent", "Worker", "--provider", provider)
        finally:
            if problem == "unreadable":
                parent.chmod(0o700)
        receipt["profile_unchanged"] = before == profile_snapshot(fixture.home)
        message = json.loads(result.stdout).get("message", "")
        outcome = message.replace(str(target), "").lower()
        receipt.update(refused=result.returncode > 0, directory_named=key in message and str(target) in message,
                       outcome_identified=any(reason in outcome for reason in REFUSALS[problem]))
        require(receipt["refused"], "Init did not refuse the invalid provider config path")
        require(receipt["directory_named"], "The refusal did not name the configured directory")
        require(receipt["outcome_identified"], "The refusal did not describe the path outcome")
        require(receipt["profile_unchanged"], "Init changed the private provider profile")
        receipt["passed"] = True
    except Exception as failure:
        receipt["failure"] = str(failure) if isinstance(failure, WitnessFailure) else type(failure).__name__
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="Path for the bounded JSON receipt")
    parser.add_argument("--loopback", action="store_true", help="Run with a private model server and a synthetic key")
    args = parser.parse_args()
    report = {"stock_codex": CODEX_VERSION, "model_mode": "loopback" if args.loopback else "live", "cases": {}}
    started = monotonic()
    try:
        require(sys.platform == "linux" and platform.machine() == "x86_64", "This stock pin is for Linux x64")
        if args.loopback:
            key, model = LOOPBACK_KEY, LOOPBACK_MODEL
        else:
            key, model = os.environ.get("CI_OPENAI_API_KEY"), os.environ.get("CI_CODEX_MODEL", "")
            require(key and key.strip() == key, "The dedicated nightly Codex API key is absent or invalid")
            require(re.fullmatch(r"[A-Za-z0-9._:/+-]{1,128}", model) and key not in model,
                    "The dedicated nightly Codex model is absent or invalid")
        se = args.se.resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="se-codex-", dir="/tmp") as temp:
            root = Path(temp)
            codex, connect = install(root)
            if args.loopback:
                claude = install_claude(root)
            report["install_seconds"] = round(monotonic() - started, 2)
            if args.loopback:
                refusals = report["configuration_refusals"] = {}
                for provider, executable in (("codex", codex), ("claude", claude)):
                    for problem in REFUSALS:
                        fixture = Fixture(root / f"config-{len(refusals)}", se, codex)
                        refusals[f"{provider}-{problem}"] = check_config_refusal(fixture, provider, executable, problem)
            with LoopbackModel() if args.loopback else nullcontext() as mock:
                url = mock.url if mock is not None else None
                for name in ("fresh", "existing", "collision"):
                    report["cases"][name] = check_case(Fixture(root / name, se, codex), name, key, model, connect, url)
                if mock is not None:
                    with mock.lock:
                        report["model_requests_verified"] = mock.accepted
                        require(mock.accepted == 3 and mock.rejected == 0,
                                "The loopback service did not verify three authenticated model requests")
    except Exception as failure:
        report["failure"] = str(failure) if isinstance(failure, WitnessFailure) else type(failure).__name__
    report["seconds"] = round(monotonic() - started, 2)
    report["passed"] = ("failure" not in report and len(report["cases"]) == 3
                        and all(case["passed"] for case in report["cases"].values()))
    if args.loopback:
        refusals = report.get("configuration_refusals", {})
        report["passed"] &= len(refusals) == 6 and all(row["passed"] for row in refusals.values())
    encoded = json.dumps(report, indent=2) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
