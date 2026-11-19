"""Account-free provider for the native launch judges."""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import urllib.request
import uuid


def save(path, value):
    temporary = path.with_suffix(".pending")
    temporary.write_text(json.dumps(value), encoding="utf-8")
    temporary.replace(path)


def process_environment():
    if sys.platform == "linux":
        return Path("/proc/self/environ").read_bytes().decode(errors="surrogateescape").strip("\0").split("\0")
    if os.name != "nt":
        return [f"{key}={value}" for key, value in os.environ.items()]
    kernel = ctypes.WinDLL("kernel32")
    get = kernel.GetEnvironmentStringsW
    get.restype = ctypes.c_void_p
    free = kernel.FreeEnvironmentStringsW
    free.argtypes = [ctypes.c_void_p]
    address = get()
    if not address:
        raise OSError("own environment block is unavailable")
    try:
        rows = []
        offset = 0
        while row := ctypes.wstring_at(address + offset * ctypes.sizeof(ctypes.c_wchar)):
            rows.append(row)
            offset += len(row.encode("utf-16-le", errors="surrogatepass")) // 2 + 1
        return rows
    finally:
        free(address)


def observe_environment(root):
    entries = process_environment()
    sessions = [value if value.startswith("ses_") else None
                for entry in entries for name, _, value in [entry.partition("=")]
                if name.upper() == "SE_SESSION"]
    save(root / "environment.json", {
        "sessions": sessions,
        "has_credential_bytes": any("sec1." in entry for entry in entries),
        "has_credential_argv": any("sec1." in word for word in sys.argv),
    })


def prepared_reply(data):
    reply = json.loads(data)
    return "result" in reply or reply.get("error", {}).get("message", "").startswith(
        "session-not-active:"
    )


def discovery_request():
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()


def prepared_session(se, home):
    result = subprocess.run(
        [se, "--home", home, "mcp"], input=discovery_request() + b"\n",
        capture_output=True, timeout=10,
    )
    return result.returncode == 0 and prepared_reply(result.stdout)


def consumer(root, se, home):
    deadline = time.monotonic() + 60
    while not (root / "call-se").exists():
        if time.monotonic() >= deadline:
            return
        time.sleep(0.05)
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "stateengine_whoami", "arguments": {}}}
    result = subprocess.run(
        [se, "--home", home, "mcp"], input=(json.dumps(request) + "\n").encode(),
        capture_output=True, timeout=15,
    )
    observation = {"exit": result.returncode}
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            reply = json.loads(line)
            if reply.get("id") != 1:
                continue
            structured = reply.get("result", {}).get("structuredContent", {})
            observation.update(
                session=structured.get("session", {}).get("id"),
                agent=structured.get("agent", {}).get("id"),
            )
    save(root / "consumer.json", observation)


def acp(root, se, home):
    # Mirror the repository's ACP session fixture: initialize, open and
    # complete a turn over the real transport before invoking the child CLI.
    worker = threading.Thread(target=consumer, args=(root, se, home), daemon=True)
    worker.start()
    for line in sys.stdin:
        request = json.loads(line)
        if "id" not in request:
            continue
        method = request["method"]
        if method == "initialize":
            reply = {"protocolVersion": 1, "agentCapabilities": {
                "loadSession": True, "mcpCapabilities": {"http": True},
            }}
        elif method == "session/new":
            (server,) = request["params"]["mcpServers"]
            headers = {header["name"]: header["value"] for header in server["headers"]}
            proof = any(header["name"].lower() == "x-stateengine-session-proof"
                        and header.get("value", "").startswith("sec1.")
                        for server in request["params"]["mcpServers"] for header in server["headers"])
            call = urllib.request.Request(
                server["url"], data=discovery_request(),
                headers={**headers, "Content-Type": "application/json"},
            )
            with urllib.request.urlopen(call, timeout=10) as response:
                http = response.status == 200 and prepared_reply(response.read())
            save(root / "acp-pipe.json", {
                "session_proof_seen": proof, "http": http, "ipc": prepared_session(se, home),
            })
            reply = {"sessionId": "fixture-conversation"}
        elif method == "session/prompt":
            reply = {"stopReason": "end_turn"}
        else:
            print(json.dumps({"jsonrpc": "2.0", "id": request["id"],
                              "error": {"code": -32601, "message": "unsupported fixture method"}}), flush=True)
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": reply}), flush=True)


def windows_codex(root, recovery):
    thread = str(uuid.uuid4())
    rollout = Path(os.environ["CODEX_HOME"]) / "sessions" / f"rollout-{thread}.jsonl"
    policy = None
    for line in sys.stdin:
        request = json.loads(line)
        if "id" not in request:
            continue
        method, params = request["method"], request.get("params", {})
        if method == "initialize":
            reply = {"userAgent": "independent-launch-double"}
        elif method == "windowsSandbox/readiness":
            reply = {"status": "ready"}
        elif method == "thread/start":
            recovery.discover(params)
            rollout.parent.mkdir(parents=True, exist_ok=True)
            rollout.write_text(json.dumps({"type": "session_meta",
                               "payload": {"id": thread, "cwd": params["cwd"]}}) + "\n")
            config = params["config"]
            workspace = config["sandbox_workspace_write"]
            sandbox = {"type": "workspaceWrite", "networkAccess": workspace["network_access"],
                       "writableRoots": [path for path in workspace["writable_roots"] if path != params["cwd"]],
                       "excludeTmpdirEnvVar": True, "excludeSlashTmp": True}
            policy = {"approvalPolicy": params["approvalPolicy"], "sandbox": sandbox, "cwd": params["cwd"]}
            reply = {"thread": {"id": thread, "path": str(rollout)}, **policy}
        elif method == "thread/read":
            reply = {"thread": {"id": thread, "path": str(rollout), "turns": [], "status": {"type": "idle"}}}
        elif method == "turn/start":
            reply = {"turn": {"id": "fixture-turn", "status": "inProgress"}}
        else:
            print(json.dumps({"id": request["id"], "error": {
                "code": -32601, "message": "unsupported fixture method",
            }}), flush=True)
            continue
        print(json.dumps({"id": request["id"], "result": reply}), flush=True)


def codex(root, se, home):
    import codex_recovery_provider as recovery
    discover = recovery.discover
    def inspect(params):
        config = params["config"]
        save(root / "hooks.json", {"configured": bool(config.get("hooks"))
                                 and config.get("features.hooks") is True})
        discover(params)
        assert prepared_session(se, home), "prepared session discovery failed"
    recovery.discover = inspect
    if os.name == "nt":
        windows_codex(root, recovery)
    else:
        sys.argv = [sys.argv[0], *sys.argv[5:]]
        recovery.main()


if __name__ == "__main__":
    mode, directory, se, home = sys.argv[1:5]
    root = Path(directory)
    observe_environment(root)
    if mode == "acp":
        acp(root, se, home)
    else:
        codex(root, se, home)
