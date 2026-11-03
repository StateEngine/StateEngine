#!/usr/bin/env python3
"""Run a real linked SE Code task; leave public records for an independent reader.

Supply a pre-initialized isolated StateEngine home/project/agent and repository.
The new root retains the native profile, raw responses and witness.json. The
deterministic local-script model executes real write/read tools; no model account
or constructed CapturedTurn is used. Read-only SQL locates event IDs only: text,
length, digest and conversation evidence comes from the public history command.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

MAX_RESPONSE = 2 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def run(root, name, argv, env, cwd):
    completed = subprocess.run(argv, env=env, cwd=cwd, capture_output=True, timeout=45)
    (root / (name + ".stdout")).write_bytes(completed.stdout)
    (root / (name + ".stderr")).write_bytes(completed.stderr)
    save(root / (name + ".command.json"), {"argv": argv, "exit": completed.returncode})
    require(completed.returncode == 0, f"{name} exited {completed.returncode}; see retained output")
    return json.loads(completed.stdout)


def metadata(home, project, agent, after):
    # This is identifier discovery, never a substitute for public event reads.
    with sqlite3.connect((home / "state.db").as_uri() + "?mode=ro", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        if after is None:
            return db.execute("SELECT coalesce(max(seq),0) FROM events").fetchone()[0]
        rows = db.execute(
            "SELECT e.event_id,t.role,t.vendor_ref FROM events e "
            "JOIN turn_data t ON t.event_seq=e.seq "
            "WHERE e.project_id=? AND t.agent_id=? AND e.seq>? ORDER BY e.seq LIMIT 129",
            (uuid.UUID(project.split("_", 1)[1]).bytes,
             uuid.UUID(agent.split("_", 1)[1]).bytes, after),
        ).fetchall()
        return [{"event_id": "ev_" + str(uuid.UUID(bytes=row[0])),
                 "role": row[1], "native_event": row[2]} for row in rows]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("secode-server", "se", "root", "state-home", "repo"):
        parser.add_argument("--" + flag, type=Path, required=True)
    for flag in ("project", "agent", "nonce"):
        parser.add_argument("--" + flag, required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", args.nonce), "nonce must be 1..64 ASCII identifier characters")
    for path in (args.secode_server, args.se, args.root, args.state_home, args.repo):
        require(path.is_absolute(), "all paths must be absolute")
    require((args.state_home / "state.db").is_file(), "initialize the isolated StateEngine home first")
    require(args.repo.is_dir(), "the registered repository must exist")
    require(not args.root.exists(), "the witness root must be new; retained results are never overwritten")
    args.root.mkdir(mode=0o700)
    root, profile = args.root, args.root / "profile"
    package = root / "package"
    (package / "stateengine").mkdir(parents=True)
    server, helper = package / args.secode_server.name, package / "stateengine" / args.se.name
    shutil.copy2(args.secode_server, server)
    shutil.copy2(args.se, helper)
    # A fresh test profile carries no factory credential or inherited seat pin.
    # Keep the real OS account and normal native runtime directory unchanged.
    env = {key: os.environ[key] for key in
           ("PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "XDG_RUNTIME_DIR", "SYSTEMROOT", "WINDIR", "LOCALAPPDATA")
           if key in os.environ}
    env["SE_HOME"] = str(args.state_home)
    branch = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[2], text=True).strip()
    save(root / "inputs.json", {"branch_tip": branch, "nonce": args.nonce,
         "state_home": str(args.state_home), "repository": str(args.repo),
         "project": args.project, "agent": args.agent,
         "server_sha256": hashlib.sha256(server.read_bytes()).hexdigest(),
         "se_sha256": hashlib.sha256(helper.read_bytes()).hexdigest()})
    run(root, "profile-init", [str(server), "init-local", "--service", str(profile)], env, args.repo)
    effect = args.repo / ("w3-native-" + args.nonce + ".txt")
    require(not effect.exists(), "the nonce-specific task file already exists")
    text = f"W3 native task {args.nonce}: π and café\n"
    task = f"Write {effect.name} containing the exact requested nonce {args.nonce} (π, café), then read it back."
    save(profile / "local-plan.json", {"calls": [
        {"tool": "write", "arguments": {"path": str(effect), "content": text}},
        {"tool": "read", "arguments": {"path": str(effect)}},
    ]})
    config = profile / "service.conf"
    config.write_text(config.read_text().replace("serve_window_ms=3600000", "serve_window_ms=60000"))
    before = metadata(args.state_home, args.project, args.agent, None)
    deadline = time.monotonic() + 50
    child = None
    witness = None
    failure = None
    with (root / "server.stdout").open("wb") as stdout, (root / "server.stderr").open("wb") as stderr:
        try:
            argv = [str(server), "serve", "--service", str(profile), "--port", "0"]
            child = subprocess.Popen(argv, env=env, cwd=args.repo, stdout=stdout, stderr=stderr)
            save(root / "process.json", {"pid": child.pid, "argv": argv})
            ready_path = profile / "serve-ready.json"
            while not ready_path.exists():
                require(child.poll() is None, "native server exited before readiness; see server output")
                require(time.monotonic() < deadline, "native server readiness timed out")
                time.sleep(0.1)
            ready = json.loads(ready_path.read_bytes())
            require(ready["pid"] == child.pid, "ready receipt names a different process")
            endpoint = ready["observed_endpoint"]
            require(re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", endpoint), "native endpoint is not loopback")
            save(root / "ready.json", ready)
            authentication = "Basic " + base64.b64encode((profile / "basic.credential").read_bytes()).decode()
            count = 0

            def request(method, path, body=None):
                nonlocal count
                require(time.monotonic() < deadline, "native task deadline exhausted")
                count += 1
                headers = {"Authorization": authentication}
                if body is not None:
                    headers["Content-Type"] = "application/json"
                req = urllib.request.Request(endpoint + path, method=method, headers=headers,
                    data=None if body is None else json.dumps(body, ensure_ascii=False).encode())
                try:
                    with urllib.request.urlopen(req, timeout=min(10, deadline - time.monotonic())) as response:
                        raw = response.read(MAX_RESPONSE + 1)
                        status = response.status
                except urllib.error.HTTPError as error:
                    raw, status = error.read(MAX_RESPONSE + 1), error.code
                require(len(raw) <= MAX_RESPONSE, "native response exceeds 2 MiB")
                value = json.loads(raw) if raw else None
                save(root / f"http-{count:03d}.json", {"method": method, "path": path, "request": body,
                     "status": status, "response": value})
                require(200 <= status < 300, f"native {method} {path} refused with HTTP {status}")
                return value

            created = request("POST", "/api/session", {"location": {"directory": str(args.repo)}})
            conversation = created["data"]["id"]
            require(isinstance(conversation, str) and conversation.startswith("ses_"), "native session identity absent")
            session = "/api/session/" + conversation
            binding = {"project_id": args.project, "agent_id": args.agent, "capture_consent": True, "scope": "project"}
            request("PUT", session + "/instructions/entries/stateengine-identity", {"value": binding})
            message_id = "msg_w3_" + hashlib.sha256(args.nonce.encode()).hexdigest()[:32]
            ack = request("POST", session + "/prompt", {"id": message_id, "text": task})
            require(ack["data"]["sessionID"] == conversation and "queued" not in ack, "task was not admitted for this session")
            history = None
            while True:
                history = request("GET", session + "/message")
                messages = history["data"]
                require(isinstance(messages, list), "native history is not a message list")
                require(not any(m.get("error") or m.get("finish") == "error" for m in messages), "native task failed")
                finals = [m for m in messages if m.get("type") == "assistant" and m.get("finish") == "stop"]
                if finals:
                    break
                time.sleep(0.15)
            save(root / "native-history.json", history)
            require(len(finals) == 1, "native task produced an unexpected number of final answers")
            require([m.get("text") for m in messages if m.get("type") == "user"] == [task],
                    "native public history differs from the exact submitted task")
            require(effect.read_text() == text, "native tool file effect differs from the nonce task")
            tools = [item for message in messages for item in message.get("content", []) if item.get("type") == "tool"]
            require([item["name"] for item in tools] == ["write", "read"], "native task did not execute both expected tools")
            require(all(item["state"]["status"] == "completed" for item in tools), "a native tool did not complete")
            while True:
                records = metadata(args.state_home, args.project, args.agent, before)
                require(len(records) <= 2, "unexpected additional captured turns in the isolated task boundary")
                if len(records) == 2:
                    break
                require(time.monotonic() < deadline, "native task did not publish both capture records")
                time.sleep(0.1)
            require({record["role"] for record in records} == {"user", "assistant"},
                    "native capture did not retain exactly the user and assistant roles")
            expected = {"user": task, "assistant": "".join(item["text"] for item in finals[0]["content"] if item["type"] == "text")}
            for record in records:
                role = record["role"]
                require(role in expected, "unexpected captured role")
                public = run(root, "history-" + role, [str(helper), "--home", str(args.state_home),
                    "--project", args.project, "history", "--event", record["event_id"], "--json"], env, args.repo)
                payload, body = public["payload"], public["payload"]["body"]
                require(public["event_id"] == record["event_id"] and public["kind"] == "session.turn", "wrong public event")
                require(payload["provider_session"] == conversation and payload["role"] == role, "capture is misbound")
                raw_text = expected[role].encode()
                require(body["text"] == expected[role] and body["bytes"] == len(raw_text) and body["complete"] is True,
                        "public capture text, completeness or UTF-8 byte count differs")
                require(body["sha256"] == hashlib.sha256(raw_text).hexdigest(), "public capture digest differs")
                record["public_argv"] = [str(helper), "--home", str(args.state_home), "--project", args.project,
                                         "history", "--event", record["event_id"], "--json"]
            witness = {"outcome": "captured", "branch_tip": branch, "nonce": args.nonce,
                "conversation": conversation, "task_message_id": message_id,
                "task_text": task, "expected_text": expected,
                "public_history": records, "native_history_path": session + "/message",
                "native_profile": str(profile), "state_home": str(args.state_home),
                "repository": str(args.repo), "project": args.project, "agent": args.agent,
                "file_effect": {"path": str(effect), "text": text}, "ready_endpoint": endpoint,
                "reopen_native_argv": argv, "reopen_environment": {"SE_HOME": str(args.state_home)},
                "basic_credential_path": str(profile / "basic.credential")}
        except Exception as error:
            failure = str(error)
        finally:
            if child is not None:
                # The fixture's ordinary finite serve window settles its own
                # task/host resources. Never kill another runtime or fake close.
                code = child.wait(timeout=100)
                save(root / "exit.json", {"pid": child.pid, "exit": code,
                     "ready_retired": not (profile / "serve-ready.json").exists()})
                if code != 0:
                    failure = f"native server exited {code}; prior failure: {failure}"
    if failure:
        save(root / "failure.json", {"outcome": "failed", "reason": failure})
        raise RuntimeError(failure)
    require(witness is not None, "task witness was not produced")
    save(root / "witness.json", witness)
    print(json.dumps(witness, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"native task witness failed: {error}", file=sys.stderr)
        sys.exit(1)
