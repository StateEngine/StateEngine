#!/usr/bin/env python3
"""Protects: B9/G2 — real kept-open MCP writes, complete receipts, outside readback.

Run with --se INSTALLED_SE --home STATE_HOME; protected stdin supplies JSON
{"clients":[{"capability":"...","to":"owner"}, ... eight distinct sessions]}.
Creates private test messages and replaces those sessions' working notes. Use
dedicated journey sessions. Measures serial and eight-client message/working
writes only; provider hook capture and mixed FULL traffic remain separate runs.
"""
import argparse
import concurrent.futures
import hashlib
import json
import math
import os
import queue
import subprocess
import sys
import threading
import time
import uuid

LIMIT = 1_048_576
META = "stateengine.session-capability-v1"


class Rpc:
    def __init__(self, binary, home, capability):
        self.capability = capability
        self.serial = 0
        self.frames = queue.Queue(maxsize=4)
        self.errors = bytearray()
        self.error_bytes = 0
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("SE_", "STATEENGINE_", "SECODE_"))
               and k not in ("CLAUDECODE", "CODEX_THREAD_ID", "CODEX_CI")}
        started = time.perf_counter_ns()
        self.process = subprocess.Popen(
            [binary, "--home", home, "mcp", "--stdio"], env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        threading.Thread(target=self._read, daemon=True).start()
        self.stderr_thread = threading.Thread(target=self._stderr, daemon=True)
        self.stderr_thread.start()
        try:
            initialized, _ = self.call("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                      "clientInfo": {"name": "independent-write-judge", "version": "1"}})
            if not isinstance(initialized.get("protocolVersion"), str):
                raise ValueError("anonymous MCP initialize did not negotiate a version")
            self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            listing, _ = self.call("tools/list", {"_meta": {META: capability}})
            names = {tool["name"] for tool in listing["tools"]}
            required = {"stateengine_msg_send", "stateengine_working_state_set",
                        "stateengine_working_state_get", "stateengine_event_read", "stateengine_status"}
            if not required <= names:
                raise ValueError("required public tools missing from the session catalogue")
        except Exception as error:
            self.close()
            raise RuntimeError(f"{error}; stderr ({self.error_bytes} bytes): " +
                               bytes(self.errors).decode(errors="replace")) from error
        self.startup_auth_ms = (time.perf_counter_ns() - started) / 1e6

    def _read(self):
        try:
            while True:
                line = self.process.stdout.readline(LIMIT + 1)
                if not line:
                    raise EOFError("MCP stdout closed")
                if len(line) > LIMIT or not line.endswith(b"\n"):
                    raise ValueError("MCP frame exceeds the bounded newline contract")
                self.frames.put(json.loads(line))
        except Exception as error:
            self.frames.put(error)

    def _stderr(self):
        while True:
            block = self.process.stderr.read(4096)
            if not block:
                return
            self.error_bytes += len(block)
            self.errors.extend(block[:max(0, 65536 - len(self.errors))])

    def _send(self, frame):
        payload = json.dumps(frame, separators=(",", ":")).encode() + b"\n"
        if len(payload) > LIMIT:
            raise ValueError("outgoing MCP frame exceeds limit")
        self.process.stdin.write(payload)
        self.process.stdin.flush()

    def call(self, method, params):
        self.serial += 1
        identifier = self.serial
        started = time.perf_counter_ns()
        self._send({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params})
        deadline = time.monotonic() + 30
        while True:
            frame = self.frames.get(timeout=max(0, deadline - time.monotonic()))
            if isinstance(frame, Exception):
                raise frame
            if "id" not in frame:
                if time.monotonic() >= deadline:
                    raise TimeoutError("MCP receipt deadline expired")
                continue
            elapsed = (time.perf_counter_ns() - started) / 1e6
            if frame.get("jsonrpc") != "2.0" or frame["id"] != identifier:
                raise ValueError("MCP response identity mismatch")
            if "error" in frame:
                raise ValueError("MCP refusal: " + json.dumps(frame["error"]))
            return frame["result"], elapsed

    def tool(self, name, arguments):
        result, elapsed = self.call("tools/call", {"name": name, "arguments": arguments,
                                                   "_meta": {META: self.capability}})
        if result.get("isError"):
            raise ValueError("typed tool refusal: " + json.dumps(result))
        structured = result["structuredContent"]
        text = [part["text"] for part in result["content"] if part.get("type") == "text"]
        if len(text) != 1 or json.loads(text[0]) != structured or "schema" not in structured:
            raise ValueError("structured/text receipt mismatch or missing schema")
        return structured, elapsed

    def close(self):
        try:
            self.process.stdin.close()
        except BrokenPipeError:
            pass
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # This Popen is unreaped and owned here; its PID cannot have been reused.
            self.process.kill()
            self.process.wait(timeout=5)
            raise RuntimeError("owned MCP bridge failed to exit on EOF")
        finally:
            self.stderr_thread.join(timeout=5)
            if self.stderr_thread.is_alive():
                raise RuntimeError("owned MCP stderr did not reach EOF")


def run_client(binary, home, client, samples, barrier, report):
    rpc = None
    receipts = []
    generation = None
    try:
        rpc = Rpc(binary, home, client["capability"])
        report["startup_auth_ms"] = rpc.startup_auth_ms
        status, _ = rpc.tool("stateengine_status", {})
        if status["runtime"]["state"] != "running" or status["runtime"]["generation"] is None:
            raise ValueError("the B9 fixture has no measured running host")
        generation = str(status["runtime"]["generation"])
        working, _ = rpc.tool("stateengine_working_state_get", {})
        value = working["value"]
        if value["state"] == "present":
            revision = value["value"]["revision"]
        elif value["state"] == "absent":
            revision = "absent"
        else:
            raise ValueError("working-state read was unreadable/unknown")
        for name in ("stateengine_msg_send", "stateengine_working_state_set"):
            if barrier:
                barrier.wait(timeout=30)
            rows = report["samples"].setdefault(name, [])
            for _ in range(samples):
                key = "b9-" + uuid.uuid4().hex
                body = "independent kept-open write " + key
                arguments = ({"to": client["to"], "body": body, "idempotency_key": key}
                             if name == "stateengine_msg_send" else
                             {"text": body, "expect": revision, "idempotency_key": key})
                receipt, elapsed = rpc.tool(name, arguments)
                if receipt["state"] != "committed" or receipt["idempotency_key"] != key:
                    raise ValueError("timed write did not commit the requested new key")
                if receipt["writer"]["mode"] != "host" or not receipt["writer"].get("host_generation"):
                    raise ValueError("timed write has no actual host writer generation")
                observed_generation = receipt["writer"]["host_generation"]
                if generation is not None and observed_generation != generation:
                    raise ValueError("writer generation changed within the kept-open cohort")
                generation = observed_generation
                if name.endswith("working_state_set"):
                    next_revision = 1 if revision == "absent" else revision + 1
                    if receipt["revision"] != next_revision:
                        raise ValueError("working-state revision did not advance once")
                    revision = next_revision
                rows.append({"ms": elapsed, "event_id": receipt["event_id"], "key": key,
                             "writer": receipt["writer"]})
                receipts.append((name, arguments, receipt, hashlib.sha256(body.encode()).hexdigest()))
        # A separate bridge reads every immutable event outside the writing connection.
        reader = Rpc(binary, home, client["capability"])
        try:
            for name, arguments, receipt, digest in receipts:
                event, _ = reader.tool("stateengine_event_read", {"event_id": receipt["event_id"]})
                if event["event_id"] != receipt["event_id"] or event["writer"] != receipt["writer"]:
                    raise ValueError("outside event identity/writer mismatch")
                if event["payload"]["body"]["sha256"] != digest:
                    raise ValueError("outside committed body differs from the submitted bytes")
                if name.endswith("msg_send") and event["payload"]["message_id"] != receipt["message_id"]:
                    raise ValueError("outside message identity mismatch")
            report["verified_events"] = len(receipts)
        finally:
            reader.close()
        # Retry after later head changes: preserve the exact original receipt identity.
        for kind in ("stateengine_msg_send", "stateengine_working_state_set"):
            name, arguments, original, _ = next(row for row in receipts if row[0] == kind)
            replay, _ = rpc.tool(name, arguments)
            fields = ["schema", "idempotency_key", "event_id", "writer"]
            fields.append("message_id" if kind.endswith("msg_send") else "revision")
            if replay["state"] != "replayed":
                raise ValueError("original-key retry was not reported as replayed")
            for field in fields:
                if replay[field] != original[field]:
                    raise ValueError(f"{kind} replay changed original {field}")
            # current_revision may truthfully report the later working-state head.
    except Exception as error:
        report["error"] = str(error)
        if barrier:
            barrier.abort()
    finally:
        if rpc:
            try:
                rpc.close()
            except Exception as error:
                report["cleanup_error"] = str(error)
            report["stderr"] = bytes(rpc.errors).decode(errors="replace")
            report["stderr_bytes"] = rpc.error_bytes
            report["stderr_truncated"] = rpc.error_bytes > len(rpc.errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--se", required=True)
    parser.add_argument("--home", required=True)
    args = parser.parse_args()
    raw = sys.stdin.buffer.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("protected fixture input exceeds 1 MiB")
    clients = json.loads(raw)["clients"]
    if (len(clients) != 8 or any(not isinstance(c["capability"], str) or
                               not 1 <= len(c["capability"]) <= 1024 for c in clients)
            or len({c["capability"] for c in clients}) != 8):
        raise ValueError("supply eight distinct dedicated session capabilities")
    result = {"boundary": "request submission to complete receipt on an open MCP client",
              "limit_ms": 20, "samples_per_command_client": 30,
              "exemptions": ["provider hooks", "mixed FULL traffic", "one-shot CLI"], "cohorts": {}}
    for count in (1, 8):
        reports = [{"samples": {}} for _ in range(count)]
        barrier = threading.Barrier(count) if count > 1 else None
        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
            list(pool.map(lambda pair: run_client(args.se, args.home, pair[0], 30, barrier, pair[1]),
                          zip(clients[:count], reports)))
        for report in reports:
            report["p95_ms"] = {name: sorted(row["ms"] for row in rows)[math.ceil(len(rows) * .95) - 1]
                                for name, rows in report["samples"].items() if rows}
            report["pass"] = (not any(k.endswith("error") for k in report)
                              and report.get("verified_events") == 60
                              and len(report["p95_ms"]) == 2
                              and all(value <= 20 for value in report["p95_ms"].values()))
        result["cohorts"][str(count)] = reports
    result["pass"] = all(r["pass"] for rows in result["cohorts"].values() for r in rows)
    output = json.dumps(result, indent=2)
    for client in clients:
        output = output.replace(client["capability"], "<redacted-session-capability>")
    print(output)
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
