#!/usr/bin/env python3
"""Deterministic local Anthropic Messages endpoint for the B7 idle measurement.

Hosted runners carry no fleet provider credentials, so the one-session trial
runs a real Claude Code session (real CLI process, real harness binding, real
capture and mail) whose single setup turn is answered by this endpoint. The
model's identity is irrelevant to the host idle budget: the measured cost is
the host's own CPU and wakeup rate while a live session sits idle.

Usage: python3 mock_anthropic.py --port PORT --log FILE
Serves POST /v1/messages (streaming SSE or plain JSON, echoing the requested
model) and answers every other path with a JSON 404. Every request is logged
as one JSON line (method, path, model, stream flag, content-length).
"""
import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPLY = "ok"


class Handler(BaseHTTPRequestHandler):
    server_version = "b7-mock-anthropic/1"
    request_log = None

    def log_message(self, format, *values):
        pass

    def _record(self, method, path, body):
        entry = {"ts": round(time.time(), 3), "method": method, "path": path}
        if body:
            try:
                document = json.loads(body)
                entry.update({
                    "model": document.get("model"),
                    "stream": document.get("stream"),
                    "max_tokens": document.get("max_tokens"),
                })
            except ValueError:
                entry["body_bytes"] = len(body)
        with open(self.server.log_path, "a") as stream:
            stream.write(json.dumps(entry) + "\n")

    def _send(self, code, content_type, payload):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._record("GET", self.path, None)
        if self.path in ("/", "/health"):
            self._send(200, "text/plain", b"ok\n")
        else:
            self._send(404, "application/json",
                       json.dumps({"type": "error", "error": {
                           "type": "not_found_error",
                           "message": f"unknown path {self.path}"}}).encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self._record("POST", self.path, body)
        if self.path != "/v1/messages":
            self._send(404, "application/json",
                       json.dumps({"type": "error", "error": {
                           "type": "not_found_error",
                           "message": f"unknown path {self.path}"}}).encode())
            return
        try:
            document = json.loads(body or b"{}")
        except ValueError:
            self._send(400, "application/json",
                       json.dumps({"type": "error", "error": {
                           "type": "invalid_request_error",
                           "message": "body is not JSON"}}).encode())
            return
        model = document.get("model") or "b7-deterministic"
        message_id = "msg_b7_" + format(int(time.time() * 1000), "x")
        if document.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            events = [
                {"type": "message_start", "message": {
                    "id": message_id, "type": "message", "role": "assistant",
                    "model": model, "content": [], "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 12, "output_tokens": 1}}},
                {"type": "content_block_start", "index": 0,
                 "content_block": {"type": "text", "text": ""}},
                {"type": "ping"},
                {"type": "content_block_delta", "index": 0,
                 "delta": {"type": "text_delta", "text": REPLY}},
                {"type": "content_block_stop", "index": 0},
                {"type": "message_delta",
                 "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                 "usage": {"output_tokens": 1}},
                {"type": "message_stop"},
            ]
            for event in events:
                self.wfile.write(f"event: {event['type']}\n".encode())
                self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
                self.wfile.flush()
        else:
            self._send(200, "application/json", json.dumps({
                "id": message_id, "type": "message", "role": "assistant",
                "model": model, "content": [{"type": "text", "text": REPLY}],
                "stop_reason": "end_turn", "stop_sequence": None,
                "usage": {"input_tokens": 12, "output_tokens": 1},
            }).encode())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--log", required=True)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.log_path = args.log
    with open(args.log, "a"):
        pass
    print(f"mock anthropic listening on 127.0.0.1:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
