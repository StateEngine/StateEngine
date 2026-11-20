"""An authenticated loopback Responses API for the stock Codex PR judge."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Lock, Thread


KEY = "synthetic-stock-codex-ci-key"
MODEL = "gpt-5.5"
TASK = "Reply with Ready. Do not use tools."


class LoopbackModel:
    def __init__(self):
        self.accepted = self.rejected = 0
        self.lock = Lock()
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                length = self.headers.get("Content-Length", "")
                size = int(length) if length.isascii() and length.isdecimal() and len(length) <= 7 else 0
                if (self.path != "/v1/responses" or self.headers.get("Authorization") != f"Bearer {KEY}"
                        or not 0 < size <= 2**20 or TASK.encode() not in self.rfile.read(size)):
                    with fixture.lock:
                        fixture.rejected += 1
                    self.send_error(403)
                    return
                with fixture.lock:
                    fixture.accepted += 1
                    response_id = f"fixture-{fixture.accepted}"
                events = [
                    {"type": "response.created", "response": {"id": response_id}},
                    {"type": "response.output_item.done", "item": {
                        "type": "message", "role": "assistant", "id": f"{response_id}-message",
                        "content": [{"type": "output_text", "text": "Ready"}],
                    }},
                    {"type": "response.completed", "response": {"id": response_id, "usage": {
                        "input_tokens": 5, "input_tokens_details": None,
                        "output_tokens": 2, "output_tokens_details": None, "total_tokens": 7,
                    }}},
                ]
                body = "".join(f"data: {json.dumps(event)}\n\n" for event in events).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.url = f"http://127.0.0.1:{self.server.server_port}/v1"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
