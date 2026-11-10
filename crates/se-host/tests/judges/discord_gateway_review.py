"""Independent local TLS, Gateway and REST fixture; every credential is synthetic.

The real adapter validates the generated certificate and performs an HTTP upgrade.
Dispatch replay starts after the durable sequence supplied by the client, never
after the highest item this fixture happened to send. No live service is contacted.
"""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import ssl
import struct
import threading
import time

TOKEN = "synthetic-discord-token-for-local-tests-only"


class Provider:
    def __init__(self, root, mode):
        self.root, self.mode = root, mode
        self.lock = threading.Lock()
        self.events, self.sockets = [], []
        self.buffers = {}
        self.connections = 0
        self.channel_reads = 0
        self.posts = 0
        self.session = None

    def record(self, **event):
        with self.lock:
            self.events.append(event)
            temporary = self.root / "events.new"
            temporary.write_text(json.dumps(self.events))
            temporary.replace(self.root / "events.json")

    @staticmethod
    def exact(stream, count):
        data = b""
        while len(data) < count:
            piece = stream.recv(count - len(data))
            if not piece:
                raise EOFError("peer closed")
            data += piece
        return data

    def read_frame(self, stream):
        buffer = self.buffers.setdefault(stream, bytearray())
        while True:
            if len(buffer) >= 2:
                first, second = buffer[:2]
                assert first & 0x80 and second & 0x80, "client frames must be final and masked"
                length, offset = second & 0x7f, 2
                extension = 2 if length == 126 else 8 if length == 127 else 0
                if len(buffer) >= 2 + extension:
                    if extension:
                        length = int.from_bytes(buffer[2:2 + extension], "big")
                        offset += extension
                    assert length <= 256 * 1024
                    if len(buffer) >= offset + 4 + length:
                        mask = buffer[offset:offset + 4]
                        data = bytes(value ^ mask[index % 4] for index, value in
                                     enumerate(buffer[offset + 4:offset + 4 + length]))
                        del buffer[:offset + 4 + length]
                        return first & 15, data
            piece = stream.recv(65536)
            if not piece:
                raise EOFError("peer closed")
            buffer.extend(piece)

    @staticmethod
    def frame(stream, data, opcode=1):
        if isinstance(data, dict):
            data = json.dumps(data).encode()
        size = len(data)
        header = bytes([0x80 | opcode])
        if size < 126:
            header += bytes([size])
        elif size < 65536:
            header += b"\x7e" + struct.pack("!H", size)
        else:
            header += b"\x7f" + struct.pack("!Q", size)
        stream.sendall(header + data)

    @staticmethod
    def message(seq, **changes):
        value = {"id": str(5000 + seq), "channel_id": "2001", "type": 0,
                 "author": {"id": "1001", "username": "fixture-human", "discriminator": "0", "avatar": None, "bot": False},
                 "content": "work-" + str(seq), "attachments": [], "embeds": [],
                 "components": [], "sticker_items": [], "timestamp": "2026-01-01T00:00:00+00:00",
                 "edited_timestamp": None, "tts": False, "mention_everyone": False,
                 "mentions": [], "mention_roles": [], "pinned": False}
        value.update(changes)
        return {"op": 0, "s": seq, "t": "MESSAGE_CREATE", "d": value}

    def dispatches(self):
        if self.mode == "pairing":
            pairing = json.loads((self.root / "incoming.json").read_text())["pairing"]
            return [self.message(2, content=pairing), self.message(3, content="durable-local-work")]
        if self.mode == "normalize":
            return [self.message(2),
                    self.message(3, guild_id="4001"),
                    self.message(4, author={"id": "1001", "username": "bot", "bot": True}),
                    self.message(5, webhook_id="6001"),
                    self.message(6, channel_id="3001"),
                    self.message(7, channel_id="2002"),
                    self.message(8, attachments=[{"id": "7001", "filename": "file.txt"}]),
                    self.message(9, type=19, content="human reply")]
        count = 32 if self.mode == "burst" else 2 if self.mode == "resume" else 1
        return [self.message(seq) for seq in range(2, count + 2)]

    def gateway(self, handler):
        key = handler.headers.get("Sec-WebSocket-Key", "")
        assert handler.headers.get("Sec-WebSocket-Version") == "13"
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        handler.send_response(101)
        handler.send_header("Upgrade", "websocket")
        handler.send_header("Connection", "Upgrade")
        handler.send_header("Sec-WebSocket-Accept", accept)
        handler.end_headers()
        handler.wfile.flush()
        stream = handler.connection
        self.sockets.append(stream)
        self.frame(stream, {"op": 10, "d": {"heartbeat_interval": 200}})
        opcode, raw = self.read_frame(stream)
        assert opcode == 1
        auth = json.loads(raw)
        assert auth["d"]["token"] == TOKEN
        self.connections += 1
        self.record(kind="gateway_auth", op=auth["op"], seq=auth["d"].get("seq"),
                    session=auth["d"].get("session_id"), intents=auth["d"].get("intents"))
        if auth["op"] == 2:
            assert auth["d"]["intents"] == 4096
            self.session = "synthetic-session-" + str(self.connections)
            self.frame(stream, {"op": 0, "s": 1, "t": "READY",
                               "d": {"session_id": self.session, "v": 10,
                                     "user": {"id": "9001", "username": "fixture-bot", "bot": True},
                                     "guilds": [], "application": {"id": "9001", "flags": 0},
                                     "resume_gateway_url": "wss://gateway.discord.gg/"}})
            start = 1
        else:
            assert auth["op"] == 6 and auth["d"]["session_id"] == self.session
            start = auth["d"]["seq"]
        if self.mode == "expired" and auth["op"] == 6:
            self.frame(stream, struct.pack("!H", 4009), 8)
            self.record(kind="replay_expired")
            return
        dispatches = self.dispatches()
        pending = iter(item for item in dispatches if item["s"] > start)
        resumed = auth["op"] == 6
        resumed_sequence = max([start] + [item["s"] for item in dispatches]) + 1
        # Fresh burst fills the bounded client queue. Replays are paced so the
        # client can durably dispose each row before receiving the next one.
        if self.mode == "burst" and auth["op"] == 2:
            for item in pending:
                self.frame(stream, item)
            pending = iter(())
        stream.settimeout(0.02)
        next_message = time.monotonic() + (0.15 if self.mode == "burst" else 0.01)
        waiting = None
        while not (self.root / "stop").exists():
            if time.monotonic() >= next_message:
                if waiting is None:
                    waiting = next(pending, None)
                if waiting and not (self.mode == "pairing" and waiting["s"] == 3
                                    and not (self.root / "approved").exists()):
                    self.frame(stream, waiting)
                    self.record(kind="dispatch", seq=waiting["s"])
                    waiting = None
                elif waiting is None and resumed:
                    self.frame(stream, {"op": 0, "s": resumed_sequence, "t": "RESUMED", "d": {}})
                    self.record(kind="dispatch", seq=resumed_sequence)
                    resumed = False
                next_message = time.monotonic() + (0.1 if self.mode == "burst" else 0.01)
            try:
                opcode, raw = self.read_frame(stream)
            except socket.timeout:
                continue
            except (EOFError, OSError):
                return
            if opcode == 8:
                return
            if opcode == 9:
                self.frame(stream, raw, 10)
            elif opcode == 1:
                value = json.loads(raw)
                assert value["op"] == 1
                self.record(kind="heartbeat", seq=value.get("d"))
                self.frame(stream, {"op": 11})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--mode", required=True)
    args = parser.parse_args()
    provider = Provider(args.root, args.mode)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def json_reply(self, code, value, **headers):
            data = json.dumps(value).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            try:
                self.wfile.write(data)
            except (OSError, ssl.SSLError):
                pass

        def do_GET(self):
            if self.headers.get("Upgrade", "").lower() == "websocket":
                try:
                    provider.gateway(self)
                except (OSError, EOFError):
                    pass
                except Exception as error:
                    provider.record(kind="fixture_error", error=type(error).__name__)
                self.close_connection = True
                return
            assert self.headers.get("Authorization") == "Bot " + TOKEN
            route = self.path.removeprefix("/api/v10")
            provider.record(kind="get", route=route)
            if route == "/users/@me":
                self.json_reply(200, {"id": "9001", "username": "fixture-bot", "discriminator": "0", "avatar": None, "bot": True})
            elif route == "/gateway/bot":
                self.json_reply(200, {"url": "wss://gateway.discord.gg/", "shards": 1,
                    "session_start_limit": {"total": 100, "remaining": 99,
                                            "reset_after": 60000, "max_concurrency": 1}})
            elif route.startswith("/channels/"):
                provider.channel_reads += 1
                if args.mode == "cancel":
                    time.sleep(0.7)
                channel = route.rsplit("/", 1)[1]
                recipients = [{"id": "1002" if channel == "2002" else "1001", "bot": False}]
                if channel == "3001":
                    recipients.append({"id": "1002", "bot": False})
                self.json_reply(200, {"id": channel, "type": 3 if channel == "3001" else 1,
                                      "recipients": recipients})
            else:
                self.json_reply(404, {"message": "fixture route absent"})

        def do_POST(self):
            assert self.headers.get("Authorization") == "Bot " + TOKEN
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            provider.posts += 1
            provider.record(kind="post", route=self.path, body=body)
            text = body["content"]
            if text == "RATE":
                self.json_reply(429, {"retry_after": 1.25, "global": False})
            elif text == "UNKNOWN":
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
            elif text == "REDIRECT":
                self.json_reply(307, {}, Location="https://discord.com/api/v10/unexpected")
            else:
                message = Provider.message(8000 + provider.posts)["d"]
                message.update(id=str(8000 + provider.posts), content=text,
                               author={"id": "9001", "username": "fixture-bot", "bot": True})
                self.json_reply(200, message)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.root / "certificate.pem", args.root / "key.pem")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.timeout = 0.1
    ready = args.root / "ready.new"
    ready.write_text(json.dumps({"port": server.server_port}))
    ready.replace(args.root / "ready.json")
    try:
        while not (args.root / "stop").exists():
            server.handle_request()
    finally:
        for stream in provider.sockets:
            try:
                stream.shutdown(socket.SHUT_RDWR)
                stream.close()
            except OSError:
                pass
        server.server_close()


if __name__ == "__main__":
    main()
