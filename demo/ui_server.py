#!/usr/bin/env python3
"""Backend for the demo UI.

Serves the web page, sends the user's raw HTTP bytes to the test target over a real TCP
connection (optionally cut into small segments), and streams the events that
netaudit-agent writes while capturing that traffic on the loopback interface.

The target address is fixed to 127.0.0.1:8080 inside the container on purpose: the UI
can only ever talk to the bundled test server.
"""

import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TARGET = ("127.0.0.1", 8080)
STATIC = Path(__file__).parent / "static"
EVENTS_FILE = Path(os.environ.get("EVENTS_FILE", "/tmp/events.jsonl"))
AGENT_PID = int(os.environ.get("AGENT_PID", "0"))

MAX_REQUEST_BYTES = 256 * 1024
MAX_SEGMENTS = 4000
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
SHOWN_RESPONSE_BYTES = 16 * 1024


class EventLog:
    """Follows the agent's JSON Lines output file."""

    def __init__(self, path):
        self.path = path
        self.offset = 0
        self.partial = b""
        self.events = []
        self.lock = threading.Lock()

    def refresh(self):
        with self.lock:
            if not self.path.exists():
                return
            with self.path.open("rb") as f:
                f.seek(self.offset)
                data = f.read()
            self.offset += len(data)
            data = self.partial + data
            lines = data.split(b"\n")
            self.partial = lines.pop()  # incomplete last line, if any
            for line in lines:
                if line.strip():
                    try:
                        self.events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    def since(self, index):
        self.refresh()
        with self.lock:
            return self.events[index:index + 500], len(self.events)


EVENTS = EventLog(EVENTS_FILE)


def agent_running():
    if AGENT_PID <= 0:
        return False
    try:
        os.kill(AGENT_PID, 0)
        return True
    except OSError:
        return False


def send_raw(raw, segment_size, delay_ms):
    if segment_size > 0:
        segments = [raw[i:i + segment_size] for i in range(0, len(raw), segment_size)]
    else:
        segments = [raw]
    if len(segments) > MAX_SEGMENTS:
        raise ValueError(f"too many segments ({len(segments)}); use a larger segment size")
    # Without a pause the kernel may merge small writes back into one segment.
    if segment_size > 0 and delay_ms <= 0:
        delay_ms = 3

    started = time.monotonic()
    sock = socket.create_connection(TARGET, timeout=5)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        client_port = sock.getsockname()[1]
        for i, seg in enumerate(segments):
            sock.sendall(seg)
            if delay_ms > 0 and i + 1 < len(segments):
                time.sleep(delay_ms / 1000)
        # Half-close: the server answers everything it received, then closes.
        sock.shutdown(socket.SHUT_WR)

        response = b""
        timed_out = False
        while len(response) < MAX_RESPONSE_BYTES:
            try:
                data = sock.recv(65536)
            except socket.timeout:
                timed_out = True
                break
            if not data:
                break
            response += data
    finally:
        sock.close()

    return {
        "client_port": client_port,
        "sent_bytes": len(raw),
        "segments": len(segments),
        "response_bytes": len(response),
        "header_bytes": response.find(b"\r\n\r\n") + 4 if b"\r\n\r\n" in response else -1,
        "response_text": response[:SHOWN_RESPONSE_BYTES].decode("utf-8", errors="replace"),
        "response_truncated": len(response) > SHOWN_RESPONSE_BYTES,
        "timed_out": timed_out,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = (STATIC / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/api/events"):
            try:
                after = int(self.path.split("after=")[1]) if "after=" in self.path else 0
            except ValueError:
                after = 0
            events, total = EVENTS.since(max(0, after))
            self._json(200, {"events": events, "next": total, "agent_running": agent_running()})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/api/send":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > MAX_REQUEST_BYTES * 2:
            self._json(400, {"error": "request too large or empty"})
            return
        try:
            req = json.loads(self.rfile.read(length))
            raw = req["raw"].encode("utf-8")
            if not raw or len(raw) > MAX_REQUEST_BYTES:
                raise ValueError("raw request must be 1 byte to 256 KiB")
            result = send_raw(raw, int(req.get("segment_size", 0)), int(req.get("delay_ms", 0)))
            self._json(200, result)
        except (KeyError, ValueError, TypeError) as e:
            self._json(400, {"error": str(e)})
        except OSError as e:
            self._json(502, {"error": f"cannot reach test server: {e}"})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print(f"demo UI on http://localhost:{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
