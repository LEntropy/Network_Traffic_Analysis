#!/usr/bin/env python3
"""HTTP/1.1 test target for the demo UI. Listens on 127.0.0.1:8080 inside the container.

Endpoints
  GET  /                  small HTML page
  GET  /big?kb=N          N KiB plain-text body (max 1024), spans many TCP segments
  GET  /chunked?n=K       response sent with Transfer-Encoding: chunked, K chunks
  GET  /status/CODE       empty response with that status code
  GET  /upgrade           101 Switching Protocols, then the connection closes
  ANY  /echo              echoes method, headers and body length as JSON
  HEAD any of the above   headers only
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive, so pipelined requests share a connection
    server_version = "netaudit-target/1.0"

    def log_message(self, *args):
        pass

    def _read_body(self):
        te = self.headers.get("Transfer-Encoding", "")
        if "chunked" in te.lower():
            total = b""
            while True:
                size_line = self.rfile.readline(1024)
                if not size_line:
                    break
                size = int(size_line.split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline(1024) not in (b"\r\n", b"\n", b""):
                        pass
                    break
                total += self.rfile.read(size)
                self.rfile.readline(1024)
            return total
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(length) if length > 0 else b""

    def _send(self, status, body=b"", content_type="text/plain; charset=utf-8", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _handle(self):
        url = urlsplit(self.path)
        query = parse_qs(url.query)
        body = self._read_body()

        if url.path == "/":
            page = b"<!doctype html><title>target</title><h1>netaudit test target</h1>"
            return self._send(200, page, "text/html; charset=utf-8")

        if url.path == "/big":
            kb = max(1, min(1024, int(query.get("kb", ["64"])[0])))
            line = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_\n"
            data = (line * (kb * 1024 // len(line) + 1))[: kb * 1024]
            return self._send(200, data)

        if url.path == "/chunked":
            n = max(1, min(50, int(query.get("n", ["5"])[0])))
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            if self.command != "HEAD":
                for i in range(n):
                    chunk = f"chunk {i + 1} of {n}\n".encode()
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
            return None

        if url.path.startswith("/status/"):
            try:
                code = int(url.path.split("/")[2])
            except ValueError:
                code = 400
            code = code if 200 <= code <= 599 else 400
            return self._send(code)

        if url.path == "/upgrade":
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.end_headers()
            self.close_connection = True
            return None

        if url.path == "/echo":
            info = {
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers.items()),
                "body_bytes": len(body),
            }
            return self._send(200, json.dumps(info, indent=2).encode(), "application/json")

        return self._send(404, b"not found\n")

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = _handle


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
