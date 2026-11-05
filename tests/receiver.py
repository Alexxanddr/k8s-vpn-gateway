#!/usr/bin/env python3
"""Optional controlled public lab receiver. TCP and UDP use the same port."""
import argparse
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class HTTP(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = f"ip={self.client_address[0]}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        if len(data) == 32:
            # The fixed response is no larger than the request.
            response = self.client_address[0].encode().ljust(16) + data[:16]
            sock.sendto(response, self.client_address)
            print(f"UDP source {self.client_address[0]}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    endpoint = (args.bind, args.port)
    with socketserver.UDPServer(endpoint, UDP) as udp, ThreadingHTTPServer(endpoint, HTTP) as http:
        threading.Thread(target=udp.serve_forever, daemon=True).start()
        http.serve_forever()
