#!/usr/bin/env python3
"""
Traffic Receiver Server for Node-B
Listens for HTTP, SMTP, VoIP (UDP), Video (UDP), and Chat (UDP) traffic.
"""
import sys
import os
import time
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

class WebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/large.bin":
            payload = b"X" * (64 * 1024)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            body = f"<html><body><h1>Node-B Web Server</h1><p>Path: {self.path}</p><p>Timestamp: {time.time()}</p></body></html>".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        resp = b'{"status": "received", "size": ' + str(len(post_data)).encode("utf-8") + b'}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, format, *args):
        # Quiet logging
        pass

def run_http_server(port=8000):
    try:
        server = HTTPServer(("0.0.0.0", port), WebHandler)
        print(f"[Traffic Server] HTTP listening on port {port}")
        server.serve_forever()
    except Exception as e:
        print(f"[Traffic Server] HTTP server error: {e}")

def run_udp_sink(port, name):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", port))
        print(f"[Traffic Server] {name} UDP sink listening on port {port}")
        while True:
            data, addr = sock.recvfrom(65535)
            # Process / sink packet
    except Exception as e:
        print(f"[Traffic Server] {name} error: {e}")

def run_smtp_server(port=2525):
    try:
        # Simple socket-based SMTP responder
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.listen(10)
        print(f"[Traffic Server] SMTP listening on port {port}")
        while True:
            client, addr = sock.accept()
            try:
                client.sendall(b"220 node-b.local ESMTP StrongSwan-VPN\r\n")
                while True:
                    line = client.recv(1024)
                    if not line:
                        break
                    cmd = line.decode("latin1", errors="ignore").upper()
                    if cmd.startswith("HELO") or cmd.startswith("EHLO"):
                        client.sendall(b"250-node-b.local\r\n250 HELP\r\n")
                    elif cmd.startswith("MAIL FROM:"):
                        client.sendall(b"250 2.1.0 Ok\r\n")
                    elif cmd.startswith("RCPT TO:"):
                        client.sendall(b"250 2.1.5 Ok\r\n")
                    elif cmd.startswith("DATA"):
                        client.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                        # Read until \r\n.\r\n
                        msg = b""
                        while b"\r\n.\r\n" not in msg:
                            chunk = client.recv(4096)
                            if not chunk:
                                break
                            msg += chunk
                        client.sendall(b"250 2.0.0 Ok: queued\r\n")
                    elif cmd.startswith("QUIT"):
                        client.sendall(b"221 2.0.0 Bye\r\n")
                        break
                    else:
                        client.sendall(b"250 Ok\r\n")
            except Exception:
                pass
            finally:
                client.close()
    except Exception as e:
        print(f"[Traffic Server] SMTP server error: {e}")

if __name__ == "__main__":
    threads = [
        threading.Thread(target=run_http_server, args=(8000,), daemon=True),
        threading.Thread(target=run_smtp_server, args=(2525,), daemon=True),
        threading.Thread(target=run_udp_sink, args=(5004, "VoIP"), daemon=True),
        threading.Thread(target=run_udp_sink, args=(5006, "Video"), daemon=True),
        threading.Thread(target=run_udp_sink, args=(5222, "Chat"), daemon=True),
    ]
    for t in threads:
        t.start()
    
    print("[Traffic Server] All traffic sinks initialized on node-b.")
    while True:
        time.sleep(3600)
